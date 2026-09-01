// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// ValueSignificantDigits is how many significant digits a compact numeric
// value keeps.
//
// Prometheus routinely reports seventeen digits of float64 noise —
// 0.43210987654321005 — and every digit past the sixth costs a token to carry
// information no agent can act on. Six digits preserves a part-per-million
// distinction, which is finer than any monitoring signal is meaningful to.
// This is the one place the compact encoding loses precision, and it is stated
// in the tool descriptions so a caller who needs the raw bytes knows to ask
// for format "json".
const ValueSignificantDigits = 6

// RangeSeries is one series of a columnar range result. Values is positional:
// index i is the sample at start + i*stepSeconds, and a nil entry is a gap.
type RangeSeries struct {
	// Labels are the labels that distinguish this series from its siblings.
	// Labels shared by every series live in [RangeResult.SharedLabels]
	// instead, and are not repeated here.
	Labels map[string]string `json:"labels,omitempty"`
	// Values holds one entry per step, nil where there is no sample.
	Values []*float64 `json:"values"`
	// Max is the largest finite value in the series. It is reported because
	// it is the key top-N truncation ranks on, so an agent can see why a
	// series survived and another did not.
	Max *float64 `json:"max,omitempty"`
}

// RangeResult is the columnar encoding of a range query.
//
// Timestamps appear exactly once, as Start and StepSeconds, rather than once
// per sample per series. That elision alone is most of the token saving this
// package exists for.
type RangeResult struct {
	// Start is the timestamp of index 0, in Unix seconds.
	Start int64 `json:"start"`
	// StepSeconds is the spacing between adjacent indices.
	StepSeconds float64 `json:"stepSeconds"`
	// Points is the length of every Values array.
	Points int `json:"points"`
	// SharedLabels are the labels every returned series has in common,
	// factored out so they are paid for once.
	SharedLabels map[string]string `json:"sharedLabels,omitempty"`
	// Series are the returned series, ranked by descending maximum value.
	Series []RangeSeries `json:"series"`
	// SeriesTotal is how many series the query matched before truncation.
	SeriesTotal int `json:"seriesTotal"`
	// Truncated is non-nil when series were dropped.
	Truncated *Truncation `json:"truncated,omitempty"`
	// Downsampled always reports the step that was applied and why.
	Downsampled Downsampled `json:"downsampled"`
	// Warnings are the query engine's own non-fatal notes.
	Warnings []string `json:"warnings,omitempty"`
}

// RangeInput is the input to [EncodeRange].
type RangeInput struct {
	// Matrix is the decoded upstream result.
	Matrix Matrix
	// Start and End are the query bounds as sent upstream.
	Start, End time.Time
	// Step is the step as sent upstream.
	Step time.Duration
	// Downsampled is the report from [SelectStep].
	Downsampled Downsampled
	// Warnings are the upstream warnings.
	Warnings []string
	// SeriesTotalHint overrides the matched-series count when the caller
	// knows upstream truncated the matrix itself. Zero means len(Matrix).
	SeriesTotalHint int
}

// EncodeRange builds the columnar representation of a range query.
//
// It ranks series by descending maximum value, keeps at most opts.MaxSeries of
// them, factors out the labels common to the survivors, and then enforces
// opts.TokenCeiling by dropping further series. Both reductions are reported
// in [RangeResult.Truncated]; the token ceiling wins the Reason field because
// it is the constraint the caller cannot lift by raising a limit.
//
// It never returns nil.
func EncodeRange(in RangeInput, opts Options) *RangeResult {
	opts = opts.WithDefaults()

	stepSecs := in.Step.Seconds()
	if stepSecs <= 0 {
		stepSecs = 1
	}
	points := 0
	if span := in.End.Sub(in.Start); span >= 0 && in.Step > 0 {
		points = int(span/in.Step) + 1
	}

	total := in.SeriesTotalHint
	if total < len(in.Matrix) {
		total = len(in.Matrix)
	}

	res := &RangeResult{
		Start:       in.Start.Unix(),
		StepSeconds: stepSecs,
		Points:      points,
		Series:      []RangeSeries{},
		SeriesTotal: total,
		Downsampled: in.Downsampled,
		Warnings:    sanitizeAll(in.Warnings),
	}
	if len(in.Matrix) == 0 {
		return res
	}

	ranked := rankByMax(in.Matrix)
	kept := ranked
	var trunc *Truncation
	if len(ranked) > opts.MaxSeries {
		kept = ranked[:opts.MaxSeries]
		trunc = &Truncation{
			Returned:  opts.MaxSeries,
			Total:     total,
			Reason:    ReasonMaxSeries,
			Selection: SelectionTopNByMax(opts.MaxSeries),
			Hint: fmt.Sprintf(
				"%d series matched. Narrow the query with label matchers, or aggregate "+
					"with sum by(...), rather than raising maxSeries: top-N by maximum "+
					"drops a series that flatlined when it should have spiked.", total),
		}
	}

	build := func(sel []rankedSeries) any {
		return buildSeries(sel, in.Start, in.Step, points)
	}
	fitted, hit := FitTokens(kept, opts.TokenCeiling, build)
	if hit {
		trunc = trunc.Escalate(len(fitted), ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of "+
				"the requested limit. Narrow the query, shorten the range, or aggregate.",
				opts.TokenCeiling))
		trunc.Total = total
		if trunc.Selection == "" {
			trunc.Selection = SelectionTopNByMax(len(fitted))
		}
	}

	series := buildSeries(fitted, in.Start, in.Step, points)
	res.SharedLabels, series = factorShared(series)
	res.Series = series
	res.Truncated = trunc
	return res
}

// rankedSeries pairs a series with the maximum finite value it reached, which
// is the key top-N selection ranks on.
type rankedSeries struct {
	s   SeriesStream
	max float64
	ok  bool
	key string
}

// rankByMax orders series by descending maximum value, with ties and
// all-non-finite series broken by their label set so the ordering is stable
// and repeated calls are diffable.
func rankByMax(m Matrix) []rankedSeries {
	out := make([]rankedSeries, len(m))
	for i, s := range m {
		r := rankedSeries{s: s, key: labelKey(s.Metric)}
		for _, p := range s.Values {
			if math.IsNaN(p.V) || math.IsInf(p.V, 0) {
				continue
			}
			if !r.ok || p.V > r.max {
				r.max, r.ok = p.V, true
			}
		}
		out[i] = r
	}
	slices.SortStableFunc(out, func(a, b rankedSeries) int {
		switch {
		case a.ok && !b.ok:
			return -1
		case !a.ok && b.ok:
			return 1
		case a.ok && b.ok && a.max != b.max:
			return cmp.Compare(b.max, a.max)
		}
		return cmp.Compare(a.key, b.key)
	})
	return out
}

// labelKey renders a label set as a stable sortable string.
func labelKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(',')
	}
	return b.String()
}

// buildSeries projects the ranked series onto the step grid.
func buildSeries(ranked []rankedSeries, start time.Time, step time.Duration, points int) []RangeSeries {
	out := make([]RangeSeries, 0, len(ranked))
	startSec := float64(start.UnixNano()) / 1e9
	stepSec := step.Seconds()
	for _, r := range ranked {
		values := make([]*float64, points)
		for _, p := range r.s.Values {
			if stepSec <= 0 || points == 0 {
				continue
			}
			idx := int(math.Round((p.T - startSec) / stepSec))
			if idx < 0 || idx >= points {
				continue
			}
			values[idx] = jsonNumber(round(p.V))
		}
		rs := RangeSeries{Labels: Labels(r.s.Metric), Values: values}
		if r.ok {
			m := round(r.max)
			rs.Max = jsonNumber(m)
		}
		out = append(out, rs)
	}
	return out
}

// factorShared removes the labels every series has in common and returns them
// separately. With a single series everything is common, which is exactly the
// case where factoring pays best.
//
// gosec reports G602 four times in this function and is wrong four times.
// series[1:] is guarded by the len(series) == 0 return immediately above it,
// and every other index is the loop variable of `for i := range series`, which
// cannot leave the slice. Its taint analysis loses the length through
// buildSeries' append loop; there is no unbounded index here.
//
//nolint:gosec // G602: bounded by the len check above and by `range series`.
func factorShared(series []RangeSeries) (map[string]string, []RangeSeries) {
	if len(series) == 0 {
		return nil, series
	}
	shared := make(map[string]string, len(series[0].Labels))
	for k, v := range series[0].Labels {
		shared[k] = v
	}
	for _, s := range series[1:] {
		for k, v := range shared {
			if s.Labels[k] != v {
				delete(shared, k)
			}
		}
		if len(shared) == 0 {
			break
		}
	}
	if len(shared) == 0 {
		return nil, series
	}
	for i := range series {
		for k := range shared {
			delete(series[i].Labels, k)
		}
		if len(series[i].Labels) == 0 {
			series[i].Labels = nil
		}
	}
	return shared, series
}

// round reduces v to [ValueSignificantDigits] significant digits.
//
// This used to format v to a decimal string and parse it back
// (strconv.FormatFloat then strconv.ParseFloat), which is correct but costs
// two allocations per call. round runs up to MaxSeries*MaxPoints times per
// range result, plus once more per point every time FitTokens re-renders a
// shrinking candidate, so those allocations were the hottest ones in the
// package. roundSignificant below gets the same answer with float64
// arithmetic only.
//
// It is bit-for-bit identical to the string round trip for every value with
// 1e-17 <= |v| < 1e28 (round_test.go's TestRoundMatchesStringOracle proves
// this against millions of generated samples) — a span that covers every
// value Prometheus could plausibly emit by many orders of magnitude in both
// directions. Outside that span (denormals, and magnitudes past roughly
// 1e28) math.Pow10 itself stops being exact, and the two implementations can
// differ by a handful of ULPs; see the doc comment on roundSignificant and
// the test for why that is understood and accepted rather than papered over.
func round(v float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	return roundSignificant(v)
}

// sigLoBound and sigHiBound are 10^(ValueSignificantDigits-1) and
// 10^ValueSignificantDigits: roundSignificant normalizes the magnitude it is
// rounding into [sigLoBound, sigHiBound) before rounding to the nearest
// integer, the same way %g's digit-count logic does.
var (
	sigLoBound = math.Pow10(ValueSignificantDigits - 1)
	sigHiBound = math.Pow10(ValueSignificantDigits)
)

// pow10ChunkExp is the largest power of ten roundSignificant will ask
// math.Pow10 for directly. Splitting a bigger shift into chunks this size
// keeps math.Pow10 from ever being asked for an out-of-range power, which
// would silently hand back +Inf or 0 and poison the result with a NaN
// instead of a rounded number — the one outcome that would be worse than an
// imprecise-but-present value at these already-extreme magnitudes.
const pow10ChunkExp = 300

// minNormalFloat64 is the smallest positive normal float64 (2^-1022).
// Subnormal values below it have already lost most of their mantissa bits,
// which throws off the exponent math.Log10 estimates for them badly enough
// to send roundSignificant's scaling wildly out of range. Multiplying a
// subnormal by an exact power of two first — subnormalRescale — repositions
// its existing bits into the normal range at no precision cost, and dividing
// the same power back out at the end undoes it.
const (
	minNormalFloat64 = 0x1p-1022
	subnormalRescale = 0x1p60
)

// roundSignificant reduces v (which is neither zero, NaN, nor infinite) to
// [ValueSignificantDigits] significant digits.
//
// The approach is the textbook one — scale the magnitude into
// [sigLoBound, sigHiBound), round to the nearest integer, scale back — but
// with two corrections a naive version of it gets wrong:
//
//  1. Scaling by multiplying by 10^k when k is negative multiplies by the
//     inexact binary approximation of, say, 1e-9 instead of dividing by the
//     exact 1e9; scaleUp/scaleDown always multiply or divide by a positive
//     power of ten, whichever the sign of the shift calls for, so the
//     lossless direction is always the one used.
//  2. A single multiply or divide still rounds once when it produces hi, and
//     then math.Round rounds again — two roundings can disagree with the one
//     correctly-rounded answer strconv would give. exactProduct/
//     exactQuotient recover the rounding error FMA would otherwise discard
//     as lo, and folding it back in before the final decision corrects the
//     rare case where double rounding picked the wrong side of a tie.
//
// Because av is always non-negative and math.Round breaks exact ties away
// from zero, the recovered error (delta below) can only ever need to pull
// the tentative answer down, never push it up further than math.Round
// already did — the case that needs correcting is "this looked like an
// exact .5 tie, or looked like it safely rounded down, but the bits we
// discarded show the true value was actually lower still or is an exact
// tie that resolves to the even neighbour"; there is no symmetric case on
// the other side. See TestRound's "exact tie" and "double rounding" cases
// for the two shapes this takes.
func roundSignificant(v float64) float64 {
	sign := 1.0
	av := v
	if av < 0 {
		sign, av = -1, -av
	}

	boosted := av < minNormalFloat64
	if boosted {
		av *= subnormalRescale
	}

	exp := int(math.Floor(math.Log10(av)))
	k := ValueSignificantDigits - 1 - exp

	scale := func(k int) (hi, lo float64) {
		if k >= 0 {
			return scaleUp(av, k)
		}
		return scaleDown(av, -k)
	}

	hi, lo := scale(k)
	// math.Log10 is a floating-point estimate of the decimal exponent and is
	// occasionally off by one right at a power-of-ten boundary; correct it
	// so the scaled magnitude always lands in [sigLoBound, sigHiBound).
	switch {
	case hi >= sigHiBound:
		exp++
		k = ValueSignificantDigits - 1 - exp
		hi, lo = scale(k)
	case hi < sigLoBound:
		exp--
		k = ValueSignificantDigits - 1 - exp
		hi, lo = scale(k)
	}

	r := math.Round(hi)
	switch delta := (hi - r) + lo; {
	case delta < -0.5:
		// The discarded bits show the true value is further from r than hi
		// alone let on, past the point where r is still the nearest integer.
		r--
	case delta == -0.5 && math.Mod(r, 2) != 0:
		// hi was an exact tie, which math.Round always resolves upward; if
		// that leaves r odd, the correctly-rounded (round-half-to-even)
		// answer is the even neighbour below it instead.
		r--
	}

	var result float64
	if k >= 0 {
		result = unscaleDown(r, k)
	} else {
		result = unscaleUp(r, -k)
	}
	if boosted {
		result /= subnormalRescale
	}
	return sign * result
}

// exactProduct returns hi and lo such that hi+lo == a*b exactly, as real
// numbers: hi is the correctly-rounded a*b a plain multiply would give, and
// lo is the rounding error that multiply discarded, recovered losslessly via
// one fused multiply-add.
func exactProduct(a, b float64) (hi, lo float64) {
	hi = a * b
	lo = math.FMA(a, b, -hi)
	return hi, lo
}

// exactQuotient is exactProduct's counterpart for division: hi is a/b and lo
// is the correction recovering the precision hi's own rounding lost,
// computed from the exact remainder a-hi*b via FMA.
func exactQuotient(a, b float64) (hi, lo float64) {
	hi = a / b
	lo = math.FMA(-hi, b, a) / b
	return hi, lo
}

// scaleUp and scaleDown return av*10^k and av/10^k respectively (k >= 0), as
// an exact hi/lo pair. Both chunk the exponent by pow10ChunkExp first so
// that no single math.Pow10 call is ever asked for a power large enough to
// overflow to +Inf — which, fed into exactProduct/exactQuotient, would
// otherwise turn a merely-imprecise extreme value into a NaN.
func scaleUp(av float64, k int) (hi, lo float64) {
	for k > pow10ChunkExp {
		av, _ = exactProduct(av, 1e300)
		k -= pow10ChunkExp
	}
	return exactProduct(av, math.Pow10(k))
}

func scaleDown(av float64, k int) (hi, lo float64) {
	for k > pow10ChunkExp {
		av, _ = exactQuotient(av, 1e300)
		k -= pow10ChunkExp
	}
	return exactQuotient(av, math.Pow10(k))
}

// unscaleDown and unscaleUp invert scaleUp/scaleDown's magnitude shift once
// r has been rounded, chunked the same way and for the same reason.
func unscaleDown(r float64, k int) float64 {
	for k > pow10ChunkExp {
		r /= 1e300
		k -= pow10ChunkExp
	}
	return r / math.Pow10(k)
}

func unscaleUp(r float64, k int) float64 {
	for k > pow10ChunkExp {
		r *= 1e300
		k -= pow10ChunkExp
	}
	return r * math.Pow10(k)
}

// sanitizeAll cleans a slice of untrusted strings, dropping empties.
func sanitizeAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if c := ClipRunes(s, MaxAnnotationRunes); c != "" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
