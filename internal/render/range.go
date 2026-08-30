// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strconv"
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
	if points < 0 {
		points = 0
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
func round(v float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	s := strconv.FormatFloat(v, 'g', ValueSignificantDigits, 64)
	out, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return v
	}
	return out
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
