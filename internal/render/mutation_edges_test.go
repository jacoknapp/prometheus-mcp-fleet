// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"
	"time"
)

// TestTableLayoutIsExact pins the rendered bytes of a table rather than
// probing it for substrings.
//
// Column alignment is the entire product of this function: the caller has
// already been given the cells. Asserting only that a cell appears somewhere
// lets the padding arithmetic drift by any amount, including into a width that
// pads the final column or one that would make strings.Repeat panic on a
// negative count. The ragged row is deliberate -- rows shorter than the header
// are normal for a partially-reporting cluster, and the missing cells must
// render as blanks rather than index past the row.
func TestTableLayoutIsExact(t *testing.T) {
	t.Parallel()

	got := Table(
		[]string{"cluster", "up"},
		[][]string{
			{"prod", "1"},
			{"a"}, // short row: the "up" cell is absent, not empty-by-choice
		},
	)

	want := "cluster  up\n" +
		"-------  --\n" +
		"prod     1\n" +
		"a        \n"

	if got != want {
		t.Errorf("Table() =\n%q\nwant\n%q", got, want)
	}

	// The header is the widest cell in column one, so its own padding is the
	// minimum two spaces. Anything less and the columns touch.
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(line, "cluster") && !strings.HasPrefix(line, "cluster  ") {
			t.Errorf("column separator is under two spaces: %q", line)
		}
	}
}

// TestEstimateTokensOfBytesRoundsUpAtExactMultiples pins the ceiling division.
//
// The token estimate is what every truncation decision in this package is
// measured against. Rounding the wrong way at an exact multiple of
// BytesPerToken either over- or under-reports every payload whose size happens
// to divide cleanly, which is the common case for padded or aligned data.
func TestEstimateTokensOfBytesRoundsUpAtExactMultiples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   int
		want int
	}{
		{0, 0},
		{1, 1},
		{BytesPerToken - 1, 1},
		{BytesPerToken, 1},     // exactly one token, not two
		{BytesPerToken + 1, 2}, // one byte over rounds up
		{2 * BytesPerToken, 2},
		{2*BytesPerToken + 1, 3},
	}
	for _, tc := range tests {
		if got := EstimateTokensOfBytes(tc.in); got != tc.want {
			t.Errorf("EstimateTokensOfBytes(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestFitTokensCeilingIsInclusive pins both edges of the token ceiling.
//
// FitTokens documents the ceiling as a limit the result must fit "under",
// which in every other size check in this codebase means at-or-below. A payload
// measuring exactly the ceiling therefore has to survive untouched; treating
// the ceiling as exclusive drops a series from every result that lands on it.
func TestFitTokensCeilingIsInclusive(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c"}
	build := func(s []string) any { return s }

	full := EstimateTokens(build(items))
	kept, cut := FitTokens(items, full, build)
	if cut || len(kept) != len(items) {
		t.Errorf("FitTokens at exactly the ceiling (%d) dropped to %d items (truncated=%v), want all %d",
			full, len(kept), cut, len(items))
	}

	// One token below the measured size, everything must not fit.
	kept, cut = FitTokens(items, full-1, build)
	if !cut {
		t.Errorf("FitTokens below the ceiling reported no truncation, kept %d", len(kept))
	}
	if len(kept) >= len(items) {
		t.Errorf("FitTokens below the ceiling kept %d of %d items", len(kept), len(items))
	}
	// Whatever it kept must actually fit, which is the inner comparison.
	if len(kept) > 0 && EstimateTokens(build(kept)) > full-1 {
		t.Errorf("FitTokens kept %d items measuring %d, over the ceiling %d",
			len(kept), EstimateTokens(build(kept)), full-1)
	}
}

// TestFitTokensAcceptsTheEmptyResult covers the case the doc comment calls out
// explicitly and nothing exercised: an envelope that alone exceeds the
// ceiling. Refusing to return anything would leave the caller no way to learn
// why, so the zero-item result is accepted rather than looped over.
func TestFitTokensAcceptsTheEmptyResult(t *testing.T) {
	t.Parallel()

	items := []int{1, 2, 3}
	// The envelope is constant and far over any ceiling asked for below, so no
	// item count can ever fit.
	build := func(s []int) any {
		return map[string]any{"padding": strings.Repeat("x", 4096), "items": s}
	}

	kept, cut := FitTokens(items, 8, build)
	if len(kept) != 0 {
		t.Errorf("FitTokens kept %d items, want 0 when the envelope alone exceeds the ceiling", len(kept))
	}
	if !cut {
		t.Error("FitTokens reported no truncation while dropping every item")
	}
}

// TestEncodeRangeSurvivesADegenerateGrid covers the two guards that stand
// between a malformed upstream response and a panic.
//
// A zero step reaches the point-count division, and a sample one step past the
// end reaches the value slice index. Both are guarded, and both guards are
// invisible to a test that only ever supplies a well-formed grid.
func TestEncodeRangeSurvivesADegenerateGrid(t *testing.T) {
	t.Parallel()

	start := baseTime

	t.Run("zero step", func(t *testing.T) {
		t.Parallel()
		got := EncodeRange(RangeInput{
			Matrix: Matrix{{
				Metric: map[string]string{"job": "api"},
				Values: points(start, time.Minute, 1, 2),
			}},
			Start: start, End: start.Add(time.Minute), Step: 0,
		}, Options{})

		if got.Points != 0 {
			t.Errorf("Points = %d, want 0 for a zero step", got.Points)
		}
		// A zero step cannot describe a grid, so the reported step falls back
		// to one second rather than dividing by zero.
		if got.StepSeconds != 1 {
			t.Errorf("StepSeconds = %v, want 1", got.StepSeconds)
		}
	})

	t.Run("sample beyond the last grid slot", func(t *testing.T) {
		t.Parallel()
		end := start.Add(2 * time.Minute) // points = 3: indices 0, 1, 2
		got := EncodeRange(RangeInput{
			Matrix: Matrix{{
				Metric: map[string]string{"job": "api"},
				Values: []Point{
					{T: float64(start.Unix()), V: 1},
					// Exactly one step past End, so it rounds to index 3,
					// which is one past the end of a 3-slot row.
					{T: float64(start.Add(3 * time.Minute).Unix()), V: 99},
				},
			}},
			Start: start, End: end, Step: time.Minute,
		}, Options{})

		if got.Points != 3 {
			t.Fatalf("Points = %d, want 3", got.Points)
		}
		if n := len(got.Series[0].Values); n != 3 {
			t.Fatalf("series has %d slots, want 3", n)
		}
		// The out-of-grid sample is dropped, not wrapped into a slot it does
		// not belong to.
		for i, v := range got.Series[0].Values {
			if i > 0 && v != nil {
				t.Errorf("slot %d = %v, want nil: only the first sample is on the grid", i, *v)
			}
		}
	})
}

// TestEncodeRangeFactorsOnlyGenuinelySharedLabels pins which labels get
// hoisted out of the per-series maps.
//
// Factoring is a token optimisation that changes what the caller reads: a
// label promoted to the shared map is asserted to hold for every series. Doing
// that to a label the series disagree on silently reports the wrong identity
// for the data.
func TestEncodeRangeFactorsOnlyGenuinelySharedLabels(t *testing.T) {
	t.Parallel()

	start := baseTime
	got := EncodeRange(RangeInput{
		Matrix: Matrix{
			{Metric: map[string]string{"job": "api", "instance": "a", "env": "prod"},
				Values: points(start, time.Minute, 1, 2)},
			{Metric: map[string]string{"job": "api", "instance": "b", "env": "prod"},
				Values: points(start, time.Minute, 3, 4)},
		},
		Start: start, End: start.Add(time.Minute), Step: time.Minute,
	}, Options{})

	// job and env agree across both series; instance does not.
	wantShared := map[string]string{"job": "api", "env": "prod"}
	if len(got.SharedLabels) != len(wantShared) {
		t.Fatalf("SharedLabels = %v, want %v", got.SharedLabels, wantShared)
	}
	for k, v := range wantShared {
		if got.SharedLabels[k] != v {
			t.Errorf("SharedLabels[%q] = %q, want %q", k, got.SharedLabels[k], v)
		}
	}
	if _, ok := got.SharedLabels["instance"]; ok {
		t.Error("instance differs between the series and must not be factored out")
	}
	// The differing label stays on each series, and the shared ones do not.
	for i, s := range got.Series {
		if s.Labels["instance"] == "" {
			t.Errorf("series %d lost its instance label", i)
		}
		if _, ok := s.Labels["job"]; ok {
			t.Errorf("series %d still carries the factored-out job label", i)
		}
	}
}

// TestSelectStepReasonAtTheBoundaries pins the Reason field at the exact
// points where two rules produce the same duration for different causes.
//
// Reason is not decoration. It is emitted on every range result specifically
// so an agent can tell whether it is reading raw or averaged data before
// drawing a conclusion. Wherever the computed step happens to equal the step
// already in hand, the duration alone cannot show which rule won -- only the
// reason can -- so an off-by-one in either comparison is invisible to a test
// that checks the duration.
func TestSelectStepReasonAtTheBoundaries(t *testing.T) {
	t.Parallel()

	start := baseTime

	t.Run("a requested step equal to the point budget stays requested", func(t *testing.T) {
		t.Parallel()
		// 30 minutes over the default 120-point budget needs exactly 15s,
		// which is also what the caller asked for and is already on the
		// ladder. Nothing overrode the request, so nothing may claim to have.
		step, d := SelectStep(StepRequest{
			Start: start, End: start.Add(30 * time.Minute), UserStep: 15 * time.Second,
		})
		if step != 15*time.Second {
			t.Errorf("step = %s, want 15s", step)
		}
		if d.Reason != StepReasonRequested {
			t.Errorf("Reason = %q, want %q: the budget matched the request, it did not override it",
				d.Reason, StepReasonRequested)
		}
	})

	t.Run("a scrape interval equal to the step is not a floor that fired", func(t *testing.T) {
		t.Parallel()
		step, d := SelectStep(StepRequest{
			Start: start, End: start.Add(30 * time.Minute),
			UserStep: 15 * time.Second, ScrapeInterval: 15 * time.Second,
		})
		if step != 15*time.Second {
			t.Errorf("step = %s, want 15s", step)
		}
		if d.Reason != StepReasonRequested {
			t.Errorf("Reason = %q, want %q: the step already met the scrape interval",
				d.Reason, StepReasonRequested)
		}
	})

	t.Run("a scrape interval above the step does raise it", func(t *testing.T) {
		t.Parallel()
		step, d := SelectStep(StepRequest{
			Start: start, End: start.Add(30 * time.Minute),
			UserStep: 15 * time.Second, ScrapeInterval: 30 * time.Second,
		})
		if step != 30*time.Second {
			t.Errorf("step = %s, want 30s", step)
		}
		if d.Reason != StepReasonScrapeInterval {
			t.Errorf("Reason = %q, want %q", d.Reason, StepReasonScrapeInterval)
		}
	})

	t.Run("a whole number of days past the top rung is left alone", func(t *testing.T) {
		t.Parallel()
		// Above the top ladder rung the step rounds up to whole days. A step
		// that already is a whole number of days must round to itself; a
		// ceiling that rounds up unconditionally would silently double a
		// two-day step to three.
		step, d := SelectStep(StepRequest{
			Start: start, End: start.Add(time.Hour), UserStep: 48 * time.Hour,
		})
		if step != 48*time.Hour {
			t.Errorf("step = %s, want 48h: 48h is already a whole number of days", step)
		}
		if d.Reason != StepReasonRequested {
			t.Errorf("Reason = %q, want %q: nothing was snapped", d.Reason, StepReasonRequested)
		}
	})

	t.Run("a partial day past the top rung rounds up", func(t *testing.T) {
		t.Parallel()
		step, d := SelectStep(StepRequest{
			Start: start, End: start.Add(time.Hour), UserStep: 25 * time.Hour,
		})
		if step != 48*time.Hour {
			t.Errorf("step = %s, want 48h", step)
		}
		if d.Reason != StepReasonLadder {
			t.Errorf("Reason = %q, want %q", d.Reason, StepReasonLadder)
		}
	})
}

// TestParsePromDurationAcceptsEveryDigit walks all ten digits through the
// scanner. Nothing else in the suite parses a duration containing a 9, so a
// scanner that stopped one short of the digit range would have gone unnoticed
// for every value below it.
func TestParsePromDurationAcceptsEveryDigit(t *testing.T) {
	t.Parallel()

	for d := 0; d <= 9; d++ {
		in := string(rune('0'+d)) + "s"
		got, err := ParsePromDuration(in)
		if err != nil {
			t.Errorf("ParsePromDuration(%q) = %v, want %s", in, err, time.Duration(d)*time.Second)
			continue
		}
		if want := time.Duration(d) * time.Second; got != want {
			t.Errorf("ParsePromDuration(%q) = %s, want %s", in, got, want)
		}
	}

	// A multi-digit value ending in the highest digit, so the scanner has to
	// carry past the first character as well.
	if got, err := ParsePromDuration("159m"); err != nil || got != 159*time.Minute {
		t.Errorf("ParsePromDuration(%q) = %s, %v; want 159m", "159m", got, err)
	}
}

// TestSelectStepNeverReturnsZeroForAZeroWidthAutoRequest pins the fallback
// SelectStep documents as its whole contract: "the returned duration is
// always positive". An auto request (UserStep zero) over a zero-width range
// gives the point-budget branch nothing to compute from -- span is zero, so
// the derived step is zero too -- which makes the final "still zero, fall
// back to the smallest ladder rung" guard the only thing standing between
// this input and a zero step reaching a caller that will divide by it.
func TestSelectStepNeverReturnsZeroForAZeroWidthAutoRequest(t *testing.T) {
	t.Parallel()

	step, d := SelectStep(StepRequest{Start: baseTime, End: baseTime})
	if step <= 0 {
		t.Fatalf("SelectStep = %s for a zero-width auto request, want a positive fallback step", step)
	}
	if step != StepLadder[0] {
		t.Errorf("step = %s, want the smallest ladder rung %s", step, StepLadder[0])
	}
	if d.Reason != StepReasonMaxPoints {
		t.Errorf("Reason = %q, want %q", d.Reason, StepReasonMaxPoints)
	}
}

// TestEncodeRangeFactorsLabelsAcrossEverySeries proves the shared-label
// intersection keeps narrowing against every series before it stops, not
// just the first two. A loop that breaks out as soon as the running
// intersection is non-empty would let a label two series happen to agree on
// leak into SharedLabels even though a third series disagrees -- and
// factorShared then deletes that key from every series' own Labels,
// including the one whose real value it never matched.
func TestEncodeRangeFactorsLabelsAcrossEverySeries(t *testing.T) {
	t.Parallel()

	// Descending values so ranking leaves this order alone: the two
	// job="api" series rank first and second, agree with each other, and
	// only the third (job="web", ranked last) breaks the intersection. A
	// loop that stops as soon as the running intersection is non-empty --
	// true after comparing only the first two -- never reaches the third.
	start := baseTime
	got := EncodeRange(RangeInput{
		Matrix: Matrix{
			{Metric: map[string]string{"job": "api"}, Values: points(start, time.Minute, 3)},
			{Metric: map[string]string{"job": "api"}, Values: points(start, time.Minute, 2)},
			{Metric: map[string]string{"job": "web"}, Values: points(start, time.Minute, 1)},
		},
		Start: start, End: start, Step: time.Minute,
	}, Options{})

	if _, ok := got.SharedLabels["job"]; ok {
		t.Fatalf("SharedLabels = %v; \"job\" is not common to all three series", got.SharedLabels)
	}
	seen := map[string]bool{}
	for _, s := range got.Series {
		seen[s.Labels["job"]] = true
	}
	if !seen["api"] || !seen["web"] {
		t.Fatalf("series job labels = %v, want both \"api\" and \"web\" to survive on their own series",
			seen)
	}
}

// Equivalent-mutant proofs.
//
// The boundary mutants below all failed to survive contact with an
// exhaustive brute-force comparison (a standalone port of the mutated vs.
// original logic run over the full cross product of representative
// span/step/scrape-interval/max-points values, for the step.go group) or a
// direct argument from the surrounding code. Each is left alive with its
// reasoning recorded here rather than with a contrived test, per the "no
// input can make original and mutant differ" bar.
//
//   - step.go:87 ("if span < 0") widening to "<=" only changes behaviour at
//     span == 0, where the guarded statement is "span = 0" — already the
//     value at that boundary. No-op either way.
//
//   - step.go:98 ("if step <= 0") narrowing to "<" only changes behaviour at
//     step == 0. But step == 0 is re-tested, unmutated, at step.go:110
//     ("if step <= 0 { step = StepLadder[0]; reason = StepReasonMaxPoints }")
//     with step unchanged in between whenever the point-budget block did not
//     already run (and if it did run, span > 0 forced needed > 0 = step,
//     which itself sets reason to StepReasonMaxPoints). Every path that
//     reaches step == 0 at line 98 reaches line 110 with reason
//     independently reset to the same value, so line 98's own assignment is
//     never observable.
//
//   - step.go:103 ("if span > 0") widening to ">=" only changes behaviour at
//     span == 0, where needed := ceil(0/maxPoints) == 0. The guarded
//     "if needed > step" can then only fire when step < 0, i.e. a negative
//     UserStep — which line 98 has already flagged as StepReasonMaxPoints,
//     and which line 110 catches identically afterwards regardless of
//     whether this block ran. The two paths converge on the same
//     (StepLadder[0], StepReasonMaxPoints) result.
//
//   - step.go:110 ("if step <= 0") narrowing to "<" only changes behaviour at
//     step == 0. snapUp(0) already returns StepLadder[0] (0 <= every rung),
//     so the step value converges regardless. Reason converges too: step
//     can only be 0 at this point via a path that already set reason to
//     StepReasonMaxPoints (see the step.go:98 entry above), so skipping the
//     reassignment here changes nothing that has not already happened.
//
//   - step.go:126 ("if r.ScrapeInterval > 0 && step < r.ScrapeInterval")
//     widening to ">=" only changes behaviour at ScrapeInterval == 0, where
//     the second half of the AND, "step < 0", can never hold: SelectStep's
//     contract is that step is always positive by this point. The clause
//     added by widening the first comparison can never itself evaluate true.
//
//   - range.go:109 ("if total < len(in.Matrix)") is max(total, len(Matrix));
//     widening to "<=" only changes behaviour when the two are already
//     equal, where the assignment total = len(in.Matrix) is a no-op.
//
//   - range.go:185 ("p.V > r.max") tracks the maximum sample value for
//     ranking. Widening to ">=" only changes behaviour on a tie, where
//     reassigning r.max = p.V stores the same float64 already held. The sort
//     key is unaffected, and no other state remembers which sample produced
//     the maximum.
//
//   - range.go:230 ("stepSec <= 0 || points == 0") narrowing the first half
//     to "<" only matters when stepSec == 0 and points > 0 (buildSeries is
//     never reached with points > 0 and step <= 0 through the exported
//     EncodeRange path, since EncodeRange only computes points > 0 when
//     in.Step > 0 — the same guard). Called directly with step == 0 and
//     points > 0, the division (p.T-startSec)/0 produces +/-Inf or NaN;
//     converting that to int under this Go runtime yields
//     math.MinInt64, which the very next bounds check
//     ("idx < 0 || idx >= points") always rejects. Verified empirically on
//     this toolchain: buildSeries's output is identical (every slot nil)
//     whether the "stepSec <= 0" arm short-circuits the loop body or the
//     division-then-bounds-check path does.
//
//   - sanitize.go:155 ("for cut > 0 && !utf8.RuneStart(s[cut])") widening to
//     ">=" only changes behaviour at cut == 0. ClipBytes only reaches this
//     loop after Sanitize(s), which guarantees valid UTF-8, so s[0] is
//     always a rune-start byte and "!utf8.RuneStart(s[0])" is always false —
//     the added iteration's body condition can never hold, so the loop still
//     exits with cut == 0 either way.
//
//   - tokens.go:29 ("if n <= 0") narrowing to "<" only changes behaviour at
//     n == 0, where falling through computes
//     (0 + BytesPerToken - 1) / BytesPerToken. With BytesPerToken == 4 that
//     is 3/4 == 0 under Go's truncating integer division — the same value
//     the guarded "return 0" would have produced.
