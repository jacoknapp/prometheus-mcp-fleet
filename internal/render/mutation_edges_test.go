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
