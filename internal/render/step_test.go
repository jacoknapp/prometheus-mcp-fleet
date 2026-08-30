// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestSelectStep covers the whole rule: point budget, ladder snap, and the
// scrape-interval floor applied last.
func TestSelectStep(t *testing.T) {
	t.Parallel()
	start := baseTime
	tests := []struct {
		name       string
		req        StepRequest
		wantStep   time.Duration
		wantReason string
		wantReq    string
	}{
		{
			name:     "six hours at the default budget",
			req:      StepRequest{Start: start, End: start.Add(6 * time.Hour)},
			wantStep: 5 * time.Minute, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
		{
			name:     "one hour at the default budget snaps to the ladder",
			req:      StepRequest{Start: start, End: start.Add(time.Hour)},
			wantStep: 30 * time.Second, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
		{
			name: "a requested ladder step is honoured",
			req: StepRequest{
				Start: start, End: start.Add(time.Hour), UserStep: 5 * time.Minute},
			wantStep: 5 * time.Minute, wantReason: StepReasonRequested, wantReq: "5m",
		},
		{
			name: "a requested off-ladder step snaps up",
			req: StepRequest{
				Start: start, End: start.Add(time.Hour), UserStep: 2 * time.Minute},
			wantStep: 5 * time.Minute, wantReason: StepReasonLadder, wantReq: "2m",
		},
		{
			name: "a requested step too small for the budget is raised",
			req: StepRequest{
				Start: start, End: start.Add(24 * time.Hour), UserStep: time.Second},
			wantStep: 15 * time.Minute, wantReason: StepReasonMaxPoints, wantReq: "1s",
		},
		{
			name: "the scrape interval is a floor",
			req: StepRequest{
				Start: start, End: start.Add(time.Hour),
				ScrapeInterval: time.Minute, MaxPoints: 500,
			},
			wantStep: time.Minute, wantReason: StepReasonScrapeInterval, wantReq: "auto",
		},
		{
			name: "the floor does not lower a larger step",
			req: StepRequest{
				Start: start, End: start.Add(24 * time.Hour), ScrapeInterval: 15 * time.Second},
			wantStep: 15 * time.Minute, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
		{
			name:     "a zero span still yields a positive step",
			req:      StepRequest{Start: start, End: start},
			wantStep: 15 * time.Second, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
		{
			name:     "an inverted range does not produce a negative step",
			req:      StepRequest{Start: start.Add(time.Hour), End: start},
			wantStep: 15 * time.Second, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
		{
			// 365d/120 needs 73h, which snaps up to a whole 4 days: 3 days
			// would be 122 points and blow the budget the snap exists to keep.
			name:     "beyond the top rung, whole days",
			req:      StepRequest{Start: start, End: start.Add(365 * 24 * time.Hour)},
			wantStep: 4 * 24 * time.Hour, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
		{
			// 1h/2 needs 30m, which is not a rung: the ladder has no half
			// hour, so it snaps to 1h.
			name:     "a tiny point budget",
			req:      StepRequest{Start: start, End: start.Add(time.Hour), MaxPoints: 2},
			wantStep: time.Hour, wantReason: StepReasonMaxPoints, wantReq: "auto",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step, down := SelectStep(tc.req)
			if step != tc.wantStep {
				t.Errorf("step = %v, want %v", step, tc.wantStep)
			}
			if step <= 0 {
				t.Fatal("step must always be positive")
			}
			if down.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", down.Reason, tc.wantReason)
			}
			if down.RequestedStep != tc.wantReq {
				t.Errorf("requestedStep = %q, want %q", down.RequestedStep, tc.wantReq)
			}
			if down.AppliedStep != FormatDuration(step) {
				t.Errorf("appliedStep = %q, want %q", down.AppliedStep, FormatDuration(step))
			}
			// The point budget is a promise, not an aspiration.
			if span := tc.req.End.Sub(tc.req.Start); span > 0 {
				budget := tc.req.MaxPoints
				if budget <= 0 {
					budget = DefaultMaxPoints
				}
				if got := int(span/step) + 1; got > budget+1 &&
					tc.wantReason != StepReasonRequested {
					t.Errorf("%d points against a budget of %d", got, budget)
				}
			}
		})
	}
}

// TestStepLadderIsSorted guards the ladder itself: snapUp walks it in order.
func TestStepLadderIsSorted(t *testing.T) {
	t.Parallel()
	if !slices.IsSorted(StepLadder) {
		t.Errorf("StepLadder is not ascending: %v", StepLadder)
	}
}

// TestFormatDuration covers the Prometheus duration rendering an agent copies
// back into its next call.
func TestFormatDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 0, want: "0s"},
		{in: -time.Second, want: "0s"},
		{in: 500 * time.Millisecond, want: "500ms"},
		{in: 15 * time.Second, want: "15s"},
		{in: time.Minute, want: "1m"},
		{in: 90 * time.Second, want: "90s"},
		{in: time.Hour, want: "1h"},
		{in: 24 * time.Hour, want: "1d"},
		{in: 36 * time.Hour, want: "36h"},
		{in: 1500 * time.Microsecond, want: "1.5ms"},
	}
	for _, tc := range tests {
		if got := FormatDuration(tc.in); got != tc.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParsePromDuration covers the inverse, including the units Go's own
// parser refuses.
func TestParsePromDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "15s", want: 15 * time.Second},
		{in: "5m", want: 5 * time.Minute},
		{in: "1h30m", want: 90 * time.Minute},
		{in: "1d", want: 24 * time.Hour},
		{in: "1w", want: 7 * 24 * time.Hour},
		{in: "1y", want: 365 * 24 * time.Hour},
		{in: "500ms", want: 500 * time.Millisecond},
		{in: "1d12h", want: 36 * time.Hour},
		{in: " 5m ", want: 5 * time.Minute},
		{in: "90", want: 90 * time.Second},
		{in: "1.5", want: 1500 * time.Millisecond},
		{in: "", wantErr: true},
		{in: "m", wantErr: true},
		{in: "5x", wantErr: true},
		{in: "5m5", wantErr: true},
		{in: "NaN", wantErr: true},
		{in: "Inf", wantErr: true},
		{in: strings.Repeat("9", 100) + "s", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParsePromDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePromDuration(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePromDuration(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParsePromDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestDurationRoundTrip proves ParsePromDuration is the inverse of
// FormatDuration for every value the ladder can produce.
func TestDurationRoundTrip(t *testing.T) {
	t.Parallel()
	for _, d := range append(slices.Clone(StepLadder),
		36*time.Hour, 3*24*time.Hour, 500*time.Millisecond) {
		s := FormatDuration(d)
		got, err := ParsePromDuration(s)
		if err != nil {
			t.Errorf("ParsePromDuration(FormatDuration(%v)=%q): %v", d, s, err)
			continue
		}
		if got != d {
			t.Errorf("round trip of %v via %q gave %v", d, s, got)
		}
	}
}

// TestParseFormat covers the closed set and its default.
func TestParseFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{in: "", want: FormatCompact},
		{in: "compact", want: FormatCompact},
		{in: "json", want: FormatJSON},
		{in: "table", want: FormatTable},
		{in: "COMPACT", wantErr: true},
		{in: "yaml", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseFormat(tc.in)
		if tc.wantErr {
			if !errors.Is(err, ErrUnknownFormat) {
				t.Errorf("ParseFormat(%q) err = %v, want ErrUnknownFormat", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestOptionsWithDefaults covers the defaulting rules, including the negative
// ceiling that disables the check for tests.
func TestOptionsWithDefaults(t *testing.T) {
	t.Parallel()
	got := Options{}.WithDefaults()
	if got.Format != FormatCompact || got.MaxSeries != DefaultMaxSeries ||
		got.MaxPoints != DefaultMaxPoints || got.MaxItems != DefaultMaxItems ||
		got.TokenCeiling != DefaultTokenCeiling {
		t.Errorf("zero Options defaulted to %+v", got)
	}
	set := Options{
		Format: FormatTable, MaxSeries: 1, MaxPoints: 2, MaxItems: 3, TokenCeiling: -1,
	}.WithDefaults()
	if set.TokenCeiling != -1 {
		t.Error("a negative ceiling was overwritten; tests rely on it disabling the check")
	}
	if set.MaxSeries != 1 || set.MaxPoints != 2 || set.MaxItems != 3 ||
		set.Format != FormatTable {
		t.Errorf("explicit Options were overwritten: %+v", set)
	}
	neg := Options{MaxSeries: -1, MaxPoints: -1, MaxItems: -1}.WithDefaults()
	if neg.MaxSeries != DefaultMaxSeries || neg.MaxPoints != DefaultMaxPoints ||
		neg.MaxItems != DefaultMaxItems {
		t.Errorf("negative caps were not defaulted: %+v", neg)
	}
}
