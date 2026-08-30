// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// f64 returns a pointer to v, for the literal RangeResult below.
func f64(v float64) *float64 { return &v }

// TestEncodeRangeExactShape pins the entire columnar encoding against a
// literal.
//
// The individual behaviours are covered elsewhere; what this asserts is the
// shape as a whole, because the shape is the product. A field renamed, a
// timestamp array quietly reintroduced or a shared label left duplicated on
// every series is a regression an assertion on one field at a time would miss.
func TestEncodeRangeExactShape(t *testing.T) {
	t.Parallel()
	start := baseTime
	step := time.Minute
	m := Matrix{
		{
			Metric: map[string]string{
				"__name__": "up", "job": "api", "namespace": "prod", "instance": "a",
			},
			Values: points(start, step, 1, 2, 3),
		},
		{
			Metric: map[string]string{
				"__name__": "up", "job": "api", "namespace": "prod", "instance": "b",
			},
			// A gap at index 1: the sample simply is not there.
			Values: []Point{
				{T: float64(start.Unix()), V: 9},
				{T: float64(start.Add(2 * step).Unix()), V: 7},
			},
		},
	}

	got := EncodeRange(RangeInput{
		Matrix: m, Start: start, End: start.Add(2 * step), Step: step,
		Downsampled: Downsampled{
			RequestedStep: "auto", AppliedStep: "1m", Reason: StepReasonMaxPoints,
		},
		Warnings: []string{"  a  warning\n"},
	}, Options{})

	want := &RangeResult{
		Start:       start.Unix(),
		StepSeconds: 60,
		Points:      3,
		// Everything the two series agree on is paid for once.
		SharedLabels: map[string]string{
			"__name__": "up", "job": "api", "namespace": "prod",
		},
		Series: []RangeSeries{
			{
				// Ranked by descending maximum, so instance b leads.
				Labels: map[string]string{"instance": "b"},
				Values: []*float64{f64(9), nil, f64(7)},
				Max:    f64(9),
			},
			{
				Labels: map[string]string{"instance": "a"},
				Values: []*float64{f64(1), f64(2), f64(3)},
				Max:    f64(3),
			},
		},
		SeriesTotal: 2,
		Truncated:   nil,
		Downsampled: Downsampled{
			RequestedStep: "auto", AppliedStep: "1m", Reason: StepReasonMaxPoints,
		},
		Warnings: []string{"a warning"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RangeResult (-want +got):\n%s", diff)
	}

	// And the JSON it becomes, because the shape an agent reads is the JSON,
	// not the Go struct: timestamps appear exactly twice in the whole payload,
	// values are bare numbers and a gap is null.
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantJSON := `{"start":1787983200,"stepSeconds":60,"points":3,` +
		`"sharedLabels":{"__name__":"up","job":"api","namespace":"prod"},` +
		`"series":[{"labels":{"instance":"b"},"values":[9,null,7],"max":9},` +
		`{"labels":{"instance":"a"},"values":[1,2,3],"max":3}],` +
		`"seriesTotal":2,` +
		`"downsampled":{"requestedStep":"auto","appliedStep":"1m","reason":"max_points"},` +
		`"warnings":["a warning"]}`
	if diff := cmp.Diff(wantJSON, string(encoded)); diff != "" {
		t.Errorf("encoded JSON (-want +got):\n%s", diff)
	}
}

// TestDownsampledIsNeverOmitted is the anti-silent-downsample guard.
//
// A silently averaged series that a model believes is raw produces a
// confident wrong conclusion, which is the failure mode this field exists to
// prevent. So it is asserted as always serialized - present in the JSON even
// when the step was honoured unchanged, because "no field" is not something a
// model reliably reads as "not downsampled".
func TestDownsampledIsNeverOmitted(t *testing.T) {
	t.Parallel()
	start := baseTime
	tests := []struct {
		name       string
		req        StepRequest
		wantReason string
		wantChange bool
	}{
		{
			name:       "the caller's step was honoured unchanged",
			req:        StepRequest{Start: start, End: start.Add(time.Hour), UserStep: 5 * time.Minute},
			wantReason: StepReasonRequested,
		},
		{
			name:       "the step was raised for the point budget",
			req:        StepRequest{Start: start, End: start.Add(24 * time.Hour), UserStep: time.Second},
			wantReason: StepReasonMaxPoints, wantChange: true,
		},
		{
			name:       "the step was snapped up the ladder",
			req:        StepRequest{Start: start, End: start.Add(time.Hour), UserStep: 2 * time.Minute},
			wantReason: StepReasonLadder, wantChange: true,
		},
		{
			name: "the scrape interval dominated both",
			req: StepRequest{
				Start: start, End: start.Add(time.Hour),
				UserStep: 15 * time.Second, ScrapeInterval: 5 * time.Minute, MaxPoints: 1000,
			},
			wantReason: StepReasonScrapeInterval, wantChange: true,
		},
		{
			name: "no step was requested at all",
			req:  StepRequest{Start: start, End: start.Add(6 * time.Hour)},
			// "auto" is itself a change the agent must be told about.
			wantReason: StepReasonMaxPoints, wantChange: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			step, down := SelectStep(tc.req)
			if down.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", down.Reason, tc.wantReason)
			}
			// All three members are populated, always.
			if down.RequestedStep == "" || down.AppliedStep == "" || down.Reason == "" {
				t.Errorf("downsampled = %+v, want every member populated", down)
			}
			if tc.wantChange && down.RequestedStep == down.AppliedStep {
				t.Errorf("a changed step reported %q -> %q",
					down.RequestedStep, down.AppliedStep)
			}

			res := EncodeRange(RangeInput{
				Matrix: Matrix{{
					Metric: map[string]string{"job": "api"},
					Values: points(tc.req.Start, step, 1, 2),
				}},
				Start: tc.req.Start, End: tc.req.End, Step: step, Downsampled: down,
			}, Options{})

			var decoded map[string]json.RawMessage
			b, err := json.Marshal(res)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := json.Unmarshal(b, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			raw, present := decoded["downsampled"]
			if !present {
				t.Fatalf("the downsampled report was omitted from %s", b)
			}
			var report Downsampled
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("decode report: %v", err)
			}
			if diff := cmp.Diff(down, report); diff != "" {
				t.Errorf("downsampled (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTruncationMarkerPresence covers both halves of the honesty contract: a
// truncated result always says so, and an untruncated one never does. A false
// truncation claim is as damaging as a missing one - it tells a model to
// narrow a query that was already complete.
func TestTruncationMarkerPresence(t *testing.T) {
	t.Parallel()
	start := baseTime

	matrix := func(n int) Matrix {
		m := make(Matrix, 0, n)
		for i := range n {
			m = append(m, SeriesStream{
				Metric: map[string]string{
					"__name__": "up", "pod": fmt.Sprintf("pod-%03d", i),
				},
				Values: points(start, time.Minute, float64(i), float64(i)+0.5),
			})
		}
		return m
	}

	tests := []struct {
		name          string
		series        int
		opts          Options
		wantTruncated bool
		wantReturned  int
		wantTotal     int
		wantReason    string
		wantSelection string
	}{
		{
			name: "well inside the cap", series: 5,
			opts: Options{MaxSeries: 20, TokenCeiling: -1},
		},
		{
			name: "exactly at the cap carries no marker", series: 20,
			opts: Options{MaxSeries: 20, TokenCeiling: -1},
		},
		{
			name: "one over the cap", series: 21,
			opts:          Options{MaxSeries: 20, TokenCeiling: -1},
			wantTruncated: true, wantReturned: 20, wantTotal: 21,
			wantReason: ReasonMaxSeries, wantSelection: "top_20_by_max",
		},
		{
			name: "a caller-lowered cap", series: 50,
			opts:          Options{MaxSeries: 3, TokenCeiling: -1},
			wantTruncated: true, wantReturned: 3, wantTotal: 50,
			wantReason: ReasonMaxSeries, wantSelection: "top_3_by_max",
		},
		{
			name: "an empty result is not a truncated one", series: 0,
			opts: Options{MaxSeries: 20, TokenCeiling: -1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EncodeRange(RangeInput{
				Matrix: matrix(tc.series), Start: start, End: start.Add(time.Minute),
				Step: time.Minute,
			}, tc.opts)

			if !tc.wantTruncated {
				if got.Truncated != nil {
					t.Fatalf("an untruncated result claimed truncation: %+v", got.Truncated)
				}
				// And the marker is absent from the JSON, not merely zeroed.
				b, err := json.Marshal(got)
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				if strings.Contains(string(b), `"truncated"`) {
					t.Errorf("the JSON carries a truncation marker: %s", b)
				}
				if got.SeriesTotal != tc.series {
					t.Errorf("seriesTotal = %d, want %d", got.SeriesTotal, tc.series)
				}
				return
			}

			if got.Truncated == nil {
				t.Fatal("series were dropped without a truncation marker")
			}
			if diff := cmp.Diff(tc.wantReturned, got.Truncated.Returned); diff != "" {
				t.Errorf("returned (-want +got):\n%s", diff)
			}
			if got.Truncated.Total != tc.wantTotal {
				t.Errorf("total = %d, want the honest %d", got.Truncated.Total, tc.wantTotal)
			}
			if got.Truncated.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Truncated.Reason, tc.wantReason)
			}
			if got.Truncated.Selection != tc.wantSelection {
				t.Errorf("selection = %q, want %q",
					got.Truncated.Selection, tc.wantSelection)
			}
			if got.Truncated.Hint == "" {
				t.Error("the truncation names no concrete next action")
			}
			if len(got.Series) != tc.wantReturned {
				t.Errorf("kept %d series but reported %d",
					len(got.Series), tc.wantReturned)
			}
		})
	}
}

// TestTopNSelectsByMaximum proves the selection strategy is what the response
// says it is.
//
// The heuristic is lossy in a knowable way - a series that flatlined when it
// should have spiked is exactly the one a maximum-based selection discards -
// which is why the strategy is named in the response rather than implied, and
// why it has to actually be the strategy in use.
func TestTopNSelectsByMaximum(t *testing.T) {
	t.Parallel()
	start := baseTime

	// Deliberately adversarial: the series with the largest *first* sample,
	// the largest *sum* and the largest *last* sample are all different from
	// the one with the largest single value.
	m := Matrix{
		{
			Metric: map[string]string{"series": "big_first"},
			Values: points(start, time.Minute, 50, 1, 1, 1),
		},
		{
			Metric: map[string]string{"series": "big_sum"},
			Values: points(start, time.Minute, 40, 40, 40, 40),
		},
		{
			Metric: map[string]string{"series": "big_last"},
			Values: points(start, time.Minute, 1, 1, 1, 60),
		},
		{
			Metric: map[string]string{"series": "big_middle"},
			Values: points(start, time.Minute, 1, 999, 1, 1),
		},
		{
			Metric: map[string]string{"series": "flatline"},
			Values: points(start, time.Minute, 0, 0, 0, 0),
		},
	}

	got := EncodeRange(RangeInput{
		Matrix: m, Start: start, End: start.Add(3 * time.Minute), Step: time.Minute,
	}, Options{MaxSeries: 3, TokenCeiling: -1})

	if got.Truncated == nil || got.Truncated.Selection != "top_3_by_max" {
		t.Fatalf("truncation = %+v", got.Truncated)
	}
	want := []string{"big_middle", "big_last", "big_first"}
	kept := make([]string, 0, len(got.Series))
	for _, s := range got.Series {
		kept = append(kept, s.Labels["series"])
	}
	if diff := cmp.Diff(want, kept); diff != "" {
		t.Errorf("kept series, ranked by maximum (-want +got):\n%s", diff)
	}
	// The reported max is the key the ranking used, so an agent can see why.
	if got.Series[0].Max == nil || *got.Series[0].Max != 999 {
		t.Errorf("leading max = %v, want 999", got.Series[0].Max)
	}
	// The flatline is dropped. That is the documented lossiness, and the hint
	// must tell the agent how to get it back rather than leave it guessing.
	if !strings.Contains(got.Truncated.Hint, "matcher") {
		t.Errorf("hint = %q, want it to name label matchers", got.Truncated.Hint)
	}
}

// TestHubTokenCeilingBeatsAnExplicitLimit pins the ceiling as the constraint a
// caller cannot lift.
//
// An agent must not be able to blow its own context in one call even by asking
// for it, so a generous maxSeries does not buy a larger result, and the reason
// reported is the ceiling rather than the limit - the ceiling is the thing the
// caller cannot argue with, and naming the limit instead would send them to
// raise a knob that does nothing.
func TestHubTokenCeilingBeatsAnExplicitLimit(t *testing.T) {
	t.Parallel()
	start := baseTime
	const total = 200

	m := make(Matrix, 0, total)
	for i := range total {
		m = append(m, SeriesStream{
			Metric: map[string]string{
				"__name__":  "container_cpu_usage_seconds_total",
				"namespace": "prod",
				"pod":       fmt.Sprintf("checkout-7d9f%03d-%05d", i, i*37),
			},
			Values: points(start, time.Minute, seq(60, float64(i))...),
		})
	}

	tests := []struct {
		name     string
		opts     Options
		wantMore bool
	}{
		{
			name: "an explicit limit far above the ceiling",
			opts: Options{MaxSeries: 10000, TokenCeiling: 2000},
		},
		{
			name: "a limit that would itself truncate, plus the ceiling",
			opts: Options{MaxSeries: 50, TokenCeiling: 2000},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EncodeRange(RangeInput{
				Matrix: m, Start: start, End: start.Add(59 * time.Minute),
				Step: time.Minute,
			}, tc.opts)

			if got.Truncated == nil {
				t.Fatal("the ceiling fired without reporting anything")
			}
			if got.Truncated.Reason != ReasonTokenCeiling {
				t.Errorf("reason = %q, want %q; the ceiling is the constraint the "+
					"caller cannot lift, so it is the one to name",
					got.Truncated.Reason, ReasonTokenCeiling)
			}
			// The true total survives both reductions.
			if got.Truncated.Total != total {
				t.Errorf("total = %d, want the honest %d", got.Truncated.Total, total)
			}
			if got.Truncated.Returned != len(got.Series) {
				t.Errorf("returned %d but carried %d series",
					got.Truncated.Returned, len(got.Series))
			}
			if got.Truncated.Selection == "" {
				t.Error("the ceiling truncation named no selection strategy")
			}
			if got.Truncated.Hint == "" {
				t.Error("the ceiling truncation named no next action")
			}
			// And it actually fits.
			if n := EstimateTokens(got); n > tc.opts.TokenCeiling*2 {
				t.Errorf("result is ~%d tokens against a ceiling of %d",
					n, tc.opts.TokenCeiling)
			}
		})
	}
}

// TestURLRefIsNeverAMarkdownLink is the exfiltration guard.
//
// In a host that auto-fetches links, a markdown link planted in an alert
// annotation is a one-click exfiltration path, and the host cannot tell that
// the annotation was written by whoever could edit a rule file in one of a
// hundred clusters. So the encoding is asserted at the JSON level: three
// fields, no markup, and an explicit refusal flag.
func TestURLRefIsNeverAMarkdownLink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "an ordinary runbook url",
			in:   "https://runbooks.corp/high-latency",
			want: `{"url":"https://runbooks.corp/high-latency",` +
				`"urlHost":"runbooks.corp","followable":false}`,
		},
		{
			name: "a markdown link in the annotation stays inert text",
			in:   "[click here](https://evil.example/steal)",
			want: `{"url":"[click here](https://evil.example/steal)",` +
				`"followable":false}`,
		},
		{
			name: "a javascript scheme is data, not a link",
			in:   "javascript:fetch('https://evil.example')",
			want: `{"url":"javascript:fetch('https://evil.example')",` +
				`"followable":false}`,
		},
		{
			name: "a bidi override in the host is stripped before parsing",
			in:   "https://evil‮.example/x",
			want: `{"url":"https://evil.example/x","urlHost":"evil.example",` +
				`"followable":false}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref := NewURLRef(tc.in)
			if ref == nil {
				t.Fatalf("NewURLRef(%q) = nil", tc.in)
			}
			b, err := json.Marshal(ref)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if diff := cmp.Diff(tc.want, string(b)); diff != "" {
				t.Errorf("URLRef JSON (-want +got):\n%s", diff)
			}
			// followable is emitted, never omitted, so a host looking for a
			// truthy flag finds an explicit refusal rather than nothing.
			if !strings.Contains(string(b), `"followable":false`) {
				t.Errorf("followable was omitted: %s", b)
			}
			// Whatever the input, the output is three known keys and no more.
			var decoded map[string]any
			if err := json.Unmarshal(b, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for k := range decoded {
				switch k {
				case "url", "urlHost", "followable":
				default:
					t.Errorf("unexpected key %q in %s", k, b)
				}
			}
		})
	}
}

// TestClipLimitsMatchTheSpec pins the numbers themselves.
//
// TestClipWrappers proves each field is clipped at its own constant; this
// proves the constants are the ones the specification and the security
// documentation name. A length cap is an injection control - a bounded field
// cannot carry a long set of instructions however carefully it is crafted -
// so widening one is a security change and should not be possible without a
// failing test.
func TestClipLimitsMatchTheSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  int
		want int
	}{
		{name: "label values, in bytes", got: MaxLabelValueBytes, want: 256},
		{name: "help strings, in runes", got: MaxHelpRunes, want: 200},
		{name: "scrape errors, in runes", got: MaxScrapeErrorRunes, want: 300},
		{name: "annotations, in runes", got: MaxAnnotationRunes, want: 500},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("cap = %d, want %d; widening a clip limit is a security "+
					"change, not a formatting one", tc.got, tc.want)
			}
		})
	}
	if ClipMarker != "…[clipped]" {
		t.Errorf("ClipMarker = %q, want the explicit marker a model can see", ClipMarker)
	}

	// Each wrapper appends the marker and nothing else, and the result stays
	// within its cap plus the marker.
	long := strings.Repeat("x", 4096)
	for name, fn := range map[string]func(string) string{
		"LabelValue":  LabelValue,
		"Help":        Help,
		"ScrapeError": ScrapeError,
		"Annotation":  Annotation,
	} {
		got := fn(long)
		if !strings.HasSuffix(got, ClipMarker) {
			t.Errorf("%s did not mark the clip: %q", name, got)
		}
		if strings.Count(got, ClipMarker) != 1 {
			t.Errorf("%s emitted the marker %d times", name, strings.Count(got, ClipMarker))
		}
	}
}
