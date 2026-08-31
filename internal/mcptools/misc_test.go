// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// TestNewValidatesOptions covers the required dependencies and the defaults.
func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Clusters: &fakeClusters{}}); err == nil {
		t.Error("New accepted a nil Prometheus")
	}
	if _, err := New(Options{Prometheus: &fakeProm{}}); err == nil {
		t.Error("New accepted a nil Clusters")
	}
	tools, err := New(Options{Prometheus: &fakeProm{}, Clusters: &fakeClusters{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if tools.tokenCeiling != render.DefaultTokenCeiling {
		t.Errorf("tokenCeiling = %d", tools.tokenCeiling)
	}
	if tools.maxLookback != DefaultMaxLookback {
		t.Errorf("maxLookback = %v", tools.maxLookback)
	}
	if tools.fanoutConcurrency != DefaultFanoutConcurrency {
		t.Errorf("fanoutConcurrency = %d", tools.fanoutConcurrency)
	}
	if tools.log == nil || tools.metrics == nil || tools.now == nil {
		t.Error("New left a dependency nil")
	}

	// Concurrency above the ceiling is clamped rather than refused: a
	// configuration typo must not take the hub down.
	clamped, err := New(Options{
		Prometheus: &fakeProm{}, Clusters: &fakeClusters{},
		FanoutConcurrency: 10_000,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if clamped.fanoutConcurrency != MaxFanoutConcurrency {
		t.Errorf("fanoutConcurrency = %d, want %d",
			clamped.fanoutConcurrency, MaxFanoutConcurrency)
	}

	// Exactly at the ceiling must pass through unchanged: only strictly above
	// it gets clamped.
	atCeiling, err := New(Options{
		Prometheus: &fakeProm{}, Clusters: &fakeClusters{},
		FanoutConcurrency: MaxFanoutConcurrency,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if atCeiling.fanoutConcurrency != MaxFanoutConcurrency {
		t.Errorf("fanoutConcurrency = %d, want the ceiling %d left untouched",
			atCeiling.fanoutConcurrency, MaxFanoutConcurrency)
	}
}

// TestNopMetricsIsSafeToDriveThroughRun proves the default [NopMetrics] a
// caller gets by leaving Options.Metrics unset is actually wired into the
// call path and safe to invoke: run() calls ToolCall and ToolDuration
// unconditionally on every request, so a Tools built without an explicit
// metrics sink must not panic when a real call reaches it.
func TestNopMetricsIsSafeToDriveThroughRun(t *testing.T) {
	t.Parallel()
	clusters := &fakeClusters{entries: testClusters()}
	tools, err := New(Options{
		Prometheus: newFakeProm(t), Clusters: clusters,
		Clock: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := tools.metrics.(NopMetrics); !ok {
		t.Fatalf("metrics = %T, want the NopMetrics default", tools.metrics)
	}

	fn := run(tools, ToolListClusters,
		func() *ListClustersOut { return &ListClustersOut{} }, tools.listClusters)
	out, res, err := fn(ctx(t), request(ToolListClusters, principal(fullScope())), ListClustersIn{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res != mcpsurface.OKResult {
		t.Errorf("result = %v, want ok", res)
	}
	if out == nil {
		t.Fatal("run returned a nil result on success")
	}
}

// TestRegisterRejectsNil covers the composition root's entry point.
func TestRegisterRejectsNil(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := Register(nil, h.tools); err == nil {
		t.Error("Register accepted a nil server")
	}
	s, _ := newRegisteredServer(t)
	if err := Register(s, nil); err == nil {
		t.Error("Register accepted nil tools")
	}
}

// TestToolErrorHelpers covers the error builders.
func TestToolErrorHelpers(t *testing.T) {
	t.Parallel()
	var nilErr *ToolError
	if got := nilErr.Error(); got != "<nil>" {
		t.Errorf("nil ToolError.Error() = %q", got)
	}
	e := newError(CodeUpstreamError, "boom", true).
		WithInput(map[string]any{"cluster": "c"}).
		WithHint("try %d", 1)
	if e.Error() != "UPSTREAM_ERROR: boom" {
		t.Errorf("Error() = %q", e.Error())
	}
	if e.Hint != "try 1" || e.Input["cluster"] != "c" {
		t.Errorf("e = %+v", e)
	}
	if e.Retryable == nil || !*e.Retryable {
		t.Error("retryable was not set")
	}

	// A ToolError travels through ordinary Go error plumbing inside the package.
	var target *ToolError
	if !errors.As(error(e), &target) || target.Code != CodeUpstreamError {
		t.Error("errors.As did not recover the ToolError")
	}

	env := Envelope{Error: e}
	if env.Error != e || env.Untrusted != "" {
		t.Errorf("failed envelope = %+v", env)
	}
	// Attaching an error clears the untrusted notice: an error body is text
	// this project authored.
	u := untrusted()
	u.setError(e)
	if u.Untrusted != "" {
		t.Error("the untrusted notice survived onto an error result")
	}
}

func TestRegisteredErrorConstructorsReturnWritableEnvelopes(t *testing.T) {
	t.Parallel()

	if out := newListClustersOut(); out == nil {
		t.Fatal("newListClustersOut returned nil")
	}
	if out := newExplainPromQLOut(); out == nil {
		t.Fatal("newExplainPromQLOut returned nil")
	}
}

// TestPromqlCaret covers both position forms Prometheus emits and the
// no-position case.
func TestPromqlCaret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		query   string
		message string
		wantLen int
	}{
		{
			name: "at char form", query: "0123456789", message: "parse error at char 5: x",
			wantLen: 5,
		},
		{
			name: "line column form", query: "0123456789", message: `1:7: parse error: x`,
			wantLen: 7,
		},
		{name: "no position", query: "up", message: "something went wrong", wantLen: 0},
		{name: "zero position", query: "up", message: "at char 0: x", wantLen: 0},
		{
			name: "past the end clamps", query: "up", message: "at char 99: x",
			wantLen: 3,
		},
		{
			// Pins the len(query)+1 clamp bound itself (not just that clamping
			// happens): col 2 sits below len(query)+1 (3) so it must pass
			// through unclamped, at 2 rather than being pulled to 3. An
			// ARITHMETIC_BASE mutation of the bound to len(query)-1 (1) would
			// wrongly clamp this to len(query)+1's *unmutated* 3.
			name: "below the clamp bound is untouched", query: "up", message: "at char 2: x",
			wantLen: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := promqlCaret(tc.query, tc.message)
			if len(got) != tc.wantLen {
				t.Errorf("caret = %q (%d chars), want %d", got, len(got), tc.wantLen)
			}
			if tc.wantLen > 0 && !strings.HasSuffix(got, "^") {
				t.Errorf("caret does not end in a caret: %q", got)
			}
		})
	}
}

// TestParseTime covers the three accepted forms and the rejections.
func TestParseTime(t *testing.T) {
	t.Parallel()
	now := testNow
	tests := []struct {
		name    string
		in      string
		want    time.Time
		wantErr bool
	}{
		{name: "empty is zero", in: "", want: time.Time{}},
		{name: "whitespace is zero", in: "   ", want: time.Time{}},
		{name: "now", in: "now", want: now},
		{name: "now with trailing space", in: "now ", want: now},
		{name: "now minus", in: "now-90m", want: now.Add(-90 * time.Minute)},
		{name: "now plus", in: "now+1h", want: now.Add(time.Hour)},
		{name: "bare minus", in: "-1w", want: now.Add(-7 * 24 * time.Hour)},
		{name: "bare plus", in: "+500ms", want: now.Add(500 * time.Millisecond)},
		{name: "compound", in: "now-1h30m", want: now.Add(-90 * time.Minute)},
		{name: "rfc3339", in: "2026-01-02T03:04:05Z",
			want: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		{name: "unix", in: "1000000000", want: time.Unix(1000000000, 0).UTC()},
		{name: "unix fractional", in: "1000000000.5",
			want: time.Unix(1000000000, 500000000).UTC()},
		{name: "no sign after now", in: "now6h", wantErr: true},
		{name: "bad duration", in: "now-6x", wantErr: true},
		{name: "prose", in: "last tuesday", wantErr: true},
		{name: "empty offset", in: "-", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTime(tc.in, now)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTime(%q) = %v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTime(%q): %v", tc.in, err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("ParseTime(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseDuration covers the duration argument parser.
func TestParseDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "30s", want: 30 * time.Second},
		{in: "1h30m", want: 90 * time.Minute},
		{in: "1d", want: 24 * time.Hour},
		{in: "90", want: 90 * time.Second},
		{in: "0", wantErr: true},
		{in: "-5m", wantErr: true},
		{in: "banana", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseDuration(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDuration(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestValidateExpr covers the pre-flight checks on a PromQL argument.
func TestValidateExpr(t *testing.T) {
	t.Parallel()
	if terr := validateExpr("", "c"); terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("empty query: %v", terr)
	} else if !strings.Contains(terr.Hint, "search_metrics") {
		t.Errorf("hint = %q", terr.Hint)
	}
	long := strings.Repeat("a", MaxPromQLBytes+1)
	if terr := validateExpr(long, "c"); terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("oversized query: %v", terr)
	}
	if terr := validateExpr("up", "c"); terr != nil {
		t.Errorf("a valid query was rejected: %v", terr)
	}
}

// TestInstantLookbackLimit covers the ceiling on an instant query's time,
// including the principal's own tighter limit.
func TestInstantLookbackLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.MaxLookback = 48 * time.Hour })
	_, terr := h.tools.query(ctx(t), h.p,
		QueryIn{Cluster: okCluster, Query: "up", Time: "now-7d"})
	if terr == nil || terr.Code != CodeRangeTooLarge {
		t.Fatalf("terr = %v, want RANGE_TOO_LARGE", terr)
	}
	if terr.Corrected["time"] != "now-2d" {
		t.Errorf("corrected time = %v", terr.Corrected["time"])
	}

	// The principal's own limit tightens the hub's.
	tight := principal(fullScope())
	tight.Scope.Limits.MaxLookback = 3600_000_000_000 // 1h
	_, terr = h.tools.query(ctx(t), tight,
		QueryIn{Cluster: okCluster, Query: "up", Time: "now-2h"})
	if terr == nil || terr.Code != CodeRangeTooLarge {
		t.Fatalf("terr = %v, want the principal's limit to bite", terr)
	}
}

// TestPrincipalLimitsTightenRangeCaps covers the scope's own point and series
// ceilings.
func TestPrincipalLimitsTightenRangeCaps(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: syntheticMatrix(t, 20, 10, testNow.Add(-10*time.Minute), time.Minute),
	})
	p := principal(fullScope())
	p.Scope.Limits.MaxSeries = 3
	p.Scope.Limits.MaxPoints = 10

	out, terr := h.tools.queryRange(ctx(t), p, QueryRangeIn{
		Cluster: okCluster, Query: "x", Start: "now-10m", MaxSeries: 200, MaxPoints: 500,
	})
	if terr != nil {
		t.Fatalf("queryRange: %v", terr)
	}
	if len(out.Series) != 3 {
		t.Errorf("series = %d, want the principal's cap of 3", len(out.Series))
	}
	if out.Points > 11 {
		t.Errorf("points = %d, want the principal's budget of 10 to drive the step", out.Points)
	}
}

// TestMalformedDataPayload covers a well-formed envelope with an unreadable
// data member.
func TestMalformedDataPayload(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlerts),
		fakeResponse{body: []byte(`{"status":"success","data":["not an object"]}`)})
	_, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}

	h.prom.set(string(promapi.EndpointQuery),
		fakeResponse{body: []byte(`{"status":"success","data":{"resultType":"vector",` +
			`"result":"not a vector"}}`)})
	if _, terr := h.tools.query(ctx(t), h.p,
		QueryIn{Cluster: okCluster, Query: "up"}); terr == nil ||
		terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestEmptyDataIsNotAnError covers an envelope with no data member.
func TestEmptyDataIsNotAnError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointLabels), fakeResponse{body: []byte(`{"status":"success"}`)})
	out, terr := h.tools.labelNames(ctx(t), h.p, LabelNamesIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("labelNames: %v", terr)
	}
	if len(out.Names) != 0 {
		t.Errorf("names = %v", out.Names)
	}
}

// TestAlertAndRuleTables covers the fixed-width renderings.
func TestAlertAndRuleTables(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a, terr := h.tools.alerts(ctx(t), h.p,
		AlertsIn{Cluster: okCluster, State: AlertAll, Format: "table",
			IncludeAnnotations: true})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if a.Alerts != nil {
		t.Error("table format still carried the structured alerts")
	}
	for _, want := range []string{"ALERT", "SEVERITY", "SUMMARY", "KubePodCrashLooping"} {
		if !strings.Contains(a.Table, want) {
			t.Errorf("alert table does not contain %q:\n%s", want, a.Table)
		}
	}

	r, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Format: "table"})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if r.Rules != nil {
		t.Error("table format still carried the structured rules")
	}
	for _, want := range []string{"GROUP", "RULE", "HEALTH", "kubernetes-apps"} {
		if !strings.Contains(r.Table, want) {
			t.Errorf("rule table does not contain %q:\n%s", want, r.Table)
		}
	}
}

// TestValueTextAndLabelsText cover the table cell renderers.
func TestValueTextAndLabelsText(t *testing.T) {
	t.Parallel()
	f := 1.5
	tests := []struct {
		in   any
		want string
	}{
		{in: &f, want: "1.5"},
		{in: (*float64)(nil), want: ""},
		{in: 2.25, want: "2.25"},
		{in: "text", want: "text"},
		{in: 7, want: "7"},
	}
	for _, tc := range tests {
		if got := valueText(tc.in); got != tc.want {
			t.Errorf("valueText(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := labelsText(nil); got != "" {
		t.Errorf("labelsText(nil) = %q", got)
	}
	if got := labelsText(map[string]string{"b": "2", "a": "1"}); got != "a=1,b=2" {
		t.Errorf("labelsText = %q, want sorted", got)
	}
}

// TestSmallHelpers covers the shared argument helpers.
func TestSmallHelpers(t *testing.T) {
	t.Parallel()
	if got := clampInt(0, 10, 1, 100); got != 10 {
		t.Errorf("clampInt zero = %d", got)
	}
	if got := clampInt(500, 10, 1, 100); got != 100 {
		t.Errorf("clampInt above = %d", got)
	}
	if got := clampInt(-5, 10, 1, 100); got != 10 {
		t.Errorf("clampInt negative = %d", got)
	}
	if diff := cmp.Diff([]string{"a", "b"}, dedupe([]string{"a", "b", "a"})); diff != "" {
		t.Errorf("dedupe (-want +got):\n%s", diff)
	}
	if got := dedupe(nil); got != nil {
		t.Errorf("dedupe(nil) = %v", got)
	}
	// Pins the len(s) < 2 boundary: exactly two elements must still be
	// deduplicated when they are equal, not passed through unchanged.
	if diff := cmp.Diff([]string{"a"}, dedupe([]string{"a", "a"})); diff != "" {
		t.Errorf("dedupe of two equal elements (-want +got):\n%s", diff)
	}
	if !matchesSelector(map[string]string{"a": "1"}, nil) {
		t.Error("an empty selector must match everything")
	}
	if matchesSelector(map[string]string{"a": "1"}, map[string]string{"a": "2"}) {
		t.Error("a mismatched selector matched")
	}
	if !includes([]string{"a"}, "a") || includes([]string{"a"}, "b") {
		t.Error("includes is wrong")
	}
	if got := factsAge(testClusters()[0], testNow); got != 30*time.Second {
		t.Errorf("factsAge = %v", got)
	}
	// A clock skew that puts LastSeen in the future must not report a negative
	// age; a negative number in a result is a bug an agent cannot reason about.
	c := testClusters()[0]
	c.LastSeen = testNow.Add(time.Hour)
	if got := factsAge(c, testNow); got != 0 {
		t.Errorf("factsAge with skew = %v, want 0", got)
	}
	c.LastSeen = time.Time{}
	if got := factsAge(c, testNow); got != 0 {
		t.Errorf("factsAge with no contact = %v", got)
	}
	if got := maxZero(-1); got != 0 {
		t.Errorf("maxZero(-1) = %d", got)
	}
	// Pins the v <= 0 boundary: zero itself must still map to 0 (a spoke that
	// truly has no metric names is different from -1's "could not collect",
	// but both render the same to an agent), while 1 must pass through.
	if got := maxZero(0); got != 0 {
		t.Errorf("maxZero(0) = %d, want 0", got)
	}
	if got := maxZero(1); got != 1 {
		t.Errorf("maxZero(1) = %d, want 1", got)
	}
	if got := plural(1, "y", "ies"); got != "y" {
		t.Errorf("plural(1) = %q", got)
	}
}

// TestPlural covers both branches of the singular/plural picker directly: the
// only existing exercise of it was the n==1 case above, so n==0 and n>1 (the
// "many" return) were unreached.
func TestPlural(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n         int
		one, many string
		want      string
	}{
		{n: 1, one: "y", many: "ies", want: "y"},
		{n: 0, one: "y", many: "ies", want: "ies"},
		{n: 2, one: "y", many: "ies", want: "ies"},
		{n: -1, one: "y", many: "ies", want: "ies"},
	}
	for _, tc := range tests {
		if got := plural(tc.n, tc.one, tc.many); got != tc.want {
			t.Errorf("plural(%d, %q, %q) = %q, want %q", tc.n, tc.one, tc.many, got, tc.want)
		}
	}
}

// TestParseRelativeTrailingWhitespace covers parseRelative's own defensive
// handling of a "now" prefix whose body trims to empty. ParseTime always
// trims its input before calling parseRelative, so s can never actually equal
// "now" plus trailing whitespace by the time parseRelative sees it through
// that path — this exercises parseRelative directly, as an internal
// function, to reach the branch on its own terms.
func TestParseRelativeTrailingWhitespace(t *testing.T) {
	t.Parallel()
	now := testNow
	got, ok, err := parseRelative("now   ", now)
	if !ok {
		t.Fatal("\"now   \" was not recognised as a relative form")
	}
	if err != nil {
		t.Fatalf("parseRelative: %v", err)
	}
	if !got.Equal(now.UTC()) {
		t.Errorf("parseRelative(\"now   \") = %v, want %v", got, now.UTC())
	}
}

// TestClipList covers the shared-truncation folding directly: which section's
// [render.Truncation] survives when two sections are both cut depends on
// which had the larger overflow, and describeCluster's own fixture data never
// produces an unequal pair, so only the "keep prev" side was reachable
// through it.
func TestClipList(t *testing.T) {
	t.Parallel()
	// No truncation: the input is returned unchanged and prev passes through.
	kept, trunc := clipList([]string{"a", "b"}, 5, nil, "jobs", "hint")
	if trunc != nil || len(kept) != 2 {
		t.Fatalf("clipList with nothing to cut: kept=%v trunc=%+v", kept, trunc)
	}

	// First section cut, no prior truncation: its own Truncation is returned.
	kept, first := clipList([]string{"a", "b", "c"}, 1, nil, "jobs", "hint")
	if first == nil || len(kept) != 1 {
		t.Fatalf("first cut: kept=%v trunc=%+v", kept, first)
	}
	if first.Selection != "jobs_first_1" {
		t.Errorf("selection = %q", first.Selection)
	}

	// A second section cut with a *smaller* overflow than the first keeps the
	// first section's Truncation.
	kept2, prevKept := clipList([]string{"x", "y"}, 1, first, "prefixes", "hint2")
	if len(kept2) != 1 {
		t.Fatalf("second cut kept = %v", kept2)
	}
	if prevKept != first {
		t.Errorf("a smaller overflow displaced the larger one: got %+v, want the jobs cut", prevKept)
	}

	// A second section cut with a *larger* overflow than the first replaces
	// it, because the bigger gap is the one most likely to have hidden the
	// answer.
	bigList := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	kept3, replaced := clipList(bigList, 1, first, "namespaces", "hint3")
	if len(kept3) != 1 {
		t.Fatalf("third cut kept = %v", kept3)
	}
	if replaced == first {
		t.Error("a larger overflow did not displace the smaller one")
	}
	if replaced.Selection != "namespaces_first_1" {
		t.Errorf("selection = %q, want the larger cut's own section named", replaced.Selection)
	}
	if replaced.Total-replaced.Returned <= first.Total-first.Returned {
		t.Errorf("replaced overflow (%d) is not larger than the original (%d)",
			replaced.Total-replaced.Returned, first.Total-first.Returned)
	}
}

// TestClipListOverflowTieAndAsymmetricCounts covers two edges of the
// trunc.Total-trunc.Returned > prev.Total-prev.Returned comparison that
// TestClipList's own numbers happen not to distinguish: an exact tie (which
// pins the ">" boundary against ">=") and a case where prev's Total and
// Returned are far enough apart that prev.Total-prev.Returned and
// prev.Total+prev.Returned pick different winners (which pins the "-" against
// a "+" on prev's side of the comparison).
func TestClipListOverflowTieAndAsymmetricCounts(t *testing.T) {
	t.Parallel()

	// Tie: prev has overflow 2 (4 items, topN 2), the new cut also has
	// overflow 2 (6 items, topN 4). A strictly-greater comparison must keep
	// prev; ">=" would wrongly replace it.
	_, prev := clipList([]string{"a", "b", "c", "d"}, 2, nil, "jobs", "hint")
	if prev == nil || prev.Total-prev.Returned != 2 {
		t.Fatalf("prev = %+v, want overflow 2", prev)
	}
	_, tied := clipList([]string{"1", "2", "3", "4", "5", "6"}, 4, prev, "prefixes", "hint2")
	if tied != prev {
		t.Errorf("a tied overflow displaced prev: got %+v, want the original jobs cut %+v", tied, prev)
	}

	// Asymmetric: prev has a small overflow (1) but a large Returned (9), so
	// prev.Total-prev.Returned (1) and prev.Total+prev.Returned (19) send the
	// comparison different ways once the new cut's overflow (2) is checked
	// against them.
	bigPrevList := make([]string, 10)
	for i := range bigPrevList {
		bigPrevList[i] = fmt.Sprint(i)
	}
	_, asymPrev := clipList(bigPrevList, 9, nil, "jobs", "hint")
	if asymPrev == nil || asymPrev.Total-asymPrev.Returned != 1 {
		t.Fatalf("asymPrev = %+v, want overflow 1", asymPrev)
	}
	_, asymNew := clipList([]string{"a", "b", "c", "d", "e"}, 3, asymPrev, "namespaces", "hint2")
	if asymNew == asymPrev {
		t.Errorf("an overflow of 2 did not displace prev's overflow of 1: got %+v", asymNew)
	}
	if asymNew.Selection != "namespaces_first_3" {
		t.Errorf("selection = %q, want the larger cut's own section named", asymNew.Selection)
	}
}

// TestFirstErr covers the multi-section "keep the first failure" helper
// directly: order matters (the first error must survive even when a later,
// different error is passed next), which the existing runtime_info tests
// never distinguish because only one section fails at a time in them.
func TestFirstErr(t *testing.T) {
	t.Parallel()
	e1 := newError(CodeUpstreamError, "first failure", true)
	e2 := newError(CodeQueryTimeout, "second failure", true)

	if got := firstErr(nil, nil); got != nil {
		t.Errorf("firstErr(nil, nil) = %v, want nil", got)
	}
	if got := firstErr(nil, e1); got != e1 {
		t.Errorf("firstErr(nil, e1) = %v, want e1", got)
	}
	if got := firstErr(e1, e2); got != e1 {
		t.Errorf("firstErr(e1, e2) = %v, want the first error retained, not the second", got)
	}
	if got := firstErr(e1, nil); got != e1 {
		t.Errorf("firstErr(e1, nil) = %v, want e1 kept", got)
	}
}

// TestJSONContentMarshalError covers jsonContent's own error path directly.
// None of this package's resource bodies actually contain a value
// json.Marshal can fail on, so the three call sites (readClusters,
// readCluster, readFiringAlerts) can never reach it; jsonContent is a
// general-purpose helper, so it keeps the branch, and it is exercised here
// with a value manufactured to fail marshalling.
func TestJSONContentMarshalError(t *testing.T) {
	t.Parallel()
	_, err := jsonContent(make(chan int))
	if err == nil {
		t.Fatal("jsonContent accepted a channel, which json.Marshal cannot encode")
	}
	code, ok := mcpsurface.ErrorCode(err)
	if !ok || code != mcpsurface.CodeInvalidParams {
		t.Errorf("err = %v (code %d), want CodeInvalidParams", err, code)
	}
}

// TestNopMetrics covers the discard implementation.
func TestNopMetrics(t *testing.T) {
	t.Parallel()
	var m Metrics = NopMetrics{}
	m.ToolCall("x", "ok")
	m.ToolDuration("x", time.Second)
}

// TestResolveClusterRejectsMalformedName proves a name outside the grammar is
// refused before it reaches a registry lookup.
func TestResolveClusterRejectsMalformedName(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, bad := range []string{"", "UPPER", "has space", "-leading", "trailing-",
		strings.Repeat("a", 64)} {
		_, terr := h.tools.resolveCluster(h.p, bad)
		if terr == nil {
			t.Errorf("cluster %q was accepted", bad)
			continue
		}
		if bad == "" && terr.Code != CodeInvalidArgument {
			t.Errorf("empty cluster: code = %s", terr.Code)
		}
		if bad != "" && terr.Code != CodeUnknownCluster {
			t.Errorf("cluster %q: code = %s, want UNKNOWN_CLUSTER", bad, terr.Code)
		}
	}
}

// TestPrefixWarnings covers the per-cluster warning attribution.
func TestPrefixWarnings(t *testing.T) {
	t.Parallel()
	if got := prefixWarnings("c", nil); got != nil {
		t.Errorf("prefixWarnings(nil) = %v", got)
	}
	got := prefixWarnings("c", []string{"w1", "w2"})
	if diff := cmp.Diff([]string{"c: w1", "c: w2"}, got); diff != "" {
		t.Errorf("prefixWarnings (-want +got):\n%s", diff)
	}
}

// TestRedactURLQueries covers the free-text URL redaction directly.
func TestRedactURLQueries(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{
			in:   `Get "https://h:9100/metrics?token=abc": dial tcp: refused`,
			want: `Get "https://h:9100/metrics?[redacted]": dial tcp: refused`,
		},
		{
			in:   `Get "https://h:9100/metrics": dial tcp: refused`,
			want: `Get "https://h:9100/metrics": dial tcp: refused`,
		},
		{
			in:   `two http://a/x?k=v and https://b/y?k=v here`,
			want: `two http://a/x?[redacted] and https://b/y?[redacted] here`,
		},
		{in: "no url at all", want: "no url at all"},
		{in: "", want: ""},
	}
	for _, tc := range tests {
		if got := RedactURLQueries(tc.in); got != tc.want {
			t.Errorf("RedactURLQueries(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
