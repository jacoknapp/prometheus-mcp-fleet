// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

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

	env := failed(e)
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
	if got := plural(1, "y", "ies"); got != "y" {
		t.Errorf("plural(1) = %q", got)
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
