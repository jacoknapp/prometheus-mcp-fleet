// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
)

// TestExplainPromQLNeverErrors is the defining property of this tool: an
// invalid expression is the answer, not a failure. An isError result would tell
// the model its call went wrong rather than its query.
func TestExplainPromQLNeverErrors(t *testing.T) {
	t.Parallel()
	inputs := []string{
		"",
		"   ",
		"up",
		`rate(http_requests_total{job="api"}[5m])`,
		`rate(http_requests_total{job=api}[5m])`,
		"sum(",
		")",
		"}",
		"]",
		"up{",
		`up{job="`,
		"up[",
		"up[5x]",
		"up[]",
		"up offset",
		"{__name__=~\".+\"}",
		strings.Repeat("(", 5000),
		strings.Repeat("a", MaxPromQLBytes+1),
		"\x00\x01\x02",
		"日本語メトリクス",
		"# just a comment",
		"1 + 1",
		"up # comment {",
		"topk(5, sum by(job) (rate(x_total[5m])))",
		"quantile_over_time(0.99, up[1h:5m])",
		`label_replace(up, "x", "$1", "job", "(.*)")`,
	}
	for _, in := range inputs {
		t.Run(shortName(in), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			fn := run(h.tools, ToolExplainPromQL,
				func() *ExplainPromQLOut { return &ExplainPromQLOut{} }, h.tools.explainPromQL)
			out, res, err := fn(ctx(t), request(ToolExplainPromQL, h.p), ExplainPromQLIn{Query: in})
			if err != nil {
				t.Fatalf("explain_promql returned an error for %q: %v", in, err)
			}
			if res.IsError {
				t.Errorf("explain_promql marked %q as a tool error", in)
			}
			if out == nil {
				t.Fatal("nil result")
			}
			if out.Error != nil {
				t.Errorf("explain_promql produced a tool error body: %+v", out.Error)
			}
			if !out.Valid && out.Message == "" {
				t.Errorf("%q was rejected without a message", in)
			}
		})
	}
}

// shortName makes a readable subtest name from an expression.
func shortName(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 32 {
		s = s[:32]
	}
	if s == "" {
		return "empty"
	}
	return s
}

// TestExplainPromQLValid covers the analysis of well-formed expressions.
func TestExplainPromQLValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		query        string
		wantMetrics  []string
		wantFuncs    []string
		wantAggs     []string
		wantWindows  []string
		wantLabels   []string
		wantSelector int
	}{
		{
			name: "bare selector", query: "up",
			wantMetrics: []string{"up"}, wantSelector: 1,
		},
		{
			name:        "rate over a counter",
			query:       `rate(http_requests_total{job="api",code=~"5.."}[5m])`,
			wantMetrics: []string{"http_requests_total"}, wantFuncs: []string{"rate"},
			wantWindows: []string{"5m"}, wantLabels: []string{"code", "job"}, wantSelector: 1,
		},
		{
			name:         "aggregation with grouping",
			query:        `sum by(namespace) (rate(container_cpu_usage_seconds_total[5m]))`,
			wantMetrics:  []string{"container_cpu_usage_seconds_total"},
			wantFuncs:    []string{"rate"},
			wantAggs:     []string{"sum"},
			wantWindows:  []string{"5m"},
			wantLabels:   []string{"namespace"},
			wantSelector: 1,
		},
		{
			name:  "binary operator over two metrics",
			query: `node_filesystem_avail_bytes / node_filesystem_size_bytes`,
			wantMetrics: []string{
				"node_filesystem_avail_bytes", "node_filesystem_size_bytes"},
			wantSelector: 2,
		},
		{
			name:         "histogram quantile",
			query:        `histogram_quantile(0.99, sum by(le) (rate(x_bucket[5m])))`,
			wantMetrics:  []string{"x_bucket"},
			wantFuncs:    []string{"histogram_quantile", "rate"},
			wantAggs:     []string{"sum"},
			wantWindows:  []string{"5m"},
			wantLabels:   []string{"le"},
			wantSelector: 1,
		},
		{
			name: "constant", query: "1 + 2", wantSelector: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			out, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{Query: tc.query})
			if terr != nil {
				t.Fatalf("explainPromQL: %v", terr)
			}
			if !out.Valid {
				t.Fatalf("%q was rejected: %s", tc.query, out.Message)
			}
			if diff := cmp.Diff(tc.wantMetrics, out.MetricsReferenced); diff != "" {
				t.Errorf("metrics (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantFuncs, out.Functions); diff != "" {
				t.Errorf("functions (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantAggs, out.Aggregations); diff != "" {
				t.Errorf("aggregations (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantWindows, out.RangeWindows); diff != "" {
				t.Errorf("rangeWindows (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantLabels, out.LabelsReferenced); diff != "" {
				t.Errorf("labels (-want +got):\n%s", diff)
			}
			if out.Summary == "" {
				t.Error("no summary")
			}
		})
	}
}

// TestExplainPromQLInvalid covers each structural fault and its caret.
func TestExplainPromQLInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		query       string
		wantMessage string
		wantCaretAt int
	}{
		{
			name: "unquoted matcher value", query: `up{job=api}`,
			wantMessage: "expected string", wantCaretAt: 8,
		},
		{
			name: "unclosed brace", query: `up{job="api"`,
			wantMessage: "unclosed", wantCaretAt: 3,
		},
		{
			name: "unclosed paren", query: `sum(rate(x[5m])`,
			wantMessage: "unclosed", wantCaretAt: 4,
		},
		{
			name: "unexpected close", query: `up)`,
			wantMessage: "unexpected", wantCaretAt: 3,
		},
		{
			name: "mismatched close", query: `sum(up}`,
			wantMessage: "expected to close", wantCaretAt: 7,
		},
		{
			name: "unterminated string", query: `up{job="api}`,
			wantMessage: "unterminated string", wantCaretAt: 8,
		},
		{
			name: "bad duration", query: `rate(up[5x])`,
			wantMessage: "not a valid duration", wantCaretAt: 9,
		},
		{
			name: "unclosed range", query: `rate(up[5m)`,
			wantMessage: "unclosed range selector", wantCaretAt: 8,
		},
		{
			name: "stray close bracket", query: `up]`,
			wantMessage: "unexpected", wantCaretAt: 3,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			out, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{Query: tc.query})
			if terr != nil {
				t.Fatalf("explainPromQL: %v", terr)
			}
			if out.Valid {
				t.Fatalf("%q was accepted", tc.query)
			}
			if !strings.Contains(out.Message, tc.wantMessage) {
				t.Errorf("message = %q, want it to contain %q", out.Message, tc.wantMessage)
			}
			if out.Caret == "" {
				t.Fatal("no caret")
			}
			if len(out.Caret) != tc.wantCaretAt {
				t.Errorf("caret is %d characters, want %d so it lands on the fault:\n%s\n%s",
					len(out.Caret), tc.wantCaretAt, tc.query, out.Caret)
			}
			if strings.TrimSpace(out.Caret) != "^" {
				t.Errorf("caret = %q", out.Caret)
			}
		})
	}
}

// TestExplainPromQLCounterAdvice covers the advisory that stops a model
// graphing a monotonically rising counter and calling it a spike.
func TestExplainPromQLCounterAdvice(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.explainPromQL(ctx(t), h.p,
		ExplainPromQLIn{Query: "http_requests_total"})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if len(out.Suggestions) == 0 {
		t.Fatal("no advice about reading a counter raw")
	}
	if !strings.Contains(out.Suggestions[0], "rate(") {
		t.Errorf("suggestion does not offer the fix: %q", out.Suggestions[0])
	}

	// Wrapped in rate(), the advice must not fire.
	wrapped, terr := h.tools.explainPromQL(ctx(t), h.p,
		ExplainPromQLIn{Query: "rate(http_requests_total[5m])"})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	for _, s := range wrapped.Suggestions {
		if strings.Contains(s, "looks like a counter") {
			t.Errorf("counter advice fired on a rated counter: %q", s)
		}
	}
}

// TestExplainPromQLUnknownFunction covers the advisory for a misspelled
// function, which must not make the expression "invalid": this hub's function
// list will fall behind upstream and a false rejection is worse than a hint.
func TestExplainPromQLUnknownFunction(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.explainPromQL(ctx(t), h.p,
		ExplainPromQLIn{Query: "raet(up[5m])"})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if !out.Valid {
		t.Error("an unrecognised function name made the expression invalid")
	}
	var advised bool
	for _, s := range out.Suggestions {
		if strings.Contains(s, "not one this hub recognises") {
			advised = true
		}
	}
	if !advised {
		t.Errorf("no advisory for an unknown function: %v", out.Suggestions)
	}
}

// TestExplainPromQLChecksMetricExistence covers the cluster-aware path and its
// did-you-mean.
func TestExplainPromQLChecksMetricExistence(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{
		Query: "rate(container_cpu_usage_second_total[5m])", Cluster: okCluster,
	})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if out.ClusterChecked != okCluster {
		t.Errorf("clusterChecked = %q", out.ClusterChecked)
	}
	if diff := cmp.Diff([]string{"container_cpu_usage_second_total"},
		out.UnknownMetrics); diff != "" {
		t.Errorf("unknownMetrics (-want +got):\n%s", diff)
	}
	var suggested bool
	for _, s := range out.Suggestions {
		if strings.Contains(s, "container_cpu_usage_seconds_total") {
			suggested = true
		}
	}
	if !suggested {
		t.Errorf("no did-you-mean for a one-character typo: %v", out.Suggestions)
	}

	// A metric that does exist produces no complaint.
	good, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{
		Query: "rate(container_cpu_usage_seconds_total[5m])", Cluster: okCluster,
	})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if len(good.UnknownMetrics) != 0 {
		t.Errorf("unknownMetrics = %v", good.UnknownMetrics)
	}
}

// TestExplainPromQLSkipsCheckGracefully proves an unreachable cluster degrades
// the enrichment, not the answer.
func TestExplainPromQLSkipsCheckGracefully(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cluster string
		setup   func(*harness)
	}{
		{name: "unknown cluster", cluster: "no-such-cluster"},
		{
			name: "upstream failure", cluster: okCluster,
			setup: func(h *harness) {
				h.prom.set(string(promapi.EndpointLabelValues)+"/__name__",
					fakeResponse{err: promproxy.ErrUpstream})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			out, terr := h.tools.explainPromQL(ctx(t), h.p,
				ExplainPromQLIn{Query: "rate(up[5m])", Cluster: tc.cluster})
			if terr != nil {
				t.Fatalf("explainPromQL errored: %v", terr)
			}
			if !out.Valid {
				t.Error("the structural answer was lost with the enrichment")
			}
			if out.CheckSkipped == "" {
				t.Error("the skipped check was not explained; an empty unknownMetrics " +
					"would read as 'everything exists'")
			}
			if out.ClusterChecked != "" {
				t.Errorf("clusterChecked = %q despite the check not happening",
					out.ClusterChecked)
			}
		})
	}
}

// TestExplainPromQLByteLimitBoundary pins the len(q) > MaxPromQLBytes
// boundary: an expression of exactly MaxPromQLBytes must reach the structural
// analyzer rather than being rejected on length, and only MaxPromQLBytes+1
// must produce the byte-limit message.
func TestExplainPromQLByteLimitBoundary(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	atLimit, terr := h.tools.explainPromQL(ctx(t), h.p,
		ExplainPromQLIn{Query: strings.Repeat("a", MaxPromQLBytes)})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if strings.Contains(atLimit.Message, "byte limit") {
		t.Errorf("message = %q, an expression of exactly MaxPromQLBytes was rejected on length",
			atLimit.Message)
	}

	overLimit, terr := h.tools.explainPromQL(ctx(t), h.p,
		ExplainPromQLIn{Query: strings.Repeat("a", MaxPromQLBytes+1)})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if !strings.Contains(overLimit.Message, "byte limit") {
		t.Errorf("message = %q, want the byte-limit rejection at MaxPromQLBytes+1", overLimit.Message)
	}
}

// TestSummarizeAnalysisBoundaries pins the len(...) > 0 / Subqueries > 0
// boundaries in summarizeAnalysis directly: each part of the summary must be
// absent with zero of a kind and present starting at exactly one.
func TestSummarizeAnalysisBoundaries(t *testing.T) {
	t.Parallel()

	none := summarizeAnalysis(promQLAnalysis{Valid: true})
	if strings.Contains(none, "function") || strings.Contains(none, "aggregation") ||
		strings.Contains(none, "range window") || strings.Contains(none, "subquer") {
		t.Errorf("summary = %q, want none of the optional parts with nothing to report", none)
	}

	withFunc := summarizeAnalysis(promQLAnalysis{Valid: true, Functions: []string{"rate"}})
	if !strings.Contains(withFunc, "functions rate") {
		t.Errorf("summary = %q, want it to mention the one function", withFunc)
	}

	withAgg := summarizeAnalysis(promQLAnalysis{Valid: true, Aggregations: []string{"sum"}})
	if !strings.Contains(withAgg, "aggregations sum") {
		t.Errorf("summary = %q, want it to mention the one aggregation", withAgg)
	}

	withWindow := summarizeAnalysis(promQLAnalysis{Valid: true, RangeWindows: []string{"5m"}})
	if !strings.Contains(withWindow, "range windows 5m") {
		t.Errorf("summary = %q, want it to mention the one range window", withWindow)
	}

	withSubquery := summarizeAnalysis(promQLAnalysis{Valid: true, Subqueries: 1})
	if !strings.Contains(withSubquery, "1 subquery") {
		t.Errorf("summary = %q, want it to mention the one subquery", withSubquery)
	}
}

// TestExplainPromQLNoClusterSaysSo covers the no-cluster notice.
func TestExplainPromQLNoClusterSaysSo(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{Query: "up"})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if !strings.Contains(out.CheckSkipped, "No cluster") {
		t.Errorf("checkSkipped = %q", out.CheckSkipped)
	}
}

// TestExplainPromQLNoClusterNoMetricsSaysNothing pins the len(a.Metrics) > 0
// boundary that gates the no-cluster notice: a constant expression names no
// metric at all, so there is nothing an existence check could have verified,
// and the notice must stay silent rather than tell the caller to pass
// cluster for no reason.
func TestExplainPromQLNoClusterNoMetricsSaysNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{Query: "1 + 1"})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if len(out.MetricsReferenced) != 0 {
		t.Fatalf("metricsReferenced = %v, want none for a constant expression", out.MetricsReferenced)
	}
	if out.CheckSkipped != "" {
		t.Errorf("checkSkipped = %q, want empty with no metrics to check", out.CheckSkipped)
	}
}

// TestValidDuration covers the duration grammar the range-selector check uses.
func TestValidDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"5m", true}, {"1h30m", true}, {"500ms", true}, {"1d", true}, {"1w", true},
		{"1y", true}, {"300", true}, {"", false}, {"5x", false}, {"m5", false},
		{"5m5", false}, {"-5m", false}, {"5.5m", false},
	}
	for _, tc := range tests {
		if got := validDuration(tc.in); got != tc.want {
			t.Errorf("validDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestNearestNames covers the metric did-you-mean ranking.
func TestNearestNames(t *testing.T) {
	t.Parallel()
	candidates := []string{
		"node_cpu_seconds_total", "node_memory_MemAvailable_bytes",
		"container_cpu_usage_seconds_total", "up",
	}
	got := nearestNames("node_cpu_second_total", candidates, 3)
	if len(got) == 0 || got[0] != "node_cpu_seconds_total" {
		t.Errorf("nearestNames = %v", got)
	}
	// Nothing remotely similar produces nothing, rather than a confident wrong
	// suggestion.
	if got := nearestNames("zzzzzzzzzzzzzzzz", candidates, 3); len(got) != 0 {
		t.Errorf("nearestNames on an unrelated name = %v, want none", got)
	}
	if got := nearestNames("up", candidates, 0); got != nil {
		t.Errorf("n=0 returned %v", got)
	}
	if got := nearestNames("up", nil, 3); got != nil {
		t.Errorf("no candidates returned %v", got)
	}
}

// TestNearestNamesTiesAndTruncation covers the ranking's tie-break by name
// and its cap at n, neither of which the single-close-match cases above
// exercise: they never produce more than one candidate past the distance
// cutoff.
func TestNearestNamesTiesAndTruncation(t *testing.T) {
	t.Parallel()
	// "xat", "yat" and "zat" are all edit distance 1 from "cat": a genuine
	// three-way tie, broken alphabetically.
	got := nearestNames("cat", []string{"zat", "xat", "yat"}, 3)
	want := []string{"xat", "yat", "zat"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("tie-break (-want +got):\n%s", diff)
	}
	// The same three candidates capped at 2 keeps the alphabetically first
	// two of the tie, proving len(out) > n actually truncates.
	if got := nearestNames("cat", []string{"zat", "xat", "yat"}, 2); len(got) != 2 {
		t.Fatalf("nearestNames capped at 2 = %v", got)
	} else if diff := cmp.Diff([]string{"xat", "yat"}, got); diff != "" {
		t.Errorf("capped tie-break (-want +got):\n%s", diff)
	}
	// "bat" (distance 1) and "cost" (distance 2) both clear the cutoff but are
	// genuinely unequal distances, so the ranking must put the closer one
	// first without falling into the name tie-break at all.
	if got := nearestNames("cat", []string{"cost", "bat"}, 5); !cmp.Equal([]string{"bat", "cost"}, got) {
		t.Errorf("unequal-distance ranking = %v, want [bat cost] (closer first)", got)
	}
}

// TestClipRunesTo covers the rune-safe clip directly, including the
// over-length case nearestNames only reaches with a target or candidate name
// longer than 128 runes.
func TestClipRunesTo(t *testing.T) {
	t.Parallel()
	if got := clipRunesTo("hello", 10); got != "hello" {
		t.Errorf("clipRunesTo under the limit = %q", got)
	}
	if got := clipRunesTo("hello", 3); got != "hel" {
		t.Errorf("clipRunesTo over the limit = %q", got)
	}
	if got := clipRunesTo("hello", 0); got != "" {
		t.Errorf("clipRunesTo(_, 0) = %q", got)
	}
	// Multi-byte runes: clip by rune count, not byte count, so the result
	// stays valid UTF-8.
	if got := clipRunesTo("日本語メトリクス", 3); got != "日本語" {
		t.Errorf("clipRunesTo on multi-byte runes = %q", got)
	}
}

// TestEditDistanceEdgeCases covers the Levenshtein helper directly: empty
// strings, equal strings and the off-by-one cases nearestNames' cutoff filter
// never surfaces on its own.
func TestEditDistanceEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "both empty", a: "", b: "", want: 0},
		{name: "one empty", a: "", b: "abc", want: 3},
		{name: "other empty", a: "abc", b: "", want: 3},
		{name: "equal", a: "abc", b: "abc", want: 0},
		{name: "one substitution", a: "abc", b: "abd", want: 1},
		{name: "one insertion", a: "abc", b: "abcd", want: 1},
		{name: "one deletion", a: "abcd", b: "abc", want: 1},
		{name: "totally different", a: "abc", b: "xyz", want: 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := editDistance([]rune(tc.a), []rune(tc.b)); got != tc.want {
				t.Errorf("editDistance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			// Symmetric: swapping the arguments must not change the answer.
			if got := editDistance([]rune(tc.b), []rune(tc.a)); got != tc.want {
				t.Errorf("editDistance(%q, %q) = %d, want %d (swapped)", tc.b, tc.a, got, tc.want)
			}
		})
	}
}

// TestExplainPromQLUnknownMetricNoSuggestion covers the branch of the
// existence check where the metric does not exist and nothing in the cluster
// is close enough to suggest — the generic "call search_metrics" advice,
// which the near-match case in TestExplainPromQLChecksMetricExistence never
// reaches.
func TestExplainPromQLUnknownMetricNoSuggestion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.explainPromQL(ctx(t), h.p, ExplainPromQLIn{
		Query: "totally_unrelated_metric_xyz_zzz", Cluster: okCluster,
	})
	if terr != nil {
		t.Fatalf("explainPromQL: %v", terr)
	}
	if diff := cmp.Diff([]string{"totally_unrelated_metric_xyz_zzz"}, out.UnknownMetrics); diff != "" {
		t.Errorf("unknownMetrics (-want +got):\n%s", diff)
	}
	var found bool
	for _, s := range out.Suggestions {
		if strings.Contains(s, "Call search_metrics to find the right name") {
			found = true
			if strings.Contains(s, "Did you mean") {
				t.Errorf("a no-match suggestion still offered a did-you-mean: %q", s)
			}
		}
	}
	if !found {
		t.Errorf("no generic search_metrics advice for a metric with no near match: %v",
			out.Suggestions)
	}
}

// TestAnalyzePromQLMatcherWhitespace covers the whitespace-skip after a
// matcher operator, which the existing fixtures (always "label=\"value\""
// with no interior space) never trigger.
func TestAnalyzePromQLMatcherWhitespace(t *testing.T) {
	t.Parallel()
	a := analyzePromQL(`up{job=  "api"}`)
	if !a.Valid {
		t.Fatalf("whitespace after a matcher operator was rejected: %s", a.Message)
	}
	if diff := cmp.Diff([]string{"job"}, a.Labels); diff != "" {
		t.Errorf("labels (-want +got):\n%s", diff)
	}
}

// TestAnalyzePromQLInvalidUTF8 covers the final UTF-8 validity check, which
// only fires once a full, structurally sound scan completes without any
// earlier fault.
func TestAnalyzePromQLInvalidUTF8(t *testing.T) {
	t.Parallel()
	a := analyzePromQL("up" + string([]byte{0xff, 0xfe}))
	if a.Valid {
		t.Fatal("invalid UTF-8 was accepted as a valid expression")
	}
	if !strings.Contains(a.Message, "not valid UTF-8") {
		t.Errorf("message = %q, want it to name the UTF-8 fault", a.Message)
	}
	if a.Position != 1 {
		t.Errorf("position = %d, want 1", a.Position)
	}
}

// TestAnalyzePromQLEscapedQuoteInString covers scanString's backslash-escape
// handling: without it, an escaped quote inside a double-quoted matcher value
// would be misread as the string's terminator.
func TestAnalyzePromQLEscapedQuoteInString(t *testing.T) {
	t.Parallel()
	a := analyzePromQL(`up{job="a\"b"}`)
	if !a.Valid {
		t.Fatalf("an escaped quote inside a string was rejected: %s", a.Message)
	}
	if diff := cmp.Diff([]string{"up"}, a.Metrics); diff != "" {
		t.Errorf("metrics (-want +got):\n%s", diff)
	}
}
