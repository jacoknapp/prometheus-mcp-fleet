// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// connectedClusters returns the two clusters a fan-out can actually reach.
var connectedClusters = []string{"eu-west-prod-1", "us-east-prod-2"}

// TestFanoutInstantComplete covers the happy path and the complete-coverage
// preamble.
func TestFanoutInstantComplete(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if !out.Coverage.Complete || out.Coverage.OK != 2 || out.Coverage.Requested != 2 {
		t.Fatalf("coverage = %+v", out.Coverage)
	}
	if !strings.HasPrefix(out.Preamble, "Complete result") {
		t.Errorf("preamble = %q", out.Preamble)
	}
	if diff := cmp.Diff(FanoutColumns, out.Columns); diff != "" {
		t.Errorf("columns (-want +got):\n%s", diff)
	}
	if len(out.Rows) == 0 {
		t.Fatal("no rows")
	}
	if out.Rows[0][0] != "eu-west-prod-1" {
		t.Errorf("rows are not ordered by cluster: %v", out.Rows[0])
	}
	if diff := cmp.Diff(connectedClusters, out.PerCluster.OK); diff != "" {
		t.Errorf("perCluster.ok (-want +got):\n%s", diff)
	}
}

// TestFanoutPartialFailureIsLoud is the test that stops a model reporting a
// fleet minimum computed over half the fleet.
func TestFanoutPartialFailureIsLoud(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set("us-east-prod-2/"+string(promapi.EndpointQuery), fakeResponse{
		err: &promproxy.NotConnectedError{
			ClusterID: "us-east-prod-2",
			LastSeen:  testNow.Add(-time.Minute),
			Since:     time.Minute,
		},
	})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters,
	})
	if terr != nil {
		t.Fatalf("partial failure became a tool error: %v", terr)
	}
	if out.Coverage.Complete {
		t.Error("coverage claims completeness with one cluster failed")
	}
	if out.Coverage.OK != 1 || out.Coverage.Failed != 1 || out.Coverage.Requested != 2 {
		t.Errorf("coverage = %+v", out.Coverage)
	}
	if !strings.HasPrefix(out.Preamble, "Partial result: 1 of 2 clusters.") {
		t.Errorf("preamble does not state the coverage first: %q", out.Preamble)
	}
	if !strings.Contains(out.Preamble, "incomplete") {
		t.Errorf("preamble does not warn: %q", out.Preamble)
	}
	if len(out.PerCluster.Failed) != 1 {
		t.Fatalf("perCluster.failed = %+v", out.PerCluster.Failed)
	}
	f := out.PerCluster.Failed[0]
	if f.Cluster != "us-east-prod-2" || f.Code != CodeSpokeUnreachable || !f.Retryable {
		t.Errorf("failure = %+v", f)
	}
}

// TestFanoutTimeoutIsReportedSeparately proves a slow cluster is accounted as
// timed out rather than merged into "failed", and does not fail the call.
func TestFanoutTimeoutIsReportedSeparately(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set("us-east-prod-2/"+string(promapi.EndpointQuery),
		fakeResponse{delay: 2 * time.Second})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Deadline: "200ms",
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.TimedOut != 1 || out.Coverage.OK != 1 {
		t.Fatalf("coverage = %+v", out.Coverage)
	}
	if diff := cmp.Diff([]string{"us-east-prod-2"}, out.PerCluster.TimedOut); diff != "" {
		t.Errorf("timedOut (-want +got):\n%s", diff)
	}
	if len(out.Rows) == 0 {
		t.Error("the cluster that did answer was discarded along with the slow one")
	}
}

// TestFanoutOnErrorFail covers the all-or-nothing policy.
func TestFanoutOnErrorFail(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set("us-east-prod-2/"+string(promapi.EndpointQuery),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, OnError: OnErrorFail,
	})
	if terr == nil || terr.Code != CodeAllClustersFailed {
		t.Fatalf("terr = %v, want ALL_CLUSTERS_FAILED", terr)
	}
	if !strings.Contains(terr.Hint, "partial") {
		t.Errorf("hint does not offer the partial policy: %q", terr.Hint)
	}
}

// TestFanoutAllFailed covers the case where nothing answered at all.
func TestFanoutAllFailed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters,
	})
	if terr == nil || terr.Code != CodeAllClustersFailed {
		t.Fatalf("terr = %v, want ALL_CLUSTERS_FAILED", terr)
	}
	if terr.Retryable == nil || !*terr.Retryable {
		t.Error("a fleet-wide upstream failure is retryable")
	}
}

// TestFanoutClusterLabelCollision proves source data is never silently
// overwritten.
func TestFanoutClusterLabelCollision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// A federated setup legitimately carries a cluster label of its own.
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "vector",
			"result": []any{map[string]any{
				"metric": map[string]string{
					"__name__": "up", "job": "api", "cluster": "legacy-name-from-federation",
				},
				"value": []any{1787047200.0, "1"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.prom.set("eu-west-prod-1/"+string(promapi.EndpointQuery), fakeResponse{body: body})

	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: []string{"eu-west-prod-1"},
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("rows = %v", out.Rows)
	}
	labels, ok := out.Rows[0][2].(map[string]string)
	if !ok {
		t.Fatalf("row labels are %T", out.Rows[0][2])
	}
	if labels[ClusterOriginalLabel] != "legacy-name-from-federation" {
		t.Errorf("the original cluster label was not preserved: %v", labels)
	}
	if out.Rows[0][0] != "eu-west-prod-1" {
		t.Errorf("the injected cluster is wrong: %v", out.Rows[0])
	}
	if len(out.Warnings) == 0 {
		t.Fatal("the collision was silent")
	}
	if !strings.Contains(out.Warnings[0], ClusterOriginalLabel) {
		t.Errorf("warning does not name the preserved label: %q", out.Warnings[0])
	}
}

// TestFanoutNoSelectorTooBroad covers the refusal of the pathological case.
func TestFanoutNoSelectorTooBroad(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", MaxClusters: 2,
	})
	if terr == nil || terr.Code != CodeNoSelectorTooBroad {
		t.Fatalf("terr = %v, want NO_SELECTOR_TOO_BROAD", terr)
	}
	if !strings.Contains(terr.Hint, "labelSelector") {
		t.Errorf("hint does not name the fix: %q", terr.Hint)
	}
	if len(h.prom.calls) != 0 {
		t.Error("the refused fan-out still contacted clusters")
	}

	// A fleet smaller than maxClusters is allowed without a selector: the rule
	// exists to prevent accidents, not to forbid the small case.
	if _, terr := h.tools.fanoutQuery(ctx(t), h.p,
		FanoutQueryIn{Query: "up", MaxClusters: 10}); terr != nil &&
		terr.Code == CodeNoSelectorTooBroad {
		t.Error("a four-cluster fleet was refused as too broad")
	}
}

// TestFanoutNoClustersMatched covers an empty selection.
func TestFanoutNoClustersMatched(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", LabelSelector: map[string]string{"env": "nowhere"},
	})
	if terr == nil || terr.Code != CodeNoClustersMatched {
		t.Fatalf("terr = %v, want NO_CLUSTERS_MATCHED", terr)
	}

	_, terr = h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: []string{"no-such-cluster"},
	})
	if terr == nil || terr.Code != CodeNoClustersMatched {
		t.Fatalf("terr = %v, want NO_CLUSTERS_MATCHED", terr)
	}
	if len(terr.DidYouMean) == 0 {
		t.Error("no did-you-mean for an all-unknown cluster list")
	}
}

// TestFanoutUnknownClusterIsAccountedNotFatal proves one bad name in a list
// does not lose the rest.
func TestFanoutUnknownClusterIsAccountedNotFatal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: append([]string{"typo-cluster"}, connectedClusters...),
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.Requested != 3 || out.Coverage.OK != 2 || out.Coverage.Failed != 1 {
		t.Fatalf("coverage = %+v", out.Coverage)
	}
	var found bool
	for _, f := range out.PerCluster.Failed {
		if f.Cluster == "typo-cluster" && f.Code == CodeUnknownCluster {
			found = true
		}
	}
	if !found {
		t.Errorf("the unknown cluster was not accounted: %+v", out.PerCluster.Failed)
	}
}

// TestFanoutValidatesQueryOnce proves a syntax error costs one round trip, not
// one per cluster.
func TestFanoutValidatesQueryOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: `rate(http_requests_total{job=api}[5m])`, Clusters: connectedClusters,
	})
	if terr == nil || terr.Code != CodePromQLParse {
		t.Fatalf("terr = %v, want PROMQL_PARSE", terr)
	}
	if len(h.prom.calls) != 0 {
		t.Errorf("%d clusters were contacted with a known-bad expression", len(h.prom.calls))
	}
	if terr.Caret == "" {
		t.Error("no caret on a hub-side parse error")
	}
	if !strings.Contains(terr.Hint, "before any cluster was contacted") {
		t.Errorf("hint = %q", terr.Hint)
	}
}

// TestFanoutRangeCommonStep proves every cluster is put on one step and one
// aligned start, which is what makes the rows comparable.
func TestFanoutRangeCommonStep(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
		Start: "now-10m", End: "now", MaxSeriesPerCluster: 5,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Downsampled == nil {
		t.Fatal("no downsampled report")
	}
	// Ten minutes at the default point budget wants a 15s step. eu-west floors
	// at its 30s scrape interval and us-east at its 15s one, so the common step
	// is the larger of the two: 30s. Querying us-east at 15s would produce
	// points eu-west cannot match, and the rows would not line up.
	if out.Downsampled.AppliedStep != "30s" {
		t.Errorf("appliedStep = %q, want 30s", out.Downsampled.AppliedStep)
	}
	if !strings.Contains(out.Downsampled.Reason, "common step across 2 clusters") {
		t.Errorf("reason does not say the step is shared: %q", out.Downsampled.Reason)
	}
	if out.Start%int64(out.StepSeconds) != 0 {
		t.Errorf("start %d is not aligned to the %v step", out.Start, out.StepSeconds)
	}
	steps := h.prom.lastForm(promapi.EndpointQueryRange)["step"]
	if len(steps) != 1 || steps[0] != "30s" {
		t.Errorf("step sent upstream = %v", steps)
	}
	for _, s := range out.Series {
		if s.Cluster == "" {
			t.Error("a series carries no cluster")
		}
		if len(s.Values) != out.Points {
			t.Errorf("series has %d values, want %d", len(s.Values), out.Points)
		}
	}
}

// TestFanoutMaxSeriesPerCluster proves the per-cluster cap is applied and
// reported.
func TestFanoutMaxSeriesPerCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		body: syntheticVector(t, 30),
	})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, MaxSeriesPerCluster: 2,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if len(out.Rows) != 4 {
		t.Fatalf("rows = %d, want 2 clusters times 2 series", len(out.Rows))
	}
	if out.Truncated == nil {
		t.Fatal("the per-cluster cap was silent")
	}
	if out.Truncated.Total != 60 {
		t.Errorf("total = %d, want the honest 60", out.Truncated.Total)
	}
	if !strings.Contains(out.Truncated.Hint, "Aggregate") {
		t.Errorf("hint = %q", out.Truncated.Hint)
	}
}

// TestFanoutConcurrencyAndDeadlineBounds covers the argument clamping.
func TestFanoutConcurrencyAndDeadlineBounds(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// Concurrency above the ceiling is clamped rather than refused, so a model
	// that guesses 1000 still gets an answer.
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Concurrency: 1000, Deadline: "1h",
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.OK != 2 {
		t.Errorf("coverage = %+v", out.Coverage)
	}

	if _, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Deadline: "not a duration",
	}); terr == nil || terr.Code != CodeInvalidTime {
		t.Errorf("terr = %v, want INVALID_TIME for a bad deadline", terr)
	}
	if _, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: "sideways",
	}); terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("terr = %v, want INVALID_ARGUMENT for a bad mode", terr)
	}
	if _, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, OnError: "explode",
	}); terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("terr = %v, want INVALID_ARGUMENT for a bad onError", terr)
	}
}

// TestFanoutEmptyQueryRejected covers validateExpr's own call site inside
// fanoutQuery: TestValidateExpr only unit-tests the helper directly, and
// TestFanoutValidatesQueryOnce only ever sends a syntactically bad but
// non-empty expression, which takes the later analyzePromQL branch instead.
func TestFanoutEmptyQueryRejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "", Clusters: connectedClusters,
	})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT for an empty query", terr)
	}
	if len(h.prom.calls) != 0 {
		t.Error("an empty query still reached a cluster")
	}
}

// TestFanoutInstantBadTime covers mode "instant"'s own time-parsing error
// return, distinct from range mode's start/end/step parsing.
func TestFanoutInstantBadTime(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Time: "not-a-time",
	})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("terr = %v, want INVALID_TIME", terr)
	}
}

// TestFanoutRangeBadStartEndAndStep covers range mode's own resolveRange and
// step-parsing error returns, neither of which TestFanoutRangeCommonStep
// exercises since it only sends valid arguments.
func TestFanoutRangeBadStartEndAndStep(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
		Start: "now", End: "now-1h",
	})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("inverted range: terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
		Step: "not-a-duration",
	})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("bad step: terr = %v, want INVALID_TIME", terr)
	}
}

// TestFanoutMaxClustersTruncates proves an over-large selection is cut
// deterministically and the dropped clusters are named.
func TestFanoutMaxClustersTruncates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", LabelSelector: map[string]string{"env": "prod"}, MaxClusters: 1,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.Requested != 2 || out.Coverage.OK != 1 {
		t.Fatalf("coverage = %+v", out.Coverage)
	}
	if len(out.PerCluster.Failed) != 1 ||
		!strings.Contains(out.PerCluster.Failed[0].Message, "maxClusters") {
		t.Errorf("the dropped cluster was not named: %+v", out.PerCluster.Failed)
	}
	if out.PerCluster.OK[0] != "eu-west-prod-1" {
		t.Errorf("selection is not deterministic by name: %v", out.PerCluster.OK)
	}
}

// TestFanoutRespectsClusterScope proves the fan-out cannot reach a cluster the
// credential may not see, even when it is named explicitly.
func TestFanoutRespectsClusterScope(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	narrow := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{"us-east-prod-2"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
	out, terr := h.tools.fanoutQuery(ctx(t), narrow, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.OK != 1 || out.PerCluster.OK[0] != "us-east-prod-2" {
		t.Fatalf("coverage = %+v ok = %v", out.Coverage, out.PerCluster.OK)
	}
	for _, c := range h.prom.calls {
		if c.ClusterID == "eu-west-prod-1" {
			t.Error("an out-of-scope cluster was contacted")
		}
	}
}

// TestFanoutDispatchTimesOutWhileQueued proves a cluster that never even gets
// a concurrency slot before the overall deadline is accounted as timed out,
// not silently dropped or misreported as answered. With concurrency 1 and
// every cluster's query held open past its own per-cluster budget, only the
// first one or two targets ever run at all; the rest sit in dispatch's own
// select waiting on the semaphore, and the fan-out's overall deadline expires
// while they are still waiting on it, not while they are in flight — the
// distinct branch from TestFanoutTimeoutIsReportedSeparately, which only
// exercises a slow *in-flight* query.
func TestFanoutDispatchTimesOutWhileQueued(t *testing.T) {
	t.Parallel()
	// "queue-a" answers instantly so the fan-out has at least one success —
	// with zero successes, fanoutQuery collapses the whole call to a single
	// top-level ALL_CLUSTERS_FAILED error and the per-cluster detail this test
	// checks is never built at all (see TestFanoutAllFailed). The other four
	// each block far longer than any per-cluster or overall budget below, so
	// none of them ever completes on its own merits: with concurrency 1 they
	// serialise behind "queue-a", and only one of them (whichever inherits the
	// concurrency slot next) even starts before the overall deadline expires.
	entries := []fleet.Cluster{
		{ID: "queue-a", State: fleet.StateConnected, LastSeen: testNow},
		{ID: "queue-b", State: fleet.StateConnected, LastSeen: testNow},
		{ID: "queue-c", State: fleet.StateConnected, LastSeen: testNow},
		{ID: "queue-d", State: fleet.StateConnected, LastSeen: testNow},
		{ID: "queue-e", State: fleet.StateConnected, LastSeen: testNow},
	}
	h := newHarness(t, func(o *Options) { o.Clusters = &fakeClusters{entries: entries} })
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{delay: 10 * time.Second})
	h.prom.set("queue-a/"+string(promapi.EndpointQuery), fakeResponse{body: fixture(t, "query.json")})

	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query:       "up",
		Clusters:    []string{"queue-a", "queue-b", "queue-c", "queue-d", "queue-e"},
		Concurrency: 1,
		// Deadline under 2s pins perCluster at its 1-second floor (deadline/2
		// would otherwise equal it exactly and tie the two clocks together).
		// "queue-a" returns immediately; the remaining budget is nowhere near
		// enough to serialise four 1-second-budgeted slow clusters through one
		// concurrency slot, so at least the last of them never starts at all.
		Deadline: "1200ms",
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.OK != 1 || out.PerCluster.OK[0] != "queue-a" {
		t.Fatalf("coverage = %+v perCluster.ok = %v, want only queue-a to answer",
			out.Coverage, out.PerCluster.OK)
	}
	if out.Coverage.TimedOut != 4 {
		t.Fatalf("coverage.timedOut = %d, want the other 4 clusters accounted as timed out; "+
			"coverage = %+v perCluster = %+v", out.Coverage.TimedOut, out.Coverage, out.PerCluster)
	}
	want := []string{"queue-b", "queue-c", "queue-d", "queue-e"}
	if diff := cmp.Diff(want, out.PerCluster.TimedOut); diff != "" {
		// Every cluster must be named by its real ID — not merely counted —
		// which is what proves dispatch's own queued-timeout branch filled in
		// results[i] properly rather than leaving a zero-value result that
		// would carry an empty cluster ID and misclassify as OK.
		t.Errorf("perCluster.timedOut (-want +got):\n%s", diff)
	}
	if out.Coverage.Complete {
		t.Error("coverage claims completeness with 4 of 5 clusters timed out")
	}
}

// TestFanoutQueryOneMalformedBody covers queryOne's own decode failures,
// distinct from the single-cluster query/query_range malformed-body tests:
// this is the fan-out's own call site of DecodeQueryData, DecodeVector and
// DecodeMatrix.
func TestFanoutQueryOneMalformedBody(t *testing.T) {
	t.Parallel()

	// Each case breaks only eu-west-prod-1, leaving us-east-prod-2 to answer
	// normally: fanoutQuery collapses an all-clusters failure into a single
	// ALL_CLUSTERS_FAILED tool error with no per-cluster detail attached (see
	// TestFanoutAllFailed), so a partial failure is the only shape that lets
	// this test actually inspect PerCluster.Failed's code.
	t.Run("no data member", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.prom.set("eu-west-prod-1/"+string(promapi.EndpointQuery),
			fakeResponse{body: []byte(`{"status":"success"}`)})
		out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
			Query: "up", Clusters: connectedClusters,
		})
		if terr != nil {
			t.Fatalf("fanoutQuery: %v", terr)
		}
		if out.Coverage.Failed != 1 || out.Coverage.OK != 1 {
			t.Fatalf("coverage = %+v, want eu-west-prod-1 failed and us-east-prod-2 ok", out.Coverage)
		}
		for _, f := range out.PerCluster.Failed {
			if f.Code != CodeMalformedUpstream {
				t.Errorf("failure code = %q, want MALFORMED_UPSTREAM", f.Code)
			}
		}
	})

	t.Run("malformed vector", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.prom.set("eu-west-prod-1/"+string(promapi.EndpointQuery), fakeResponse{
			body: []byte(`{"status":"success","data":{"resultType":"vector","result":"not-an-array"}}`),
		})
		out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
			Query: "up", Clusters: connectedClusters,
		})
		if terr != nil {
			t.Fatalf("fanoutQuery: %v", terr)
		}
		if out.Coverage.Failed != 1 || out.Coverage.OK != 1 {
			t.Fatalf("coverage = %+v, want eu-west-prod-1 failed and us-east-prod-2 ok", out.Coverage)
		}
		for _, f := range out.PerCluster.Failed {
			if f.Code != CodeMalformedUpstream {
				t.Errorf("failure code = %q, want MALFORMED_UPSTREAM", f.Code)
			}
		}
	})

	t.Run("malformed matrix", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.prom.set("eu-west-prod-1/"+string(promapi.EndpointQueryRange), fakeResponse{
			body: []byte(`{"status":"success","data":{"resultType":"matrix","result":"not-an-array"}}`),
		})
		out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
			Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
			Start: "now-10m", End: "now",
		})
		if terr != nil {
			t.Fatalf("fanoutQuery: %v", terr)
		}
		if out.Coverage.Failed != 1 || out.Coverage.OK != 1 {
			t.Fatalf("coverage = %+v, want eu-west-prod-1 failed and us-east-prod-2 ok", out.Coverage)
		}
		for _, f := range out.PerCluster.Failed {
			if f.Code != CodeMalformedUpstream {
				t.Errorf("failure code = %q, want MALFORMED_UPSTREAM", f.Code)
			}
		}
	})
}

// TestFanoutInstantTokenCeiling proves the hub's token ceiling truncates a
// merged instant fan-out even when the per-cluster series cap alone would
// not, mirroring the single-cluster equivalents but never previously
// exercised for fan-out's own merge step.
func TestFanoutInstantTokenCeiling(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.TokenCeiling = 300 })
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{body: syntheticVector(t, 30)})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, MaxSeriesPerCluster: 30,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncated = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if len(out.Rows) >= 60 {
		t.Errorf("rows = %d, want fewer than the 60 available", len(out.Rows))
	}
}

// TestFanoutRangePartialFailure proves mergeRange skips a failed cluster's
// contribution rather than merging in its zero-value matrix, the range-mode
// analogue of TestFanoutPartialFailureIsLoud which only exercises instant
// mode.
func TestFanoutRangePartialFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set("us-east-prod-2/"+string(promapi.EndpointQueryRange), fakeResponse{
		err: fmt.Errorf("x: %w", promproxy.ErrUpstream),
	})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
		Start: "now-10m", End: "now",
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Coverage.OK != 1 || out.Coverage.Failed != 1 {
		t.Fatalf("coverage = %+v", out.Coverage)
	}
	for _, s := range out.Series {
		if s.Cluster == "us-east-prod-2" {
			t.Error("the failed cluster's zero-value matrix still contributed a series")
		}
	}
}

// TestFanoutRangeClusterLabelCollision is mergeRange's analogue of
// TestFanoutClusterLabelCollision, which only ever exercises mergeInstant.
func TestFanoutRangeClusterLabelCollision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "matrix",
			"result": []any{map[string]any{
				"metric": map[string]string{
					"__name__": "up", "job": "api", "cluster": "legacy-name-from-federation",
				},
				"values": []any{[]any{1787047200.0, "1"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.prom.set("eu-west-prod-1/"+string(promapi.EndpointQueryRange), fakeResponse{body: body})

	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: []string{"eu-west-prod-1"}, Mode: FanoutRange,
		Start: "now-10m", End: "now",
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if len(out.Series) != 1 {
		t.Fatalf("series = %v", out.Series)
	}
	if out.Series[0].Labels[ClusterOriginalLabel] != "legacy-name-from-federation" {
		t.Errorf("the original cluster label was not preserved: %v", out.Series[0].Labels)
	}
	if len(out.Warnings) == 0 {
		t.Fatal("the collision was silent")
	}
	if !strings.Contains(out.Warnings[0], ClusterOriginalLabel) {
		t.Errorf("warning does not name the preserved label: %q", out.Warnings[0])
	}
}

// TestFanoutRangeMaxSeriesPerCluster is mergeRange's analogue of
// TestFanoutMaxSeriesPerCluster, which only ever exercises mergeInstant.
func TestFanoutRangeMaxSeriesPerCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: syntheticMatrix(t, 30, 5, testNow.Add(-10*time.Minute), time.Minute),
	})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
		Start: "now-10m", End: "now", MaxSeriesPerCluster: 2,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if len(out.Series) != 4 {
		t.Fatalf("series = %d, want 2 clusters times 2 series", len(out.Series))
	}
	if out.Truncated == nil {
		t.Fatal("the per-cluster cap was silent")
	}
	if out.Truncated.Reason != render.ReasonMaxSeries {
		t.Errorf("reason = %q, want %q", out.Truncated.Reason, render.ReasonMaxSeries)
	}
	if out.Truncated.Total != 60 {
		t.Errorf("total = %d, want the honest 60", out.Truncated.Total)
	}
}

// TestFanoutRangeTokenCeiling proves the hub's token ceiling truncates a
// merged range fan-out even when the per-cluster series cap alone would not.
func TestFanoutRangeTokenCeiling(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.TokenCeiling = 300 })
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: syntheticMatrix(t, 30, 20, testNow.Add(-10*time.Minute), time.Minute),
	})
	out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
		Query: "up", Clusters: connectedClusters, Mode: FanoutRange,
		Start: "now-10m", End: "now", MaxSeriesPerCluster: 30,
	})
	if terr != nil {
		t.Fatalf("fanoutQuery: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncated = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if len(out.Series) >= 60 {
		t.Errorf("series = %d, want fewer than the 60 available", len(out.Series))
	}
}

// syntheticVector builds an instant payload with n distinct series.
func syntheticVector(t *testing.T, n int) []byte {
	t.Helper()
	result := make([]any, 0, n)
	for i := range n {
		result = append(result, map[string]any{
			"metric": map[string]string{
				"__name__": "synthetic",
				"job":      "synthetic",
				"pod":      fmt.Sprintf("workload-%04d", i),
			},
			"value": []any{1787047200.0, fmt.Sprint(i)},
		})
	}
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "vector", "result": result},
	})
	if err != nil {
		t.Fatalf("marshal synthetic vector: %v", err)
	}
	return body
}
