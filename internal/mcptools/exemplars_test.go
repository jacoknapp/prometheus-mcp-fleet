// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// TestQueryExemplarsBasic covers the success path against the recorded
// fixture: sanitisation, the most-recent-first ordering and the two summary
// counts.
func TestQueryExemplarsBasic(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: "http_request_duration_seconds_bucket"})
	if terr != nil {
		t.Fatalf("queryExemplars: %v", terr)
	}
	if out.SeriesMatched != 1 {
		t.Errorf("seriesMatched = %d, want 1", out.SeriesMatched)
	}
	if out.Total != 2 || len(out.Exemplars) != 2 {
		t.Fatalf("exemplars = %+v, want 2", out.Exemplars)
	}
	// The fixture lists the earlier exemplar first; the tool must reorder it
	// most-recent-first.
	if out.Exemplars[0].TimestampMillis <= out.Exemplars[1].TimestampMillis {
		t.Errorf("exemplars are not most-recent-first: %+v", out.Exemplars)
	}
	if out.Exemplars[0].Labels["span_id"] != "789a" {
		t.Errorf("expected the later exemplar first, got %+v", out.Exemplars[0])
	}
	if out.Exemplars[0].SeriesLabels["job"] != "api" {
		t.Errorf("seriesLabels were not attached: %+v", out.Exemplars[0])
	}
	if out.Untrusted != render.UntrustedNotice {
		t.Error("exemplars carry remote data and must be marked untrusted")
	}
}

// TestQueryExemplarsSortIsStableAndTotalOrder covers the two comparator
// branches TestQueryExemplarsBasic's two-element fixture cannot reach: two
// exemplars already in the right order (no swap needed) and two exemplars
// tied on timestamp (which must not reorder relative to each other).
func TestQueryExemplarsSortIsStableAndTotalOrder(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryExemplars), fakeResponse{body: []byte(`{
		"status": "success",
		"data": [{
			"seriesLabels": {"__name__": "up"},
			"exemplars": [
				{"labels": {"trace_id": "first"}, "value": "1", "timestamp": 300},
				{"labels": {"trace_id": "second"}, "value": "1", "timestamp": 200},
				{"labels": {"trace_id": "third"}, "value": "1", "timestamp": 200}
			]
		}]
	}`)})
	out, terr := h.tools.queryExemplars(ctx(t), h.p, QueryExemplarsIn{Cluster: okCluster, Query: "up"})
	if terr != nil {
		t.Fatalf("queryExemplars: %v", terr)
	}
	if len(out.Exemplars) != 3 {
		t.Fatalf("exemplars = %+v, want 3", out.Exemplars)
	}
	got := []string{
		out.Exemplars[0].Labels["trace_id"],
		out.Exemplars[1].Labels["trace_id"],
		out.Exemplars[2].Labels["trace_id"],
	}
	want := []string{"first", "second", "third"}
	if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("order = %v, want %v (most-recent-first, ties kept stable)", got, want)
	}
}

// TestQueryExemplarsInvalidQuery covers the structural argument checks.
func TestQueryExemplarsInvalidQuery(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: ""}); terr == nil ||
		terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestQueryExemplarsInvalidTime covers the range-parsing failure path.
func TestQueryExemplarsInvalidTime(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: "up", Start: "not-a-time"}); terr == nil ||
		terr.Code != CodeInvalidTime {
		t.Fatalf("terr = %v, want INVALID_TIME", terr)
	}
}

// TestQueryExemplarsUnknownCluster covers the resolveCluster failure path.
func TestQueryExemplarsUnknownCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: "no-such-cluster", Query: "up"}); terr == nil ||
		terr.Code != CodeUnknownCluster {
		t.Fatalf("terr = %v, want UNKNOWN_CLUSTER", terr)
	}
}

// TestQueryExemplarsUpstreamFailure covers the fetch failure path.
func TestQueryExemplarsUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryExemplars), fakeResponse{err: errors.New("boom")})
	if _, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: "up"}); terr == nil {
		t.Fatal("an upstream failure was not reported")
	}
}

// TestQueryExemplarsMalformedPayload covers the decode failure path.
func TestQueryExemplarsMalformedPayload(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryExemplars),
		fakeResponse{body: []byte(`{"status":"success","data":"not an array"}`)})
	if _, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: "up"}); terr == nil ||
		terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// syntheticExemplars builds n series, each with one exemplar, for the
// truncation and token-ceiling tests below.
func syntheticExemplars(t *testing.T, n int) []byte {
	t.Helper()
	series := make([]any, 0, n)
	for i := range n {
		series = append(series, map[string]any{
			"seriesLabels": map[string]string{
				"__name__": "http_request_duration_seconds_bucket",
				"instance": fmt.Sprintf("host-%04d:9100", i),
			},
			"exemplars": []any{
				map[string]any{
					"labels":    map[string]string{"trace_id": fmt.Sprintf("trace-%04d", i)},
					"value":     "0.1",
					"timestamp": float64(1756468700 + i),
				},
			},
		})
	}
	body, err := json.Marshal(map[string]any{"status": "success", "data": series})
	if err != nil {
		t.Fatalf("marshal synthetic exemplars: %v", err)
	}
	return body
}

// TestQueryExemplarsLimitTruncates covers the count-limit truncation.
func TestQueryExemplarsLimitTruncates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryExemplars), fakeResponse{body: syntheticExemplars(t, 10)})
	out, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: "up", Limit: 1})
	if terr != nil {
		t.Fatalf("queryExemplars: %v", terr)
	}
	if len(out.Exemplars) != 1 {
		t.Fatalf("exemplars = %+v, want exactly 1", out.Exemplars)
	}
	if out.Truncated == nil || out.Truncated.Total != 10 {
		t.Fatalf("truncated = %+v, want total 10", out.Truncated)
	}
}

// TestQueryExemplarsTokenCeiling covers the hub-wide token budget, distinct
// from the count-limit truncation above.
func TestQueryExemplarsTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 50
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointQueryExemplars), fakeResponse{body: syntheticExemplars(t, 200)})
	out, terr := h.tools.queryExemplars(ctx(t), h.p,
		QueryExemplarsIn{Cluster: okCluster, Query: "up", Limit: 500})
	if terr != nil {
		t.Fatalf("queryExemplars: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncated = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}
