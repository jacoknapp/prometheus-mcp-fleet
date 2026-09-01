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

// TestTargetMetadataBasic covers the success path against the recorded
// fixture, which deliberately has two targets disagreeing on the same
// metric's type — the exact case metric_metadata cannot show.
func TestTargetMetadataBasic(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.targetMetadata(ctx(t), h.p, TargetMetadataIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if out.Total != 2 || len(out.Metadata) != 2 {
		t.Fatalf("metadata = %+v, want 2 entries", out.Metadata)
	}
	types := map[string]bool{}
	for _, m := range out.Metadata {
		if m.Metric != "node_cpu_seconds_total" {
			t.Errorf("metric = %q, want node_cpu_seconds_total", m.Metric)
		}
		if m.Target["job"] != "node-exporter" {
			t.Errorf("target labels missing job: %+v", m.Target)
		}
		types[m.Type] = true
	}
	if !types["counter"] || !types["gauge"] {
		t.Errorf("the per-target type disagreement was lost: %+v", out.Metadata)
	}
	if out.Untrusted != render.UntrustedNotice {
		t.Error("target metadata carries remote data and must be marked untrusted")
	}
}

// TestTargetMetadataWithMetricFilter covers the request-side metric filter,
// under which Prometheus omits the "metric" field from every entry.
func TestTargetMetadataWithMetricFilter(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargetsMetadata), fakeResponse{body: []byte(`{
		"status": "success",
		"data": [
			{"target": {"job": "prometheus", "instance": "127.0.0.1:9090"},
			 "type": "gauge", "help": "Number of goroutines.", "unit": ""}
		]
	}`)})
	out, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster, Metric: "go_goroutines"})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if len(out.Metadata) != 1 || out.Metadata[0].Metric != "go_goroutines" {
		t.Fatalf("metadata = %+v, want the filter metric attached", out.Metadata)
	}
	if got := h.prom.lastForm(promapi.EndpointTargetsMetadata)["metric"]; len(got) != 1 || got[0] != "go_goroutines" {
		t.Errorf("metric param = %v, want it forwarded upstream", got)
	}
}

// TestTargetMetadataDropsUnnamedEntries covers the defensive skip: an entry
// naming no metric, upstream or in the request, cannot be reported without
// inventing a key.
func TestTargetMetadataDropsUnnamedEntries(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargetsMetadata), fakeResponse{body: []byte(`{
		"status": "success",
		"data": [
			{"target": {"job": "x"}, "type": "gauge", "help": "", "unit": ""},
			{"target": {"job": "x"}, "metric": "bad metric name", "type": "gauge"}
		]
	}`)})
	out, terr := h.tools.targetMetadata(ctx(t), h.p, TargetMetadataIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if len(out.Metadata) != 0 {
		t.Errorf("metadata = %+v, want both unnamed entries dropped", out.Metadata)
	}
}

// TestTargetMetadataOrdersByMetricThenTarget covers both branches of the
// sort comparator: entries naming different metrics sort by metric name
// first, and only fall back to comparing targets when the metric matches.
func TestTargetMetadataOrdersByMetricThenTarget(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargetsMetadata), fakeResponse{body: []byte(`{
		"status": "success",
		"data": [
			{"target": {"job": "x"}, "metric": "zzz_metric", "type": "gauge"},
			{"target": {"job": "x"}, "metric": "aaa_metric", "type": "gauge"}
		]
	}`)})
	out, terr := h.tools.targetMetadata(ctx(t), h.p, TargetMetadataIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if len(out.Metadata) != 2 || out.Metadata[0].Metric != "aaa_metric" ||
		out.Metadata[1].Metric != "zzz_metric" {
		t.Fatalf("metadata = %+v, want aaa_metric before zzz_metric", out.Metadata)
	}
}

// TestTargetMetadataInvalidMetric covers the metric-name argument check.
func TestTargetMetadataInvalidMetric(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster, Metric: "has-a-dash"}); terr == nil ||
		terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestTargetMetadataInvalidMatchTarget covers the selector structural check.
func TestTargetMetadataInvalidMatchTarget(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster, MatchTarget: "not a selector"}); terr == nil ||
		terr.Code != CodeBadMatcher {
		t.Fatalf("terr = %v, want BAD_MATCHER", terr)
	}
}

// TestTargetMetadataForwardsMatchTarget proves a valid selector reaches the
// upstream call unmodified.
func TestTargetMetadataForwardsMatchTarget(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster, MatchTarget: `{job="node-exporter"}`})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if got := h.prom.lastForm(promapi.EndpointTargetsMetadata)["match_target"]; len(got) != 1 || got[0] != `{job="node-exporter"}` {
		t.Errorf("match_target param = %v", got)
	}
}

// TestTargetMetadataUnknownCluster covers the resolveCluster failure path.
func TestTargetMetadataUnknownCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: "no-such-cluster"}); terr == nil ||
		terr.Code != CodeUnknownCluster {
		t.Fatalf("terr = %v, want UNKNOWN_CLUSTER", terr)
	}
}

// TestTargetMetadataUpstreamFailure covers the fetch failure path.
func TestTargetMetadataUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargetsMetadata), fakeResponse{err: errors.New("boom")})
	if _, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster}); terr == nil {
		t.Fatal("an upstream failure was not reported")
	}
}

// TestTargetMetadataMalformedPayload covers the decode failure path.
func TestTargetMetadataMalformedPayload(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargetsMetadata),
		fakeResponse{body: []byte(`{"status":"success","data":"not an array"}`)})
	if _, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster}); terr == nil ||
		terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// syntheticTargetMetadata builds n entries for the truncation and
// token-ceiling tests below.
func syntheticTargetMetadata(t *testing.T, n int) []byte {
	t.Helper()
	entries := make([]any, 0, n)
	for i := range n {
		entries = append(entries, map[string]any{
			"target": map[string]string{"instance": fmt.Sprintf("host-%04d:9100", i), "job": "synthetic"},
			"metric": "synthetic_metric",
			"type":   "gauge", "help": "synthetic help text", "unit": "",
		})
	}
	body, err := json.Marshal(map[string]any{"status": "success", "data": entries})
	if err != nil {
		t.Fatalf("marshal synthetic target metadata: %v", err)
	}
	return body
}

// TestTargetMetadataLimitTruncates covers the count-limit truncation.
func TestTargetMetadataLimitTruncates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargetsMetadata), fakeResponse{body: syntheticTargetMetadata(t, 10)})
	out, terr := h.tools.targetMetadata(ctx(t), h.p, TargetMetadataIn{Cluster: okCluster, Limit: 1})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if len(out.Metadata) != 1 {
		t.Fatalf("metadata = %+v, want exactly 1", out.Metadata)
	}
	if out.Truncated == nil || out.Truncated.Total != 10 {
		t.Fatalf("truncated = %+v, want total 10", out.Truncated)
	}
}

// TestTargetMetadataTokenCeiling covers the hub-wide token budget, distinct
// from the count-limit truncation above.
func TestTargetMetadataTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 50
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointTargetsMetadata), fakeResponse{body: syntheticTargetMetadata(t, 200)})
	out, terr := h.tools.targetMetadata(ctx(t), h.p,
		TargetMetadataIn{Cluster: okCluster, Limit: 1000})
	if terr != nil {
		t.Fatalf("targetMetadata: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncated = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}
