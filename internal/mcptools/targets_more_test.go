// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// TestTargetsMalformedUpstream covers the decode-data failure path.
func TestTargetsMalformedUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargets), fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-object"}`),
	})
	_, terr := h.tools.targets(ctx(t), h.p, TargetsIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// mixedJobTargets builds an /api/v1/targets payload spanning two jobs in both
// activeTargets and droppedTargets, so a job filter actually has something to
// discard from each loop rather than matching everything by accident the way
// the single-job default fixture does.
func mixedJobTargets() []byte {
	body, _ := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"activeTargets": []any{
				map[string]any{
					"discoveredLabels": map[string]string{},
					"labels":           map[string]string{"instance": "a", "job": "wanted"},
					"scrapePool":       "wanted/0", "scrapeUrl": "http://a/metrics",
					"health": "up", "lastScrape": "2026-08-26T11:00:00Z", "scrapeInterval": "30s",
				},
				map[string]any{
					"discoveredLabels": map[string]string{},
					"labels":           map[string]string{"instance": "b", "job": "other"},
					"scrapePool":       "other/0", "scrapeUrl": "http://b/metrics",
					"health": "up", "lastScrape": "2026-08-26T11:00:00Z", "scrapeInterval": "30s",
				},
			},
			"droppedTargets": []any{
				map[string]any{
					"discoveredLabels": map[string]string{"job": "wanted"},
					"scrapePool":       "wanted/0",
				},
				map[string]any{
					"discoveredLabels": map[string]string{"job": "other"},
					"scrapePool":       "other/0",
				},
			},
		},
	})
	return body
}

// TestTargetsJobFilterSkipsOtherJobs proves the job filter discards
// non-matching entries in both the active and the dropped loop, not just the
// matching ones.
func TestTargetsJobFilterSkipsOtherJobs(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargets), fakeResponse{body: mixedJobTargets()})

	out, terr := h.tools.targets(ctx(t), h.p,
		TargetsIn{Cluster: okCluster, Job: "wanted", State: TargetStateAny})
	if terr != nil {
		t.Fatalf("targets: %v", terr)
	}
	if len(out.Targets) != 2 {
		t.Fatalf("targets = %+v, want exactly the 2 \"wanted\" entries (1 active, 1 dropped)", out.Targets)
	}
	for _, tg := range out.Targets {
		if tg.Job != "wanted" {
			t.Errorf("job filter leaked %q", tg.Job)
		}
	}
	// The summary must still count the "other" job's entries even though the
	// listing dropped them.
	if out.Summary.Up == 0 {
		t.Error("the summary was filtered along with the listing")
	}
}

// TestTargetsJobTieBreak proves that when two targets share a health rank,
// the job name breaks the tie in the stable sort.
func TestTargetsJobTieBreak(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"activeTargets": []any{
				map[string]any{
					"discoveredLabels": map[string]string{},
					"labels":           map[string]string{"instance": "a", "job": "zzz-job"},
					"scrapePool":       "zzz/0", "scrapeUrl": "http://a/metrics",
					"health": "up", "lastScrape": "2026-08-26T11:00:00Z", "scrapeInterval": "30s",
				},
				map[string]any{
					"discoveredLabels": map[string]string{},
					"labels":           map[string]string{"instance": "b", "job": "aaa-job"},
					"scrapePool":       "aaa/0", "scrapeUrl": "http://b/metrics",
					"health": "up", "lastScrape": "2026-08-26T11:00:00Z", "scrapeInterval": "30s",
				},
			},
			"droppedTargets": []any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargets), fakeResponse{body: body})

	out, terr := h.tools.targets(ctx(t), h.p, TargetsIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("targets: %v", terr)
	}
	if len(out.Targets) != 2 || out.Targets[0].Job != "aaa-job" || out.Targets[1].Job != "zzz-job" {
		t.Fatalf("targets = %+v, want the equal-health pair tie-broken by job name", out.Targets)
	}
}

// syntheticTargets builds an /api/v1/targets payload with n active targets,
// all up, so it can push a result past a small token ceiling while also
// exercising the count-limit truncation.
func syntheticTargets(t *testing.T, n int) []byte {
	t.Helper()
	active := make([]any, 0, n)
	for i := range n {
		active = append(active, map[string]any{
			"discoveredLabels": map[string]string{},
			"labels": map[string]string{
				"instance": fmt.Sprintf("host-with-a-long-name-%04d:9100", i), "job": "synthetic",
			},
			"scrapePool": "synthetic/0", "scrapeUrl": "http://x/metrics",
			"health": "up", "lastScrape": "2026-08-26T11:00:00Z", "scrapeInterval": "30s",
		})
	}
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data":   map[string]any{"activeTargets": active, "droppedTargets": []any{}},
	})
	if err != nil {
		t.Fatalf("marshal synthetic targets: %v", err)
	}
	return body
}

// TestTargetsLimitTruncates covers the count-limit truncation marker.
func TestTargetsLimitTruncates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargets), fakeResponse{body: syntheticTargets(t, 10)})
	out, terr := h.tools.targets(ctx(t), h.p, TargetsIn{Cluster: okCluster, Limit: 1})
	if terr != nil {
		t.Fatalf("targets: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Selection != "down_first_then_job_instance" {
		t.Fatalf("truncation = %+v, want the fixed selection marker", out.Truncated)
	}
}

// TestTargetsTokenCeiling covers the token-ceiling escalation, distinct from
// the count-limit truncation above.
func TestTargetsTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointTargets), fakeResponse{body: syntheticTargets(t, 200)})
	out, terr := h.tools.targets(ctx(t), h.p, TargetsIn{Cluster: okCluster, Limit: 500})
	if terr != nil {
		t.Fatalf("targets: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Selection != "down_first_then_job_instance" {
		t.Errorf("selection = %q", out.Truncated.Selection)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}
