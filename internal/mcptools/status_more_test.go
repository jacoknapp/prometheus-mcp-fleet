// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"errors"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// TestTSDBStatsMalformedUpstream covers tsdbStats' own decode-data failure
// path, distinct from tsdbUnavailable's reclassification: a well-formed
// envelope (status "success") whose data member is not the head-statistics
// shape fails decodeData directly and is never routed through
// tsdbUnavailable at all, because that helper only wraps the error [fetch]
// itself returns.
func TestTSDBStatsMalformedUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTSDBStatus), fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-object"}`),
	})
	_, terr := h.tools.tsdbStats(ctx(t), h.p, TSDBStatsIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestTSDBStatsGenericUpstreamErrorPassesThrough proves tsdbUnavailable does
// not reclassify every failure as "not implemented": a plain upstream error
// with no 404/501 status and no malformed body must reach the caller as-is,
// so a transient failure gets the ordinary retry hint rather than the
// permanent workaround hint.
func TestTSDBStatsGenericUpstreamErrorPassesThrough(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTSDBStatus), fakeResponse{err: errors.New("boom")})
	_, terr := h.tools.tsdbStats(ctx(t), h.p, TSDBStatsIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeUpstreamError {
		t.Fatalf("terr = %v, want UPSTREAM_ERROR, not TSDB_STATS_UNAVAILABLE", terr)
	}
}

// TestTSDBStatsTieBreakAndTruncation covers the name tie-break in the stable
// sort (two entries with equal value) and the truncation selection marker.
func TestTSDBStatsTieBreakAndTruncation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTSDBStatus), fakeResponse{body: []byte(`{
		"status": "success",
		"data": {
			"headStats": {"numSeries": 100, "numLabelPairs": 1, "chunkCount": 1, "minTime": 0, "maxTime": 0},
			"seriesCountByMetricName": [
				{"name": "zzz_last", "value": 50},
				{"name": "aaa_first", "value": 50},
				{"name": "middle", "value": 10}
			]
		}
	}`)})

	out, terr := h.tools.tsdbStats(ctx(t), h.p, TSDBStatsIn{Cluster: okCluster, TopN: 2})
	if terr != nil {
		t.Fatalf("tsdbStats: %v", terr)
	}
	if len(out.Top) != 2 || out.Top[0].Name != "aaa_first" || out.Top[1].Name != "zzz_last" {
		t.Fatalf("top = %+v, want the equal-value pair tie-broken alphabetically", out.Top)
	}
	if out.Truncated == nil || out.Truncated.Selection == "" {
		t.Fatalf("truncation = %+v, want a selection marker", out.Truncated)
	}
}

// TestRuntimeInfoInvalidInclude covers runtime_info's own argument
// validation error.
func TestRuntimeInfoInvalidInclude(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.runtimeInfo(ctx(t), h.p,
		RuntimeInfoIn{Cluster: okCluster, Include: []string{"bogus"}})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestRuntimeInfoRuntimeSectionFailure proves a failure isolated to the
// "runtime" section (as opposed to "build" or "flags", which the existing
// TestRuntimeInfo already breaks) is named in partial and does not take the
// other sections down with it.
func TestRuntimeInfoRuntimeSectionFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointRuntimeInfo), fakeResponse{err: errors.New("boom")})
	out, terr := h.tools.runtimeInfo(ctx(t), h.p,
		RuntimeInfoIn{Cluster: okCluster, Include: []string{SectionBuild, SectionRuntime}})
	if terr != nil {
		t.Fatalf("runtimeInfo: %v", terr)
	}
	if out.Build == nil {
		t.Error("the build section, which did not fail, was dropped")
	}
	if out.Runtime != nil {
		t.Error("the failed runtime section still populated Runtime")
	}
	if len(out.Partial) != 1 || out.Partial[0] != SectionRuntime {
		t.Errorf("partial = %v, want exactly [runtime]", out.Partial)
	}
}
