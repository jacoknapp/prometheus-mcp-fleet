// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"bytes"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Results are retained until the slowest cluster completes. Verify the worker
// discards excess samples before it returns, including their backing storage,
// while preserving ranking, shared labels, warnings and the upstream total.
func TestFanoutWorkerRetainsOnlySelectedSeries(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []promapi.Endpoint{promapi.EndpointQuery, promapi.EndpointQueryRange} {
		t.Run(string(endpoint), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			start := testNow.Add(-2 * time.Minute)
			body := syntheticVector(t, 100)
			if endpoint == promapi.EndpointQueryRange {
				body = syntheticMatrix(t, 100, 3, start, time.Minute)
			}
			body = bytes.Replace(body, []byte(`"status":"success"`),
				[]byte(`"status":"success","warnings":["partial upstream"],"infos":["info"]`), 1)
			h.prom.set(string(endpoint), fakeResponse{body: body})
			r := h.tools.queryOne(ctx(t), h.p, fleet.Cluster{ID: okCluster}, endpoint,
				url.Values{"query": {"up"}}, time.Second, fanoutEncoding{
					maxSeries: 2, start: start, end: testNow, step: time.Minute,
				})
			if r.err != nil {
				t.Fatal(r.err)
			}
			if endpoint == promapi.EndpointQuery {
				enc := r.instant
				if len(enc.Rows) != 2 || cap(enc.Rows) != 2 || enc.Total != 100 {
					t.Fatalf("retained rows len/cap/total = %d/%d/%d", len(enc.Rows), cap(enc.Rows), enc.Total)
				}
				if enc.SharedLabels["job"] != "synthetic" || len(enc.Warnings) != 2 {
					t.Fatalf("lost shared labels or upstream notes: %+v", enc)
				}
				if *enc.Rows[0][2].(*float64) != 99 || *enc.Rows[1][2].(*float64) != 98 {
					t.Fatalf("worker lost highest-value selection: %v", enc.Rows)
				}
			} else {
				enc := r.rangeResult
				if len(enc.Series) != 2 || cap(enc.Series) != 2 || enc.SeriesTotal != 100 {
					t.Fatalf("retained series len/cap/total = %d/%d/%d", len(enc.Series), cap(enc.Series), enc.SeriesTotal)
				}
				if enc.SharedLabels["job"] != "synthetic" || len(enc.Warnings) != 2 {
					t.Fatalf("lost shared labels or upstream notes: %+v", enc)
				}
				for i, s := range enc.Series {
					if len(s.Values) != 3 || *s.Max != float64(99-i) || *s.Values[2] != float64(99-i) {
						t.Fatalf("worker lost range grid or maximum selection: %+v", s)
					}
				}
			}
		})
	}
}

func TestFanoutTokenTruncationRetainsOriginalTotal(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{FanoutInstant, FanoutRange} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, func(o *Options) { o.TokenCeiling = 1 })
			h.prom.set(string(promapi.EndpointQuery), fakeResponse{body: syntheticVector(t, 20)})
			h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
				body: syntheticMatrix(t, 20, 3, testNow.Add(-2*time.Minute), time.Minute),
			})
			out, terr := h.tools.fanoutQuery(ctx(t), h.p, FanoutQueryIn{
				Query: "up", Clusters: connectedClusters, Mode: mode, MaxSeriesPerCluster: 2,
				Start: "now-2m", Step: "1m",
			})
			if terr != nil {
				t.Fatal(terr)
			}
			if out.Total != 40 || out.Truncated == nil || out.Truncated.Total != 40 ||
				out.Truncated.Reason != render.ReasonTokenCeiling || out.Truncated.Returned != 0 {
				t.Fatalf("truncation lost original total: total=%d truncated=%+v", out.Total, out.Truncated)
			}
		})
	}
}

func TestNativeHistogramRequiresRawOrFloatExpression(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{FanoutInstant, FanoutRange} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			data := `{"resultType":"vector","result":[{"metric":{"__name__":"latency"},"histogram":[1,{"count":"2","sum":"3","buckets":[]}]}]}`
			endpoint := promapi.EndpointQuery
			if mode == FanoutRange {
				endpoint = promapi.EndpointQueryRange
				data = `{"resultType":"matrix","result":[{"metric":{"__name__":"latency"},"values":[[1,"4"]],"histograms":[[2,{"count":"2","sum":"3","buckets":[]}]]}]}`
			}
			h.prom.set(string(endpoint), fakeResponse{body: []byte(`{"status":"success","data":` + data + `}`)})
			for _, format := range []string{"compact", "json"} {
				var terr *ToolError
				var raw any
				if mode == FanoutInstant {
					out, err := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "latency", Format: format})
					terr = err
					if out != nil {
						raw = out.Raw
					}
				} else {
					out, err := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{Cluster: okCluster, Query: "latency", Format: format})
					terr = err
					if out != nil {
						raw = out.Raw
					}
				}
				if format == "compact" {
					if terr == nil || terr.Code != CodeInvalidArgument || terr.Hint == "" || *terr.Retryable {
						t.Fatalf("compact silently accepted histograms: %v", terr)
					}
				} else {
					if terr != nil {
						t.Fatal(terr)
					}
					if got, ok := raw.(json.RawMessage); !ok || string(got) != data {
						t.Fatalf("raw output lost histogram samples: %s", got)
					}
				}
			}
		})
	}
}
