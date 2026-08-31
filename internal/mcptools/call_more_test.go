// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// TestClassifyUpstreamEmptyMessageAndPlainDefault covers two edges of
// classifyUpstream at once: an error envelope that carries no Error text at
// all (Prometheus does this for some 5xx responses), which forces the
// synthesised "reported an error (HTTP n)" message, and an unrecognised
// errorType on a kindPlain call (one with no user-authored expression or
// selector), which must fall through to CodeInvalidArgument rather than the
// PromQL- or matcher-flavoured errors kindQuery and kindSelector produce.
func TestClassifyUpstreamEmptyMessageAndPlainDefault(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointTargets), fakeResponse{
		status: 503,
		body:   []byte(`{"status":"error"}`),
	})
	_, terr := h.tools.targets(ctx(t), h.p, TargetsIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
	if terr.Message == "" {
		t.Error("no message was synthesised for an upstream error with no error text")
	}
}

// TestSeriesJSONPassthroughUnderCeiling covers the format "json" success path
// on series: a payload small enough to stay under the token ceiling is passed
// through verbatim as raw JSON rather than being re-encoded columnar.
func TestSeriesJSONPassthroughUnderCeiling(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}, Format: "json"})
	if terr != nil {
		t.Fatalf("series: %v", terr)
	}
	if out.Raw == nil {
		t.Fatal("format json returned no raw payload")
	}
	if out.Columns != nil || out.Rows != nil {
		t.Error("format json also populated the columnar fields")
	}
	if out.Truncated != nil {
		t.Errorf("a small payload was truncated: %+v", out.Truncated)
	}
}
