// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
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

// TestClassifyUpstreamMatchersBoundary pins the len(m) > 0 boundary that
// decides whether classifyUpstream echoes a "matchers" input: zero match[]
// values must leave it absent, and exactly one must set it.
func TestClassifyUpstreamMatchersBoundary(t *testing.T) {
	t.Parallel()
	env := &render.APIResponse{Status: "error", ErrorType: "bad_data", Error: "bad matcher"}

	none := classifyUpstream(promproxy.Call{ClusterID: "c1", Form: url.Values{}}, env, 400, kindSelector)
	if _, ok := none.Input["matchers"]; ok {
		t.Errorf("Input = %v, want no \"matchers\" key with zero match[] values", none.Input)
	}

	one := classifyUpstream(promproxy.Call{
		ClusterID: "c1", Form: url.Values{"match[]": {`up{job="api"}`}},
	}, env, 400, kindSelector)
	got, ok := one.Input["matchers"]
	if !ok {
		t.Fatalf("Input = %v, want a \"matchers\" key with one match[] value", one.Input)
	}
	if diff := cmp.Diff([]string{`up{job="api"}`}, got); diff != "" {
		t.Errorf("matchers (-want +got):\n%s", diff)
	}
}

// TestEffectiveTimeoutZeroBoundary pins the want <= 0 boundary: exactly zero
// must fall back to the default, while any positive duration (even a
// nanosecond) must pass through unchanged.
func TestEffectiveTimeoutZeroBoundary(t *testing.T) {
	t.Parallel()
	const def = 30 * time.Second

	if got := effectiveTimeout(0, def); got != def {
		t.Errorf("effectiveTimeout(0, ...) = %v, want the default %v", got, def)
	}
	if got := effectiveTimeout(time.Nanosecond, def); got != time.Nanosecond {
		t.Errorf("effectiveTimeout(1ns, ...) = %v, want 1ns passed through", got)
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
