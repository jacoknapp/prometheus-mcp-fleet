// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

func TestMetricsAdapterRecordsEveryContract(t *testing.T) {
	t.Parallel()

	r := prometheus.NewRegistry()
	raw := obs.NewHubMetrics(r)
	a := newMetricsAdapter(raw)
	if a.m != raw {
		t.Fatal("newMetricsAdapter did not retain the supplied metric set")
	}

	a.SpokeConnected("prod", true)
	if got := metricValue(t, r, `promfleet_hub_spoke_connected{cluster="prod"}`); got != 1 {
		t.Fatalf("connected gauge = %v, want 1", got)
	}
	a.SpokeConnected("prod", false)
	if got := metricValue(t, r, `promfleet_hub_spoke_connected{cluster="prod"}`); got != 0 {
		t.Fatalf("disconnected gauge = %v, want 0", got)
	}
	a.SpokesConnected(3)
	if got := metricValue(t, r, "promfleet_hub_spokes_connected"); got != 3 {
		t.Fatalf("spokes gauge = %v, want 3", got)
	}

	notAfter := time.Now().Add(time.Hour)
	a.SpokeCertExpiry("prod", notAfter)
	assertApprox(t, metricValue(t, r, `promfleet_hub_spoke_cert_expiry_seconds{cluster="prod"}`), time.Hour.Seconds())
	a.IdentityMismatch("prod")
	if got := metricValue(t, r, `promfleet_hub_authn_failures_total{reason="identity-mismatch"}`); got != 1 {
		t.Fatalf("identity mismatch count = %v, want 1", got)
	}

	a.ProxyRequest("prod", promapi.EndpointQuery, "ok")
	if got := metricValue(t, r, `promfleet_hub_proxy_requests_total{cluster="prod",code="ok",endpoint="query"}`); got != 1 {
		t.Fatalf("proxy request count = %v, want 1", got)
	}
	a.ProxyDuration("prod", promapi.EndpointQuery, 250*time.Millisecond)
	a.ProxyInflight("prod", 2)
	if got := metricValue(t, r, `promfleet_hub_proxy_inflight{cluster="prod"}`); got != 2 {
		t.Fatalf("proxy inflight = %v, want 2", got)
	}
	a.ProxyResponseBytes(4096)

	// Successful authentications and cache bookkeeping intentionally have no
	// metric today, but calling the adapter pins that they remain safe no-ops.
	a.AuthSuccess(fleet.ClassAgent)
	a.CacheHit()
	a.CacheMiss()
	a.AuthFailure("invalid")
	if got := metricValue(t, r, `promfleet_hub_authn_failures_total{reason="invalid"}`); got != 1 {
		t.Fatalf("auth failure count = %v, want 1", got)
	}

	a.Enrollment("ok")
	if got := metricValue(t, r, `promfleet_hub_enrollments_total{result="ok"}`); got != 1 {
		t.Fatalf("enrollment count = %v, want 1", got)
	}
	a.SecurityEvent("key_minted")
	if got := metricValue(t, r, `promfleet_hub_security_events_total{event="key_minted"}`); got != 1 {
		t.Fatalf("security event count = %v, want 1", got)
	}
	a.ToolCall("query", "ok")
	if got := metricValue(t, r, `promfleet_hub_mcp_tool_calls_total{result="ok",tool="query"}`); got != 1 {
		t.Fatalf("tool call count = %v, want 1", got)
	}
	a.ToolDuration("query", 500*time.Millisecond)
	a.CACertExpiry(notAfter)
	assertApprox(t, metricValue(t, r, "promfleet_hub_ca_cert_expiry_seconds"), time.Hour.Seconds())
	a.StateBytes(700)
	if got := metricValue(t, r, "promfleet_hub_state_bytes"); got != 700 {
		t.Fatalf("state bytes = %v, want 700", got)
	}
	a.StoreOp("put_key", "ok", 10*time.Millisecond)

	// Histogram calls are behavioral only if they emit an observation. Verify
	// all four adapters contributed exactly one sample.
	for _, name := range []string{
		"promfleet_hub_proxy_duration_seconds",
		"promfleet_hub_proxy_response_bytes",
		"promfleet_hub_mcp_tool_duration_seconds",
		"promfleet_hub_store_op_duration_seconds",
	} {
		assertHistogramCount(t, r, name, 1)
	}
}

func assertApprox(t *testing.T, got, want float64) {
	t.Helper()
	if delta := got - want; delta < -1 || delta > 1 {
		t.Fatalf("metric = %v, want within one second of %v", got, want)
	}
}

func assertHistogramCount(t *testing.T, r *prometheus.Registry, name string, want uint64) {
	t.Helper()
	text := metricsText(t, r)
	var got uint64
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, name+"_count") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed metric line %q", line)
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("parse %s count: %v", name, err)
		}
		got += n
	}
	if got != want {
		t.Fatalf("%s sample count = %d, want %d", name, got, want)
	}
}

func metricValue(t *testing.T, r *prometheus.Registry, series string) float64 {
	t.Helper()
	for _, line := range strings.Split(metricsText(t, r), "\n") {
		if !strings.HasPrefix(line, series+" ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed metric line %q", line)
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("parse %s: %v", series, err)
		}
		return value
	}
	t.Fatalf("metric series %s not found", series)
	return 0
}

func metricsText(t *testing.T, r *prometheus.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	obs.MetricsHandler(r).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("metrics status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}
