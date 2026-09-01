// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// touchHub exercises every hub metric so that Gather reports it.
func touchHub(m *HubMetrics) {
	m.SpokeConnected.WithLabelValues("prod-us-east-1").Set(1)
	m.SpokesConnected.Set(1)
	m.EnrollmentsTotal.WithLabelValues("ok").Inc()
	m.SecurityEventsTotal.WithLabelValues("enrollment_burned").Inc()
	m.StateBytes.Set(12345)
	m.StatePrunedTotal.WithLabelValues("key").Inc()
	m.DiscoveredPeers.Set(3)
	m.ProxyRequestsTotal.WithLabelValues("prod-us-east-1", "query", "200").Inc()
	m.ProxyDuration.WithLabelValues("prod-us-east-1", "query").Observe(0.1)
	m.ProxyInflight.WithLabelValues("prod-us-east-1").Set(2)
	m.ProxyResponseBytes.Observe(4096)
	m.MCPToolCallsTotal.WithLabelValues("prom_query", "ok").Inc()
	m.MCPToolDuration.WithLabelValues("prom_query").Observe(0.2)
	m.AuthnFailuresTotal.WithLabelValues("expired").Inc()
	m.SpokeCertExpiry.WithLabelValues("prod-us-east-1").Set(86400)
	m.CACertExpiry.Set(864000)
	m.CARotationPhase.WithLabelValues("steady").Set(1)
	m.CARotationPhaseStart.Set(1756000000)
	m.CAOutgoingRootSessions.Set(0)
	m.CARotationTransitionsTotal.WithLabelValues("publishing").Inc()
	m.StoreOpDuration.WithLabelValues("put_key", "ok").Observe(0.001)
}

// touchSpoke exercises every spoke metric so that Gather reports it.
func touchSpoke(m *SpokeMetrics) {
	m.TunnelUp.WithLabelValues("hub.example.com:8443").Set(1)
	m.TunnelReconnectsTotal.WithLabelValues("keepalive_timeout").Inc()
	m.PromRequestsTotal.WithLabelValues("query", "200").Inc()
	m.PromDuration.WithLabelValues("query").Observe(0.05)
	m.PromUp.Set(1)
	m.FactsRefreshTotal.WithLabelValues("ok").Inc()
	m.ClientCertExpiry.Set(1209600)
	m.InflightRequests.Set(0)
	m.HubReplicas.WithLabelValues("hub.example.com:8443").Set(3)
	m.TunnelsCovered.WithLabelValues("hub.example.com:8443").Set(3)
}

// gatheredLabels maps each gathered metric family name to its sorted label
// names, which is how the cardinality law is asserted below.
func gatheredLabels(t *testing.T, r *prometheus.Registry) map[string][]string {
	t.Helper()
	families, err := r.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	out := make(map[string][]string, len(families))
	for _, f := range families {
		labels := []string{}
		if len(f.GetMetric()) > 0 {
			for _, lp := range f.GetMetric()[0].GetLabel() {
				labels = append(labels, lp.GetName())
			}
			slices.Sort(labels)
		}
		out[f.GetName()] = labels
	}
	return out
}

func TestNewHubMetricsNamesAndLabels(t *testing.T) {
	t.Parallel()

	r := prometheus.NewRegistry()
	touchHub(NewHubMetrics(r))

	want := map[string][]string{
		"promfleet_hub_spoke_connected":                           {"cluster"},
		"promfleet_hub_spokes_connected":                          {},
		"promfleet_hub_enrollments_total":                         {"result"},
		"promfleet_hub_security_events_total":                     {"event"},
		"promfleet_hub_state_bytes":                               {},
		"promfleet_hub_proxy_requests_total":                      {"cluster", "code", "endpoint"},
		"promfleet_hub_proxy_duration_seconds":                    {"cluster", "endpoint"},
		"promfleet_hub_proxy_inflight":                            {"cluster"},
		"promfleet_hub_proxy_response_bytes":                      {},
		"promfleet_hub_discovered_peers":                          {},
		"promfleet_hub_state_pruned_total":                        {"kind"},
		"promfleet_hub_revocation_refresh_timestamp_seconds":      {},
		"promfleet_hub_mcp_tool_calls_total":                      {"result", "tool"},
		"promfleet_hub_mcp_tool_duration_seconds":                 {"tool"},
		"promfleet_hub_authn_failures_total":                      {"reason"},
		"promfleet_hub_spoke_cert_expiry_seconds":                 {"cluster"},
		"promfleet_hub_ca_cert_expiry_seconds":                    {},
		"promfleet_hub_ca_trust_roots":                            {},
		"promfleet_hub_ca_rotation_phase":                         {"phase"},
		"promfleet_hub_ca_rotation_phase_start_timestamp_seconds": {},
		"promfleet_hub_ca_outgoing_root_sessions":                 {},
		"promfleet_hub_ca_rotation_transitions_total":             {"to"},
		"promfleet_hub_store_op_duration_seconds":                 {"op", "result"},
	}
	if diff := cmp.Diff(want, gatheredLabels(t, r)); diff != "" {
		t.Errorf("hub metric set mismatch (-want +got):\n%s", diff)
	}
}

func TestNewSpokeMetricsNamesAndLabels(t *testing.T) {
	t.Parallel()

	r := prometheus.NewRegistry()
	touchSpoke(NewSpokeMetrics(r))

	want := map[string][]string{
		"promfleet_spoke_tunnel_up":                  {"endpoint"},
		"promfleet_spoke_tunnel_reconnects_total":    {"reason"},
		"promfleet_spoke_prom_requests_total":        {"code", "endpoint"},
		"promfleet_spoke_prom_duration_seconds":      {"endpoint"},
		"promfleet_spoke_prom_up":                    {},
		"promfleet_spoke_facts_refresh_total":        {"result"},
		"promfleet_spoke_client_cert_expiry_seconds": {},
		"promfleet_spoke_inflight_requests":          {},
		"promfleet_spoke_hub_replicas":               {"endpoint"},
		"promfleet_spoke_tunnels_covered":            {"endpoint"},
	}
	if diff := cmp.Diff(want, gatheredLabels(t, r)); diff != "" {
		t.Errorf("spoke metric set mismatch (-want +got):\n%s", diff)
	}
}

func TestNewRegistryBuildInfo(t *testing.T) {
	t.Parallel()

	b := version.Build{Version: "1.2.3", Commit: "abc1234", Date: "2026-08-29", GoVersion: "go1.27.0", Platform: "linux/amd64"}

	tests := []struct{ name, binary, want string }{
		{name: "hub", binary: SubsystemHub, want: "promfleet_hub_build_info"},
		{name: "spoke", binary: SubsystemSpoke, want: "promfleet_spoke_build_info"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := NewRegistry(b, tc.binary)
			got := gatheredLabels(t, r)
			labels, ok := got[tc.want]
			if !ok {
				t.Fatalf("%s is missing; gathered %v", tc.want, got)
			}
			if diff := cmp.Diff([]string{"commit", "goversion", "version"}, labels); diff != "" {
				t.Errorf("build_info labels mismatch (-want +got):\n%s", diff)
			}
			for _, runtimeMetric := range []string{"go_goroutines", "process_start_time_seconds"} {
				if _, ok := got[runtimeMetric]; !ok {
					t.Errorf("%s is missing: the Go and process collectors must be registered", runtimeMetric)
				}
			}
		})
	}
}

func TestNewRegistryRejectsInvalidBinaryName(t *testing.T) {
	t.Parallel()

	for _, binary := range []string{"", "Hub", "hub-1", "9hub", "hub/spoke"} {
		t.Run(binary, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Errorf("NewRegistry(%q) did not panic on an invalid metric name", binary)
				}
			}()
			NewRegistry(version.Build{}, binary)
		})
	}
}

func TestMetricsHandler(t *testing.T) {
	t.Parallel()

	r := NewRegistry(version.Build{Version: "1.2.3", Commit: "abc1234", GoVersion: "go1.27.0"}, SubsystemHub)
	touchHub(NewHubMetrics(r))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	MetricsHandler(r).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`promfleet_hub_build_info{commit="abc1234",goversion="go1.27.0",version="1.2.3"} 1`,
		"promfleet_hub_proxy_requests_total",
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output is missing %q", want)
		}
	}
}

func TestMetricsHandlerServesOpenMetrics(t *testing.T) {
	t.Parallel()

	r := NewRegistry(version.Build{Version: "dev"}, SubsystemSpoke)
	touchSpoke(NewSpokeMetrics(r))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "application/openmetrics-text; version=1.0.0")
	MetricsHandler(r).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "openmetrics") {
		t.Errorf("Content-Type = %q, want an OpenMetrics response", got)
	}
	if !strings.Contains(rec.Body.String(), "# EOF") {
		t.Error("OpenMetrics body is not terminated with # EOF")
	}
}
