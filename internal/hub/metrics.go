// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// metricsAdapter satisfies the small Metrics interfaces that the registry,
// proxy, authentication and API layers each declare for themselves.
//
// Those layers deliberately do not import internal/obs. Declaring the interface
// at the point of use keeps them testable without a Prometheus registry, and
// keeps the observability surface from becoming a dependency that every layer
// has to know about. This type is where the abstraction is paid for — one place,
// in the composition root, which is exactly where a translation like this
// belongs.
type metricsAdapter struct{ m *obs.HubMetrics }

// newMetricsAdapter wraps the hub metric set.
func newMetricsAdapter(m *obs.HubMetrics) *metricsAdapter { return &metricsAdapter{m: m} }

// --- registry.Metrics ---

// SpokeConnected records whether a cluster currently has a live tunnel.
func (a *metricsAdapter) SpokeConnected(clusterID string, connected bool) {
	v := 0.0
	if connected {
		v = 1
	}
	a.m.SpokeConnected.WithLabelValues(clusterID).Set(v)
}

// SpokesConnected records the total number of connected clusters.
func (a *metricsAdapter) SpokesConnected(n int) { a.m.SpokesConnected.Set(float64(n)) }

// SpokeCertExpiry records seconds remaining on a spoke's certificate.
func (a *metricsAdapter) SpokeCertExpiry(clusterID string, notAfter time.Time) {
	a.m.SpokeCertExpiry.WithLabelValues(clusterID).Set(time.Until(notAfter).Seconds())
}

// IdentityMismatch counts a spoke reporting a cluster ID that disagrees with
// its certificate. The certificate always wins; this counter exists so the
// disagreement is visible rather than only logged.
func (a *metricsAdapter) IdentityMismatch(clusterID string) {
	a.m.AuthnFailuresTotal.WithLabelValues("identity-mismatch").Inc()
	_ = clusterID // deliberately not a label: see ADR-0008 on cardinality
}

// --- promproxy.Metrics ---

// ProxyRequest counts one proxied upstream call.
func (a *metricsAdapter) ProxyRequest(clusterID string, endpoint promapi.Endpoint, code string) {
	a.m.ProxyRequestsTotal.WithLabelValues(clusterID, string(endpoint), code).Inc()
}

// ProxyDuration records the latency of one proxied call.
func (a *metricsAdapter) ProxyDuration(clusterID string, endpoint promapi.Endpoint, d time.Duration) {
	a.m.ProxyDuration.WithLabelValues(clusterID, string(endpoint)).Observe(d.Seconds())
}

// ProxyInflight adjusts the in-flight gauge for a cluster.
func (a *metricsAdapter) ProxyInflight(clusterID string, delta int) {
	a.m.ProxyInflight.WithLabelValues(clusterID).Add(float64(delta))
}

// ProxyResponseBytes records the size of one upstream response.
func (a *metricsAdapter) ProxyResponseBytes(n int64) {
	a.m.ProxyResponseBytes.Observe(float64(n))
}

// --- authn.Metrics ---

// AuthSuccess counts a successful authentication by credential class.
func (a *metricsAdapter) AuthSuccess(fleet.KeyClass) {}

// AuthFailure counts a failed authentication by reason. The reason must come
// from a closed set; see ADR-0008.
func (a *metricsAdapter) AuthFailure(reason string) {
	a.m.AuthnFailuresTotal.WithLabelValues(reason).Inc()
}

// CacheHit counts a verified-key cache hit.
func (a *metricsAdapter) CacheHit() {}

// CacheMiss counts a verified-key cache miss.
func (a *metricsAdapter) CacheMiss() {}

// --- hubapi.Metrics ---

// Enrollment counts an enrollment attempt by result.
func (a *metricsAdapter) Enrollment(result string) {
	a.m.EnrollmentsTotal.WithLabelValues(result).Inc()
}

// SecurityEvent counts one credential mint, revocation or burn. The event name
// comes from a closed set defined in internal/hubapi.
func (a *metricsAdapter) SecurityEvent(event string) {
	a.m.SecurityEventsTotal.WithLabelValues(event).Inc()
}

// ToolCall counts one MCP tool call by result.
func (a *metricsAdapter) ToolCall(tool, result string) {
	a.m.MCPToolCallsTotal.WithLabelValues(tool, result).Inc()
}

// ToolDuration records the latency of one MCP tool call.
func (a *metricsAdapter) ToolDuration(tool string, d time.Duration) {
	a.m.MCPToolDuration.WithLabelValues(tool).Observe(d.Seconds())
}

// CACertExpiry records seconds remaining on the CA certificate.
func (a *metricsAdapter) CACertExpiry(notAfter time.Time) {
	a.m.CACertExpiry.Set(time.Until(notAfter).Seconds())
}

// StateBytes records the encoded size of the credential state document.
func (a *metricsAdapter) StateBytes(n int) { a.m.StateBytes.Set(float64(n)) }

// StoreOp records the latency and outcome of one credential-store operation.
func (a *metricsAdapter) StoreOp(op, result string, d time.Duration) {
	a.m.StoreOpDuration.WithLabelValues(op, result).Observe(d.Seconds())
}
