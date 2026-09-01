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

// SessionsPerCluster records how many live tunnels one cluster holds. It
// satisfies registry.SessionsGauge, which the registry type-asserts: a cluster
// running several spoke pods is invisible without it, because SpokeConnected is
// a boolean and SpokesConnected counts clusters rather than sessions.
func (a *metricsAdapter) SessionsPerCluster(clusterID string, n int) {
	a.m.SpokeSessions.WithLabelValues(clusterID).Set(float64(n))
}

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

// StatePruned records one prune pass. Zero counts are still added so the
// series exists from the first pass, which is what makes "has it ever run"
// answerable.
func (a *metricsAdapter) StatePruned(keys, revokedCerts int) {
	a.m.StatePrunedTotal.WithLabelValues("key").Add(float64(keys))
	a.m.StatePrunedTotal.WithLabelValues("revoked_cert").Add(float64(revokedCerts))
}

// DiscoveredPeers records what peer discovery resolved.
func (a *metricsAdapter) DiscoveredPeers(n int) { a.m.DiscoveredPeers.Set(float64(n)) }

// RevocationRefreshed records a successful revoked-serial cache refresh. The
// alert on this series is what turns "revocations silently stopped landing on
// this replica" from a forensic discovery into a page.
func (a *metricsAdapter) RevocationRefreshed(at time.Time) {
	a.m.RevocationRefreshTimestamp.Set(float64(at.Unix()))
}

// CATrustRoots records how many roots the hub accepts on a spoke chain. Two
// means a rotation is in progress; see docs/adr/0015-ca-rotation.md.
func (a *metricsAdapter) CATrustRoots(n int) { a.m.CATrustRoots.Set(float64(n)) }

// CARotationPhase records which phase of a CA rotation the fleet is in and
// when it entered it.
//
// It is a set of gauges, one per phase with exactly one of them at 1, rather
// than a single number: a phase is a name, and encoding names as 0, 1, 2 makes
// every dashboard and every alert carry a copy of the mapping. The start time
// is a separate gauge because "how long has it been stuck there" is the
// question an operator actually asks, and a timestamp answers it without
// needing the series to have been scraped when the phase changed.
func (a *metricsAdapter) CARotationPhase(phase string, since time.Time) {
	// "unknown" is in the enum for the frozen state: a recorded phase this
	// build does not recognise. The stalled alert excludes only "steady", so
	// a fleet frozen on an unknown phase pages the same way a stuck
	// rotation does.
	names := make([]string, 0, len(caPhases)+1)
	for _, p := range caPhases {
		names = append(names, string(p))
	}
	names = append(names, "unknown")
	for _, name := range names {
		v := 0.0
		if name == phase {
			v = 1
		}
		a.m.CARotationPhase.WithLabelValues(name).Set(v)
	}
	if since.IsZero() {
		a.m.CARotationPhaseStart.Set(0)
		return
	}
	a.m.CARotationPhaseStart.Set(float64(since.Unix()))
}

// CAOutgoingRootSessions records how many live sessions on this replica still
// present a certificate issued by the root a rotation is retiring.
//
// Sum it across replicas: no single replica sees the whole fleet, because a
// tunnel terminates on exactly one of them. While this is above zero anywhere,
// the outgoing root cannot be dropped without disconnecting somebody.
func (a *metricsAdapter) CAOutgoingRootSessions(n int) {
	a.m.CAOutgoingRootSessions.Set(float64(n))
}

// CARotationTransition counts one advance of the rotation state machine. It is
// a counter rather than a log line because the interesting question -- did a
// rotation happen at all in the last year -- is not answerable from logs that
// have rolled over.
func (a *metricsAdapter) CARotationTransition(to string) {
	a.m.CARotationTransitionsTotal.WithLabelValues(to).Inc()
}

// StateBytes records the encoded size of the credential state document.
func (a *metricsAdapter) StateBytes(n int) { a.m.StateBytes.Set(float64(n)) }

// StoreOp records the latency and outcome of one credential-store operation.
func (a *metricsAdapter) StoreOp(op, result string, d time.Duration) {
	a.m.StoreOpDuration.WithLabelValues(op, result).Observe(d.Seconds())
}
