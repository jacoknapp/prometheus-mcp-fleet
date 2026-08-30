// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import "time"

// Metrics is the subset of instrumentation the registry reports. It is
// declared here rather than imported so that this package does not depend on
// internal/obs; the hub's composition root adapts its Prometheus collectors to
// it.
//
// Implementations must be safe for concurrent use and must not block: they are
// called while no lock is held, but on the session attach and detach paths.
//
// The mapping to the collectors named in the spec is:
//
//	SpokeConnected   -> promfleet_hub_spoke_connected{cluster}
//	SpokesConnected  -> promfleet_hub_spokes_connected
//	SpokeCertExpiry  -> promfleet_hub_spoke_cert_expiry_seconds{cluster}
//	IdentityMismatch -> promfleet_hub_authn_failures_total{reason="identity-mismatch"}
type Metrics interface {
	// SpokeConnected records whether one cluster currently holds a tunnel.
	SpokeConnected(clusterID string, connected bool)
	// SpokesConnected records how many clusters currently hold a tunnel.
	SpokesConnected(n int)
	// SpokeCertExpiry records the expiry of a spoke's client certificate.
	SpokeCertExpiry(clusterID string, notAfter time.Time)
	// IdentityMismatch counts sessions whose self-reported cluster ID
	// disagreed with the certificate-derived one. clusterID is always the
	// certificate's value, never the reported one, so this label cannot be
	// steered by a spoke.
	IdentityMismatch(clusterID string)
}

// NopMetrics implements [Metrics] and discards everything. It is the default
// when [Options.Metrics] is nil, so tests and the file-backed dev path need no
// metrics wiring.
type NopMetrics struct{}

// SpokeConnected implements [Metrics].
func (NopMetrics) SpokeConnected(string, bool) {}

// SpokesConnected implements [Metrics].
func (NopMetrics) SpokesConnected(int) {}

// SpokeCertExpiry implements [Metrics].
func (NopMetrics) SpokeCertExpiry(string, time.Time) {}

// IdentityMismatch implements [Metrics].
func (NopMetrics) IdentityMismatch(string) {}
