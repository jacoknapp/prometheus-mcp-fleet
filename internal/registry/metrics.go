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

// SessionsGauge is an optional extension of [Metrics]. An implementation that
// also satisfies it is additionally given a per-cluster count of live
// sessions, which lets an operator see that a cluster is running more than one
// spoke pod.
//
// It is deliberately not a method on [Metrics] itself: adding it there would
// break every existing implementation (the hub's composition root included),
// where growing the pool from one session to several changes nothing about
// the narrow set of gauges those layers were built to satisfy. The registry
// checks for it with a type assertion and simply does not report it when
// absent.
//
// Suggested mapping: promfleet_hub_spoke_sessions{cluster}. Cardinality is
// bounded by pods per cluster (a handful at most, for a spoke's own
// availability) times the number of clusters — the same "few hundred" fleet
// bound the package doc gives for facts-polling goroutines.
type SessionsGauge interface {
	// SessionsPerCluster records how many live sessions one cluster currently
	// holds.
	SessionsPerCluster(clusterID string, n int)
}

// NopMetrics implements [Metrics] and discards everything. It is the default
// when [Options.Metrics] is nil, so tests and the file-backed dev path need no
// metrics wiring. It does not implement [SessionsGauge]; the registry treats
// that as "not offered" rather than calling a no-op.
type NopMetrics struct{}

// SpokeConnected implements [Metrics].
func (NopMetrics) SpokeConnected(string, bool) {}

// SpokesConnected implements [Metrics].
func (NopMetrics) SpokesConnected(int) {}

// SpokeCertExpiry implements [Metrics].
func (NopMetrics) SpokeCertExpiry(string, time.Time) {}

// IdentityMismatch implements [Metrics].
func (NopMetrics) IdentityMismatch(string) {}
