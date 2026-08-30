// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import "github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"

// Metrics is the narrow counter surface this package needs. It is declared
// here rather than imported from internal/obs so that authentication does not
// depend on the observability stack and so that tests can assert on counts
// without a Prometheus registry.
//
// Implementations must be safe for concurrent use and must never block: every
// method is called on the request hot path.
//
// Cardinality: reason is one of the Reason constants in this package and class
// is one of the three [fleet.KeyClass] values. Neither a key identifier nor a
// source address may ever be used as a label value.
type Metrics interface {
	// AuthSuccess records one successful verification of the given class.
	AuthSuccess(class fleet.KeyClass)
	// AuthFailure records one failed verification with a closed-enum reason.
	AuthFailure(reason string)
	// CacheHit records a verification served from the verified-token cache.
	CacheHit()
	// CacheMiss records a verification that had to consult the store.
	CacheMiss()
}

// NopMetrics is a [Metrics] that records nothing. It is the default when
// [Options.Metrics] is nil, so a caller that does not care about metrics does
// not have to write four empty methods.
type NopMetrics struct{}

// AuthSuccess implements [Metrics] and does nothing.
func (NopMetrics) AuthSuccess(fleet.KeyClass) {}

// AuthFailure implements [Metrics] and does nothing.
func (NopMetrics) AuthFailure(string) {}

// CacheHit implements [Metrics] and does nothing.
func (NopMetrics) CacheHit() {}

// CacheMiss implements [Metrics] and does nothing.
func (NopMetrics) CacheMiss() {}

// Compile-time proof that the zero value satisfies the interface.
var _ Metrics = NopMetrics{}
