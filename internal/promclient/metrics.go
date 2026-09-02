// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient

import (
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// Result codes reported to [Metrics.PromRequest] when no HTTP status was
// received. A call that did get an answer reports the status as its decimal
// form ("200", "422", "503"), because the spoke's error-ratio alert selects
// on code=~"5.." and because operators already read status codes; an
// enum would only make them translate. The label stays bounded either way:
// Go's HTTP client refuses any status outside 100-999, and this list is the
// whole of the rest.
const (
	// CodeTimeout is a call the spoke gave up on: the context expired or was
	// cancelled before the upstream answered, or the transport reported a
	// timeout of its own.
	CodeTimeout = "timeout"
	// CodeError is any other transport failure -- dial refused, TLS failure,
	// a malformed status line -- where no status code exists to report.
	CodeError = "error"
)

// EndpointHealthy is the label under which the readiness probe of
// Prometheus's /-/healthy is reported. It is not a promapi endpoint (the
// probe is the one request that bypasses the allow-list, because that path
// carries no query) but it is a distinct upstream call and the metric would
// otherwise hide it inside the nearest real endpoint.
const EndpointHealthy promapi.Endpoint = "healthy"

// Metrics is the instrumentation one client reports. It is declared here
// rather than imported so this package does not depend on internal/obs; the
// spoke's composition root adapts its Prometheus collectors to it.
//
// Implementations must be safe for concurrent use and must not block.
//
// The mapping to the collectors named in the spec is:
//
//	PromRequest  -> promfleet_spoke_prom_requests_total{endpoint,code}
//	PromDuration -> promfleet_spoke_prom_duration_seconds{endpoint}
//
// Both are recorded once per upstream round trip, at the moment the response
// headers arrive or the transport gives up. A body that later fails to
// stream (the byte cap, a cancelled tunnel) is not a second event: the
// status it was counted under is still what Prometheus said, and the byte
// cap has its own signal in the tunnel error the hub receives.
type Metrics interface {
	// PromRequest counts one round trip. endpoint is the allow-list name of
	// the call ("query", "series"), never a URL; code is a decimal HTTP
	// status or one of the Code constants in this package.
	PromRequest(endpoint promapi.Endpoint, code string)
	// PromDuration observes the wall time from the request leaving until
	// the response headers arrived, or the transport failed.
	PromDuration(endpoint promapi.Endpoint, d time.Duration)
}

// NopMetrics implements [Metrics] and discards everything. It is the default
// when [Config.Metrics] is nil.
type NopMetrics struct{}

// PromRequest implements [Metrics].
func (NopMetrics) PromRequest(promapi.Endpoint, string) {}

// PromDuration implements [Metrics].
func (NopMetrics) PromDuration(promapi.Endpoint, time.Duration) {}
