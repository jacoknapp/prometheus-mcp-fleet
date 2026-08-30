// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// Result codes reported to [Metrics.ProxyRequest]. This is a closed enum: the
// `code` metric label must never carry PromQL, a matcher, a label value or a
// request id, and an open enum is how that rule gets broken.
const (
	// CodeOK is a 2xx upstream response.
	CodeOK = "2xx"
	// CodeClientError is a 4xx upstream response, typically a PromQL error.
	CodeClientError = "4xx"
	// CodeServerError is a 5xx upstream response.
	CodeServerError = "5xx"
	// CodeForbidden is a scope denial; the call never left the hub.
	CodeForbidden = "forbidden"
	// CodeInvalid is a parameter or endpoint validation failure.
	CodeInvalid = "invalid"
	// CodeBusy is a budget refusal.
	CodeBusy = "busy"
	// CodeUnavailable is a cluster with no live tunnel.
	CodeUnavailable = "unavailable"
	// CodeTimeout is a deadline or cancellation.
	CodeTimeout = "timeout"
	// CodeTooLarge is a response truncated at the byte cap.
	CodeTooLarge = "too_large"
	// CodeUpstream is any other tunnel or upstream failure.
	CodeUpstream = "upstream"
)

// Metrics is the subset of instrumentation the proxy reports. It is declared
// here rather than imported so this package does not depend on internal/obs;
// the hub's composition root adapts its Prometheus collectors to it.
//
// Implementations must be safe for concurrent use and must not block.
//
// The mapping to the collectors named in the spec is:
//
//	ProxyRequest       -> promfleet_hub_proxy_requests_total{cluster,endpoint,code}
//	ProxyDuration      -> promfleet_hub_proxy_duration_seconds{cluster,endpoint}
//	ProxyInflight      -> promfleet_hub_proxy_inflight{cluster}
//	ProxyResponseBytes -> promfleet_hub_proxy_response_bytes
type Metrics interface {
	// ProxyRequest counts one completed call. code is one of the Code
	// constants in this package and never carries caller data.
	ProxyRequest(clusterID string, endpoint promapi.Endpoint, code string)
	// ProxyDuration observes the wall time of one call, including time spent
	// waiting on a budget.
	ProxyDuration(clusterID string, endpoint promapi.Endpoint, d time.Duration)
	// ProxyInflight adjusts the per-cluster in-flight gauge by delta, which is
	// +1 on admission and -1 on completion.
	ProxyInflight(clusterID string, delta int)
	// ProxyResponseBytes observes the decompressed size of one response body.
	ProxyResponseBytes(n int64)
}

// NopMetrics implements [Metrics] and discards everything. It is the default
// when [Options.Metrics] is nil.
type NopMetrics struct{}

// ProxyRequest implements [Metrics].
func (NopMetrics) ProxyRequest(string, promapi.Endpoint, string) {}

// ProxyDuration implements [Metrics].
func (NopMetrics) ProxyDuration(string, promapi.Endpoint, time.Duration) {}

// ProxyInflight implements [Metrics].
func (NopMetrics) ProxyInflight(string, int) {}

// ProxyResponseBytes implements [Metrics].
func (NopMetrics) ProxyResponseBytes(int64) {}
