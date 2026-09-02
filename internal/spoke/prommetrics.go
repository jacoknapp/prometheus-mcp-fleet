// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// promMetrics adapts the spoke's collectors to [promclient.Metrics], the
// same way the hub adapts its own to promproxy. promclient does not import
// internal/obs, so the mapping has to live in the composition root.
type promMetrics struct{ m *obs.SpokeMetrics }

// PromRequest counts one upstream round trip by allow-list endpoint and code.
func (a promMetrics) PromRequest(endpoint promapi.Endpoint, code string) {
	a.m.PromRequestsTotal.WithLabelValues(string(endpoint), code).Inc()
}

// PromDuration observes one upstream round trip's latency.
func (a promMetrics) PromDuration(endpoint promapi.Endpoint, d time.Duration) {
	a.m.PromDuration.WithLabelValues(string(endpoint)).Observe(d.Seconds())
}
