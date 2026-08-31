// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// TestSummarizeStaleBoundary pins the age > StaleFactsAfter boundary: a
// cluster whose facts are exactly StaleFactsAfter old must not be reported
// stale, only one strictly older than that.
func TestSummarizeStaleBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	atBoundary := summarize(fleet.Cluster{ID: "c1", LastSeen: now.Add(-StaleFactsAfter)}, now)
	if atBoundary.Stale {
		t.Errorf("Stale = true at age exactly StaleFactsAfter (%v), want false", StaleFactsAfter)
	}

	pastBoundary := summarize(fleet.Cluster{ID: "c1", LastSeen: now.Add(-StaleFactsAfter - time.Nanosecond)}, now)
	if !pastBoundary.Stale {
		t.Errorf("Stale = false at age StaleFactsAfter+1ns, want true")
	}
}

// TestSummarizeActiveSeriesBoundary pins the ActiveSeries > 0 boundary:
// summarize must leave ActiveSeries at its zero value when the upstream
// reported none, and copy it through starting at exactly 1.
func TestSummarizeActiveSeriesBoundary(t *testing.T) {
	t.Parallel()
	now := time.Now()

	zero := summarize(fleet.Cluster{ID: "c1", Prometheus: fleet.PrometheusInfo{ActiveSeries: 0}}, now)
	if zero.ActiveSeries != 0 {
		t.Errorf("ActiveSeries = %d, want 0 to stay unset when upstream reported 0", zero.ActiveSeries)
	}

	one := summarize(fleet.Cluster{ID: "c1", Prometheus: fleet.PrometheusInfo{ActiveSeries: 1}}, now)
	if one.ActiveSeries != 1 {
		t.Errorf("ActiveSeries = %d, want 1 copied through", one.ActiveSeries)
	}
}
