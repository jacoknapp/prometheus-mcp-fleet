// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
)

// TestPromMetricsWriteTheSpokeCollectors pins the adapter onto the series the
// chart's PrometheusMCPSpokePromErrorRatioHigh alert selects on:
// promfleet_spoke_prom_requests_total{endpoint,code} and the matching
// duration histogram. Until this adapter existed those collectors were
// registered and never written, so the alert could not fire.
func TestPromMetricsWriteTheSpokeCollectors(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := obs.NewSpokeMetrics(reg)
	var a promclient.Metrics = promMetrics{m: m}

	a.PromRequest(promapi.EndpointQuery, "200")
	a.PromRequest(promapi.EndpointQuery, "503")
	a.PromRequest(promclient.EndpointHealthy, promclient.CodeTimeout)
	a.PromDuration(promapi.EndpointQuery, 250*time.Millisecond)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	counters := map[string]float64{}
	histograms := map[string]uint64{}
	for _, f := range families {
		for _, mt := range f.GetMetric() {
			var sb strings.Builder
			for _, lp := range mt.GetLabel() {
				sb.WriteString(lp.GetName() + "=" + lp.GetValue() + ",")
			}
			key := sb.String()
			switch f.GetName() {
			case "promfleet_spoke_prom_requests_total":
				counters[key] = mt.GetCounter().GetValue()
			case "promfleet_spoke_prom_duration_seconds":
				histograms[key] = mt.GetHistogram().GetSampleCount()
			}
		}
	}

	for key, want := range map[string]float64{
		"code=200,endpoint=query,":       1,
		"code=503,endpoint=query,":       1,
		"code=timeout,endpoint=healthy,": 1,
	} {
		if got := counters[key]; got != want {
			t.Errorf("prom_requests_total{%s} = %v, want %v (all: %v)", key, got, want, counters)
		}
	}
	if got := histograms["endpoint=query,"]; got != 1 {
		t.Errorf("prom_duration_seconds{endpoint=query} count = %d, want 1 (all: %v)", got, histograms)
	}
	if len(histograms) != 1 {
		t.Errorf("duration series = %v, want only the timed query", histograms)
	}
}
