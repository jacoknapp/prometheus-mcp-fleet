// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// recordingMetrics captures every record so a test can assert on the exact
// label values, which is the whole point: the chart's alert selects on them.
type recordingMetrics struct {
	mu        sync.Mutex
	requests  []string // "endpoint code"
	durations map[promapi.Endpoint]int
}

func (m *recordingMetrics) PromRequest(endpoint promapi.Endpoint, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, string(endpoint)+" "+code)
}

func (m *recordingMetrics) PromDuration(endpoint promapi.Endpoint, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.durations == nil {
		m.durations = map[promapi.Endpoint]int{}
	}
	m.durations[endpoint]++
	if d < 0 {
		panic("negative duration observed")
	}
}

func (m *recordingMetrics) snapshot() ([]string, map[promapi.Endpoint]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.requests...), m.durations
}

func withMetrics(m promclient.Metrics) func(*promclient.Config) {
	return func(c *promclient.Config) { c.Metrics = m }
}

// TestMetricsRecordEveryRoundTrip pins the contract the spoke chart alerts
// on: one request record per upstream call, labelled by the allow-list
// endpoint name and the decimal HTTP status, plus one duration per call.
// Before this the collectors existed, the alert selected on them, and
// nothing ever wrote them.
func TestMetricsRecordEveryRoundTrip(t *testing.T) {
	t.Parallel()

	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
		FailEndpoints: map[string]int{"series": http.StatusServiceUnavailable},
	})
	rec := &recordingMetrics{}
	c := newClient(t, fake.URL, withMetrics(rec))

	// The tunnel path: a 2xx and a 5xx, both passed through as answers.
	for path, form := range map[string]string{"/api/v1/query": "query=up", "/api/v1/series": "match[]=up"} {
		resp, err := c.Do(t.Context(), &tunnel.Request{Method: "POST", Path: path, Form: []byte(form)})
		if err != nil {
			t.Fatalf("Do(%s): %v", path, err)
		}
		_, _, _ = drain(t, resp)
	}
	// The JSON helper path.
	if _, err := c.LabelValues(t.Context(), "job"); err != nil {
		t.Fatalf("LabelValues: %v", err)
	}
	// The probe path, which is not an allow-list call and so needs its own
	// label rather than vanishing into the nearest real endpoint.
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	requests, durations := rec.snapshot()
	want := []string{"query 200", "series 503", "label_values 200", "healthy 200"}
	if diff := cmp.Diff(want, requests, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("request records (-want +got):\n%s", diff)
	}
	wantDur := map[promapi.Endpoint]int{
		promapi.EndpointQuery: 1, promapi.EndpointSeries: 1,
		promapi.EndpointLabelValues: 1, promclient.EndpointHealthy: 1,
	}
	if diff := cmp.Diff(wantDur, durations); diff != "" {
		t.Errorf("duration records (-want +got):\n%s", diff)
	}
}

// TestMetricsPingFallbackCountsBothProbes: a Ping that falls through to
// buildinfo made two upstream calls, and an operator watching the counter
// should see both, under the endpoint each really hit.
func TestMetricsPingFallbackCountsBothProbes(t *testing.T) {
	t.Parallel()

	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
		FailEndpoints: map[string]int{"/-/healthy": http.StatusNotFound},
	})
	rec := &recordingMetrics{}
	c := newClient(t, fake.URL, withMetrics(rec))
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	requests, _ := rec.snapshot()
	if diff := cmp.Diff([]string{"healthy 404", "build_info 200"}, requests); diff != "" {
		t.Errorf("request records (-want +got):\n%s", diff)
	}
}

// TestMetricsTransportFailuresUseClosedCodes covers the calls that never got
// a status line. They must still be counted -- a Prometheus that stops
// answering is the case the error-ratio alert exists for -- and under a
// fixed code, never anything derived from the error text.
func TestMetricsTransportFailuresUseClosedCodes(t *testing.T) {
	t.Parallel()

	t.Run("deadline", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{Latency: 2 * time.Second})
		rec := &recordingMetrics{}
		c := newClient(t, fake.URL, withMetrics(rec))
		ctx, cancel := context.WithTimeout(t.Context(), promclient.HopMargin+150*time.Millisecond)
		defer cancel()
		if _, err := c.Do(ctx, &tunnel.Request{Method: "POST", Path: "/api/v1/query", Form: []byte("query=up")}); !errors.Is(err, promclient.ErrUpstream) {
			t.Fatalf("Do() error = %v, want ErrUpstream", err)
		}
		requests, durations := rec.snapshot()
		if diff := cmp.Diff([]string{"query " + promclient.CodeTimeout}, requests); diff != "" {
			t.Errorf("request records (-want +got):\n%s", diff)
		}
		if durations[promapi.EndpointQuery] != 1 {
			t.Errorf("a timed-out call was not timed: %v", durations)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		base := fake.URL
		fake.Close()
		rec := &recordingMetrics{}
		c := newClient(t, base, withMetrics(rec))
		if err := c.Ping(t.Context()); !errors.Is(err, promclient.ErrUpstream) {
			t.Fatalf("Ping() error = %v, want ErrUpstream", err)
		}
		requests, _ := rec.snapshot()
		want := []string{"healthy " + promclient.CodeError, "build_info " + promclient.CodeError}
		if diff := cmp.Diff(want, requests); diff != "" {
			t.Errorf("request records (-want +got):\n%s", diff)
		}
	})
}

// TestMetricsDefaultToNop: a client built without Metrics must still work,
// which is every test in this package and every non-spoke caller.
func TestMetricsDefaultToNop(t *testing.T) {
	t.Parallel()

	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.Metrics = nil })
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping without metrics: %v", err)
	}
	// NopMetrics is also usable explicitly, and discards.
	var m promclient.Metrics = promclient.NopMetrics{}
	m.PromRequest(promapi.EndpointQuery, "200")
	m.PromDuration(promapi.EndpointQuery, time.Second)
}
