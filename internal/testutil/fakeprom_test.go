// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package testutil_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
)

// get issues a plain GET against the fake and returns the status and body.
func get(t *testing.T, f *testutil.FakePrometheus, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Keep wire-size and slow-body assertions deterministic. Tests that need
	// gzip opt in explicitly rather than inheriting net/http's transparent gzip.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

// TestFakeServesEveryEndpointClusterfactsNeeds is the contract test between the
// fake and its main consumer. A facts refresh that silently 404s would look
// like a tolerated source failure rather than a broken fixture, so the set is
// asserted explicitly.
func TestFakeServesEveryEndpointClusterfactsNeeds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		// want is a JSON pointer-ish probe: the decoded body must contain this
		// key at the top level of "data", or be the named type.
		check func(*testing.T, []byte)
	}{
		{
			name: "liveness probe", path: "/-/healthy",
			check: func(t *testing.T, b []byte) {
				if !strings.Contains(string(b), "Healthy") {
					t.Fatalf("body = %q", b)
				}
			},
		},
		{name: "readiness probe", path: "/-/ready"},
		{name: "build info", path: "/api/v1/status/buildinfo", check: hasDataKey("version")},
		{name: "flags", path: "/api/v1/status/flags", check: hasDataKey("storage.tsdb.retention.time")},
		{name: "tsdb status", path: "/api/v1/status/tsdb", check: hasDataKey("headStats")},
		{name: "runtime info", path: "/api/v1/status/runtimeinfo", check: hasDataKey("startTime")},
		{name: "config", path: "/api/v1/status/config", check: hasDataKey("yaml")},
		{name: "rules", path: "/api/v1/rules", check: hasDataKey("groups")},
		{name: "alerts", path: "/api/v1/alerts", check: hasDataKey("alerts")},
		{name: "alertmanagers", path: "/api/v1/alertmanagers", check: hasDataKey("activeAlertmanagers")},
		{name: "targets", path: "/api/v1/targets", check: hasDataKey("activeTargets")},
		{name: "metadata", path: "/api/v1/metadata", check: hasDataKey("up")},
		{name: "labels", path: "/api/v1/labels"},
		{name: "series", path: "/api/v1/series"},
		{name: "label values for job", path: "/api/v1/label/job/values"},
		{name: "label values for namespace", path: "/api/v1/label/namespace/values"},
		{name: "label values for __name__", path: "/api/v1/label/__name__/values"},
		{name: "label values for an unknown label", path: "/api/v1/label/whatever/values"},
		{name: "instant query", path: "/api/v1/query?query=up", check: hasResultType("vector")},
		{
			name:  "range query",
			path:  "/api/v1/query_range?query=up&start=1&end=2&step=15",
			check: hasResultType("matrix"),
		},
		{name: "kubernetes build info probe", path: "/api/v1/query?query=kubernetes_build_info", check: hasResultType("vector")},
		{name: "node count probe", path: "/api/v1/query?query=" + url.QueryEscape("count(kube_node_info)"), check: hasResultType("vector")},
		{name: "prometheus build info probe", path: "/api/v1/query?query=prometheus_build_info", check: hasResultType("vector")},
		{
			name:  "scrape interval probe",
			path:  "/api/v1/query?query=" + url.QueryEscape(`prometheus_target_interval_length_seconds{quantile="0.99"}`),
			check: hasResultType("vector"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
			status, body := get(t, f, tc.path)
			if status != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200: %s", tc.path, status, body)
			}
			if tc.check != nil {
				tc.check(t, body)
			}
		})
	}
}

// hasDataKey asserts the reply is a Prometheus success envelope whose data
// object carries key.
func hasDataKey(key string) func(*testing.T, []byte) {
	return func(t *testing.T, b []byte) {
		t.Helper()
		var env struct {
			Status string         `json:"status"`
			Data   map[string]any `json:"data"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("body is not JSON: %v: %s", err, b)
		}
		if env.Status != "success" {
			t.Fatalf("status = %q, want success", env.Status)
		}
		if _, ok := env.Data[key]; !ok {
			t.Fatalf("data has no %q member: %s", key, b)
		}
	}
}

// hasResultType asserts the reply is a query envelope of the given resultType.
func hasResultType(want string) func(*testing.T, []byte) {
	return func(t *testing.T, b []byte) {
		t.Helper()
		var env struct {
			Status string `json:"status"`
			Data   struct {
				ResultType string `json:"resultType"`
			} `json:"data"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("body is not JSON: %v: %s", err, b)
		}
		if env.Status != "success" || env.Data.ResultType != want {
			t.Fatalf("envelope = %+v, want a success %s", env, want)
		}
	}
}

// TestFixturesAreValidPrometheusEnvelopes catches a fixture that was hand-edited
// into invalid JSON, which would otherwise surface as a confusing decode error
// in an unrelated package's test.
func TestFixturesAreValidPrometheusEnvelopes(t *testing.T) {
	t.Parallel()
	f := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	for _, path := range []string{
		"/api/v1/query", "/api/v1/query_range", "/api/v1/series", "/api/v1/labels",
		"/api/v1/metadata", "/api/v1/targets", "/api/v1/rules", "/api/v1/alerts",
		"/api/v1/alertmanagers", "/api/v1/status/tsdb", "/api/v1/status/runtimeinfo",
		"/api/v1/status/buildinfo", "/api/v1/status/flags", "/api/v1/status/config",
		"/api/v1/label/job/values",
	} {
		_, body := get(t, f, path)
		var env struct {
			Status string          `json:"status"`
			Data   json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if env.Status != "success" {
			t.Errorf("%s: status = %q", path, env.Status)
		}
		if len(env.Data) == 0 {
			t.Errorf("%s: no data member", path)
		}
		// Fixtures reach the wire compacted, as a real server would send them.
		if strings.Contains(string(body), "\n") {
			t.Errorf("%s: body is not compact", path)
		}
	}
}

func TestFakeRecordsRequests(t *testing.T) {
	t.Parallel()
	f := testutil.NewFakePrometheus(t, testutil.FakeOptions{})

	get(t, f, "/api/v1/status/flags")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.URL+"/api/v1/query",
		strings.NewReader("query=up&time=1787047200"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	want := []testutil.RecordedRequest{
		{Method: "GET", Path: "/api/v1/status/flags", Form: url.Values{}},
		{Method: "POST", Path: "/api/v1/query", Form: url.Values{"query": {"up"}, "time": {"1787047200"}}},
	}
	if diff := cmp.Diff(want, f.Requests()); diff != "" {
		t.Fatalf("recorded requests mismatch (-want +got):\n%s", diff)
	}

	f.Reset()
	if got := f.Requests(); len(got) != 0 {
		t.Fatalf("Reset left %d requests", len(got))
	}
}

func TestFakeFaultInjection(t *testing.T) {
	t.Parallel()

	t.Run("failure by short endpoint id", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			FailEndpoints: map[string]int{"flags": http.StatusServiceUnavailable},
		})
		status, body := get(t, f, "/api/v1/status/flags")
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", status)
		}
		if !strings.Contains(string(body), `"errorType":"unavailable"`) {
			t.Fatalf("body = %s", body)
		}
		// An unrelated endpoint is untouched.
		if s, _ := get(t, f, "/api/v1/alerts"); s != http.StatusOK {
			t.Fatalf("unrelated endpoint = %d", s)
		}
	})

	t.Run("failure by full path", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			FailEndpoints: map[string]int{"/api/v1/label/job/values": http.StatusInternalServerError},
		})
		if s, _ := get(t, f, "/api/v1/label/job/values"); s != http.StatusInternalServerError {
			t.Fatalf("status = %d", s)
		}
		// A different label still works, which is what lets a test fail one
		// label_values call without failing them all.
		if s, _ := get(t, f, "/api/v1/label/namespace/values"); s != http.StatusOK {
			t.Fatalf("sibling label status = %d", s)
		}
	})

	t.Run("error envelopes name the fault kind", func(t *testing.T) {
		t.Parallel()
		for code, kind := range map[int]string{
			http.StatusBadRequest:          "bad_data",
			http.StatusUnprocessableEntity: "execution",
			http.StatusServiceUnavailable:  "unavailable",
			http.StatusNotFound:            "not_found",
			http.StatusInternalServerError: "internal",
		} {
			f := testutil.NewFakePrometheus(t, testutil.FakeOptions{
				FailEndpoints: map[string]int{"alerts": code},
			})
			_, body := get(t, f, "/api/v1/alerts")
			if !strings.Contains(string(body), `"errorType":"`+kind+`"`) {
				t.Errorf("HTTP %d body = %s, want errorType %q", code, body, kind)
			}
		}
	})

	t.Run("disabled tsdb status", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{DisableTSDBStatus: true})
		if s, _ := get(t, f, "/api/v1/status/tsdb"); s != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", s)
		}
		if s, _ := get(t, f, "/api/v1/status/flags"); s != http.StatusOK {
			t.Fatalf("unrelated status endpoint = %d", s)
		}
	})

	t.Run("unknown path is a 404", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		if s, _ := get(t, f, "/api/v1/nope"); s != http.StatusNotFound {
			t.Fatalf("status = %d", s)
		}
	})

	t.Run("oversize body", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: 40_000})
		_, body := get(t, f, "/api/v1/status/flags")
		if len(body) < 40_000 {
			t.Fatalf("body is %d bytes, want at least 40000", len(body))
		}
		// Padding must keep the envelope parseable.
		var env map[string]any
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("padded body is not JSON: %v", err)
		}
	})

	t.Run("warnings", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{Warnings: []string{"partial", "dropped"}})
		_, body := get(t, f, "/api/v1/query?query=up")
		var env struct {
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"partial", "dropped"}, env.Warnings); diff != "" {
			t.Fatalf("warnings mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("latency", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{Latency: 25 * time.Millisecond})
		start := time.Now()
		get(t, f, "/api/v1/status/flags")
		if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
			t.Fatalf("responded in %s, want at least the injected 25ms", elapsed)
		}
	})

	t.Run("slow body", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			BodySize: 20_000, SlowBody: 5 * time.Millisecond,
		})
		start := time.Now()
		_, body := get(t, f, "/api/v1/status/flags")
		if len(body) < 20_000 {
			t.Fatalf("body is %d bytes", len(body))
		}
		if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
			t.Fatalf("streamed in %s, want the chunk pauses to be observable", elapsed)
		}
	})

	t.Run("query result override", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			QueryResults: map[string]string{"up": `{"status":"success","data":{"resultType":"scalar","result":[1,"7"]}}`},
		})
		_, body := get(t, f, "/api/v1/query?query=up")
		if !strings.Contains(string(body), `"scalar"`) {
			t.Fatalf("body = %s", body)
		}
	})

	t.Run("label values override", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			LabelValues: map[string][]string{"job": {"only-one"}},
		})
		_, body := get(t, f, "/api/v1/label/job/values")
		var env struct {
			Data []string `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]string{"only-one"}, env.Data); diff != "" {
			t.Fatalf("label values mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("server header", func(t *testing.T) {
		t.Parallel()
		f := testutil.NewFakePrometheus(t, testutil.FakeOptions{ServerHeader: "Thanos/0.39.2"})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.URL+"/api/v1/status/flags", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Server"); got != "Thanos/0.39.2" {
			t.Fatalf("Server = %q", got)
		}
	})
}

func TestFakeCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	f := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	f.Close()
	// The t.Cleanup registered by the constructor closes it a second time; do
	// so explicitly too, so the property is asserted rather than assumed.
	f.Close()
}

func TestClock(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 29, 11, 2, 0, 0, time.UTC)
	c := testutil.NewClock(start)
	if !c.Now().Equal(start) {
		t.Fatalf("Now = %s, want %s", c.Now(), start)
	}
	c.Advance(90 * time.Second)
	if want := start.Add(90 * time.Second); !c.Now().Equal(want) {
		t.Fatalf("Now = %s, want %s", c.Now(), want)
	}
	// Negative durations move it backwards, for clock-skew handling.
	c.Advance(-2 * time.Minute)
	if want := start.Add(-30 * time.Second); !c.Now().Equal(want) {
		t.Fatalf("Now = %s, want %s", c.Now(), want)
	}
	other := start.Add(time.Hour)
	c.Set(other)
	if !c.Now().Equal(other) {
		t.Fatalf("Now = %s, want %s", c.Now(), other)
	}
}

func TestClockIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	c := testutil.NewClock(time.Unix(0, 0))
	done := make(chan struct{})
	for range 4 {
		go func() {
			for range 500 {
				c.Advance(time.Millisecond)
				_ = c.Now()
			}
			done <- struct{}{}
		}()
	}
	for range 4 {
		<-done
	}
	if got := c.Now(); !got.Equal(time.Unix(0, 0).Add(2000 * time.Millisecond)) {
		t.Fatalf("Now = %s after 2000 advances", got)
	}
}
