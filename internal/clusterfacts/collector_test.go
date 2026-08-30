// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/clusterfacts"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
)

// fixedNow is the instant every collector test runs at. A manually advanced
// clock keeps LastSeen and LastRefresh assertable without a sleep.
var fixedNow = time.Date(2026, 8, 29, 11, 2, 0, 0, time.UTC)

// newCollector wires a collector to a fake Prometheus, applying opt to the
// config after the defaults are filled in.
func newCollector(t *testing.T, fake *testutil.FakePrometheus, opt func(*clusterfacts.Config)) (*clusterfacts.Collector, *testutil.Clock) {
	t.Helper()
	clock := testutil.NewClock(fixedNow)
	client, err := promclient.New(promclient.Config{BaseURL: fake.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("promclient.New: %v", err)
	}
	cfg := clusterfacts.Config{
		ClusterID:       "prod-us-east-1",
		DisplayName:     "Production US East",
		Description:     "customer-facing API tier",
		Labels:          map[string]string{"env": "prod", "region": "us-east-1"},
		AgentVersion:    "1.4.0",
		ProtocolVersion: "2026-07-28",
		StartedAt:       fixedNow.Add(-time.Hour),
		Client:          client,
		Clock:           clock.Now,
	}
	if opt != nil {
		opt(&cfg)
	}
	c, err := clusterfacts.New(cfg)
	if err != nil {
		t.Fatalf("clusterfacts.New: %v", err)
	}
	return c, clock
}

// wantHealthyPrometheus is the fact set the shipped fixtures describe. It is
// spelled out in full so that a change to collection shows up as a diff rather
// than as a field nobody was asserting on.
func wantHealthyPrometheus() fleet.PrometheusInfo {
	return fleet.PrometheusInfo{
		Reachable:      true,
		Flavor:         "Prometheus",
		Version:        "3.6.0",
		Retention:      "15d",
		ScrapeInterval: "30s",
		LookbackDelta:  "5m",
		ExternalLabels: map[string]string{"cluster": "prod-us-east-1", "region": "us-east-1"},
		ActiveSeries:   482913,
		MetricNames:    22,
		Jobs: []string{
			"apiserver", "cadvisor", "coredns", "kube-state-metrics",
			"kubelet", "node-exporter", "prometheus",
		},
		Namespaces: []string{
			"default", "istio-system", "kube-node-lease",
			"kube-public", "kube-system", "monitoring",
		},
		MetricPrefixes: []string{
			"kube_pod", "apiserver_request", "kube_node",
			"container_cpu", "container_memory", "go_gc", "go_goroutines",
			"istio_request", "istio_requests", "kube_deployment", "kubernetes_build",
			"node_cpu", "node_filesystem", "node_memory",
			"prometheus_build", "prometheus_target", "prometheus_tsdb", "up",
		},
		RuleGroups:      2,
		AlertingRules:   3,
		FiringAlerts:    2,
		HasAlertmanager: true,
	}
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	client, err := promclient.New(promclient.Config{BaseURL: fake.URL})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     clusterfacts.Config
		wantErr string
	}{
		{"empty cluster id", clusterfacts.Config{Client: client}, "ClusterID"},
		{"uppercase cluster id", clusterfacts.Config{ClusterID: "Prod", Client: client}, "ClusterID"},
		{"leading hyphen", clusterfacts.Config{ClusterID: "-prod", Client: client}, "ClusterID"},
		{"trailing hyphen", clusterfacts.Config{ClusterID: "prod-", Client: client}, "ClusterID"},
		{"underscore", clusterfacts.Config{ClusterID: "prod_us", Client: client}, "ClusterID"},
		{"too long", clusterfacts.Config{ClusterID: strings.Repeat("a", 64), Client: client}, "ClusterID"},
		{"nil client", clusterfacts.Config{ClusterID: "prod"}, "Client is required"},
		{
			"negative refresh interval",
			clusterfacts.Config{ClusterID: "prod", Client: client, RefreshInterval: -time.Second},
			"RefreshInterval",
		},
		{"negative topn", clusterfacts.Config{ClusterID: "prod", Client: client, TopN: -1}, "TopN"},
		{
			"negative max facts bytes",
			clusterfacts.Config{ClusterID: "prod", Client: client, MaxFactsBytes: -1},
			"MaxFactsBytes",
		},
		{
			"negative node count",
			clusterfacts.Config{ClusterID: "prod", Client: client, KubernetesNodeCount: -1},
			"KubernetesNodeCount",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := clusterfacts.New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) {
		cfg.RefreshInterval = 0
		cfg.TopN = 0
	})
	if got := c.RefreshInterval(); got != clusterfacts.DefaultRefreshInterval {
		t.Fatalf("RefreshInterval = %s, want %s", got, clusterfacts.DefaultRefreshInterval)
	}
	if got, want := c.Generation(), fixedNow.Add(-time.Hour).UnixNano(); got != want {
		t.Fatalf("Generation = %d, want the StartedAt nanos %d", got, want)
	}
	if !c.LastRefresh().IsZero() {
		t.Fatalf("LastRefresh = %s before any refresh, want the zero time", c.LastRefresh())
	}
	if got := fake.Requests(); len(got) != 0 {
		t.Fatalf("New performed I/O: %+v", got)
	}
}

// TestNewDefaultsGenerationToTheClock covers the StartedAt-unset path, where
// the generation has to come from the injected clock rather than time.Now.
func TestNewDefaultsGenerationToTheClock(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) { cfg.StartedAt = time.Time{} })
	if got, want := c.Generation(), fixedNow.UnixNano(); got != want {
		t.Fatalf("Generation = %d, want %d", got, want)
	}
}

// TestNewPublishesPlaceholderFacts proves a spoke can answer Describe the
// instant its tunnel attaches, before any upstream call has been made.
func TestNewPublishesPlaceholderFacts(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)

	facts := c.Facts()
	if facts.Fingerprint == "" {
		t.Fatal("placeholder facts have no fingerprint")
	}
	if !facts.Changed {
		t.Fatal("Facts().Changed = false")
	}
	if facts.Cluster.Prometheus.Reachable {
		t.Fatal("placeholder reports Prometheus as reachable")
	}
	if !strings.Contains(facts.Cluster.Prometheus.UnreachableReason, "not been collected") {
		t.Fatalf("UnreachableReason = %q", facts.Cluster.Prometheus.UnreachableReason)
	}
	if facts.Cluster.Prometheus.ActiveSeries != -1 || facts.Cluster.Prometheus.MetricNames != -1 {
		t.Fatalf("uncollected counts = %d/%d, want -1/-1",
			facts.Cluster.Prometheus.ActiveSeries, facts.Cluster.Prometheus.MetricNames)
	}
	if facts.Cluster.Kubernetes.Available {
		t.Fatal("placeholder reports Kubernetes as available")
	}
	// The operator-supplied fields are known without any I/O and must be there.
	if facts.Cluster.ID != "prod-us-east-1" || facts.Cluster.DisplayName != "Production US East" {
		t.Fatalf("static fields missing: %+v", facts.Cluster)
	}
	if diff := cmp.Diff(map[string]string{"env": "prod", "region": "us-east-1"}, facts.Cluster.Labels); diff != "" {
		t.Fatalf("labels mismatch (-want +got):\n%s", diff)
	}
}

// TestNewPlaceholderHonoursOperatorKubernetes covers the case where the
// operator supplied Kubernetes facts: they are available from the very first
// Describe, because they need no upstream call.
func TestNewPlaceholderHonoursOperatorKubernetes(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) {
		cfg.KubernetesVersion = "v1.31.0"
		cfg.KubernetesNodeCount = 7
		cfg.KubernetesClusterUID = "abc123"
	})
	got := c.Facts().Cluster.Kubernetes
	want := fleet.KubernetesInfo{Available: true, Version: "v1.31.0", ClusterUID: "abc123", NodeCount: 7}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("kubernetes facts mismatch (-want +got):\n%s", diff)
	}
}

func TestRefreshCollectsEveryFact(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, clock := newCollector(t, fake, nil)

	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got := c.Facts().Cluster

	if diff := cmp.Diff(wantHealthyPrometheus(), got.Prometheus); diff != "" {
		t.Fatalf("prometheus facts mismatch (-want +got):\n%s", diff)
	}
	wantK8s := fleet.KubernetesInfo{Available: true, Version: "v1.32.4", NodeCount: 12}
	if diff := cmp.Diff(wantK8s, got.Kubernetes); diff != "" {
		t.Fatalf("kubernetes facts mismatch (-want +got):\n%s", diff)
	}
	if !got.LastSeen.Equal(clock.Now()) {
		t.Fatalf("LastSeen = %s, want %s", got.LastSeen, clock.Now())
	}
	if !c.LastRefresh().Equal(clock.Now()) {
		t.Fatalf("LastRefresh = %s, want %s", c.LastRefresh(), clock.Now())
	}
}

// TestRefreshNeverCountsEverySeries is a cost regression test.
// count({__name__=~".+"}) answers the same question as the tsdb status
// endpoint, but on a large TSDB it walks the whole index and can take the
// Prometheus down. A facts refresh must never be the most expensive query a
// cluster serves.
func TestRefreshNeverCountsEverySeries(t *testing.T) {
	t.Parallel()

	for _, opts := range []testutil.FakeOptions{
		{},
		{DisableTSDBStatus: true},
		{FailEndpoints: map[string]int{"tsdb_status": http.StatusNotFound, "label_values": http.StatusInternalServerError}},
	} {
		fake := testutil.NewFakePrometheus(t, opts)
		c, _ := newCollector(t, fake, nil)
		_ = c.Refresh(t.Context())

		for _, req := range fake.Requests() {
			for _, expr := range req.Form["query"] {
				if strings.Contains(expr, "__name__") {
					t.Fatalf("refresh issued a whole-index query: %q", expr)
				}
				if strings.HasPrefix(expr, "count(") && !strings.Contains(expr, "kube_node_info") {
					t.Fatalf("refresh issued an unexpected count query: %q", expr)
				}
			}
		}
	}
}

// TestRefreshTSDBUnavailable covers the servers that do not implement
// /api/v1/status/tsdb: the series count becomes the -1 sentinel with the reason
// on the refresh error, and every other fact still arrives.
func TestRefreshTSDBUnavailable(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{DisableTSDBStatus: true})
	c, _ := newCollector(t, fake, nil)

	err := c.Refresh(t.Context())
	if err == nil {
		t.Fatal("Refresh() error = nil, want the tsdb source reported")
	}
	if !strings.Contains(err.Error(), "status/tsdb") {
		t.Fatalf("Refresh() error = %v, want it to name the failing source", err)
	}

	got := c.Facts().Cluster.Prometheus
	if got.ActiveSeries != -1 {
		t.Fatalf("ActiveSeries = %d, want the -1 sentinel", got.ActiveSeries)
	}
	// metricNames comes from the metric-name list, which is still available.
	if got.MetricNames != 22 {
		t.Fatalf("MetricNames = %d, want 22", got.MetricNames)
	}
	want := wantHealthyPrometheus()
	want.ActiveSeries = -1
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("one failing source disturbed the others (-want +got):\n%s", diff)
	}
}

// TestRefreshMetricNamesFallBackToTSDB covers the reverse failure: the
// metric-name list is unavailable but the tsdb status endpoint knows how many
// distinct __name__ values there are.
func TestRefreshMetricNamesFallBackToTSDB(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
		FailEndpoints: map[string]int{"/api/v1/label/__name__/values": http.StatusInternalServerError},
	})
	c, _ := newCollector(t, fake, nil)
	_ = c.Refresh(t.Context())

	got := c.Facts().Cluster.Prometheus
	if got.MetricNames != 2211 {
		t.Fatalf("MetricNames = %d, want the tsdb labelValueCountByLabelName figure 2211", got.MetricNames)
	}
	if got.MetricPrefixes != nil {
		t.Fatalf("MetricPrefixes = %v, want nil when the name list is unavailable", got.MetricPrefixes)
	}
	if got.ActiveSeries != 482913 {
		t.Fatalf("ActiveSeries = %d", got.ActiveSeries)
	}
}

// TestRefreshSourcesFailIndependently is the core failure-tolerance property:
// one broken endpoint records a reason and leaves every other fact intact.
func TestRefreshSourcesFailIndependently(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		fail       map[string]int
		opts       *testutil.FakeOptions
		wantSource string
		mutate     func(*fleet.PrometheusInfo)
	}{
		{
			name: "buildinfo", fail: map[string]int{"build_info": http.StatusInternalServerError},
			wantSource: "buildinfo",
			mutate: func(p *fleet.PrometheusInfo) {
				// The version is lost, but the Server header arrives on the
				// failure response too, so the flavor survives.
				p.Version = ""
			},
		},
		{
			name: "buildinfo behind an anonymous proxy",
			fail: map[string]int{"build_info": http.StatusInternalServerError},
			opts: &testutil.FakeOptions{ServerHeader: "nginx/1.27.0"},
			// No version and no product name anywhere: the detector refuses to
			// guess rather than sending an agent after endpoints that may not
			// exist.
			wantSource: "buildinfo",
			mutate: func(p *fleet.PrometheusInfo) {
				p.Version = ""
				p.Flavor = clusterfacts.FlavorUnknown
			},
		},
		{
			name: "flags", fail: map[string]int{"flags": http.StatusInternalServerError},
			wantSource: "flags",
			mutate: func(p *fleet.PrometheusInfo) {
				p.Retention = ""
				p.LookbackDelta = ""
			},
		},
		{
			name: "rules", fail: map[string]int{"rules": http.StatusInternalServerError},
			wantSource: "rules",
			mutate:     func(p *fleet.PrometheusInfo) { p.RuleGroups, p.AlertingRules = 0, 0 },
		},
		{
			name: "alerts", fail: map[string]int{"alerts": http.StatusInternalServerError},
			wantSource: "alerts",
			mutate:     func(p *fleet.PrometheusInfo) { p.FiringAlerts = 0 },
		},
		{
			name: "alertmanagers", fail: map[string]int{"alertmanagers": http.StatusInternalServerError},
			wantSource: "alertmanagers",
			mutate:     func(p *fleet.PrometheusInfo) { p.HasAlertmanager = false },
		},
		{
			name: "jobs", fail: map[string]int{"/api/v1/label/job/values": http.StatusInternalServerError},
			wantSource: "label_values(job)",
			mutate:     func(p *fleet.PrometheusInfo) { p.Jobs = nil },
		},
		{
			name: "namespaces", fail: map[string]int{"/api/v1/label/namespace/values": http.StatusInternalServerError},
			wantSource: "label_values(namespace)",
			mutate:     func(p *fleet.PrometheusInfo) { p.Namespaces = nil },
		},
		{
			name: "metric names", fail: map[string]int{"/api/v1/label/__name__/values": http.StatusInternalServerError},
			wantSource: "label_values(__name__)",
			mutate: func(p *fleet.PrometheusInfo) {
				p.MetricNames = 2211 // from the tsdb status fallback
				p.MetricPrefixes = nil
			},
		},
		{
			name: "instant queries", fail: map[string]int{"query": http.StatusInternalServerError},
			wantSource: "external labels probe",
			mutate: func(p *fleet.PrometheusInfo) {
				p.ExternalLabels = nil
				p.ScrapeInterval = ""
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := testutil.FakeOptions{}
			if tc.opts != nil {
				opts = *tc.opts
			}
			opts.FailEndpoints = tc.fail
			fake := testutil.NewFakePrometheus(t, opts)
			c, _ := newCollector(t, fake, nil)

			err := c.Refresh(t.Context())
			if err == nil || !strings.Contains(err.Error(), tc.wantSource) {
				t.Fatalf("Refresh() error = %v, want it to name %q", err, tc.wantSource)
			}

			want := wantHealthyPrometheus()
			tc.mutate(&want)
			if diff := cmp.Diff(want, c.Facts().Cluster.Prometheus); diff != "" {
				t.Fatalf("a single failing source disturbed the rest (-want +got):\n%s", diff)
			}
			// The cluster is still reachable and still identified.
			if !c.Facts().Cluster.Prometheus.Reachable {
				t.Fatal("one failing source marked the whole cluster unreachable")
			}
		})
	}
}

// TestRefreshPingFailureCarriesDetailForward proves a Prometheus restart does
// not erase what an agent already knows about a cluster: reachability flips to
// false with a reason, while the retention, jobs and prefixes collected earlier
// remain.
func TestRefreshPingFailureCarriesDetailForward(t *testing.T) {
	t.Parallel()

	healthy := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	client, err := promclient.New(promclient.Config{BaseURL: healthy.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	clock := testutil.NewClock(fixedNow)
	c, err := clusterfacts.New(clusterfacts.Config{
		ClusterID: "prod-us-east-1", Client: client, Clock: clock.Now,
		KubernetesVersion: "v1.31.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	before := c.Facts().Cluster

	// The Prometheus goes away entirely.
	healthy.Close()
	clock.Advance(10 * time.Minute)
	err = c.Refresh(t.Context())
	if err == nil {
		t.Fatal("Refresh() error = nil after the ping failed")
	}
	if !strings.Contains(err.Error(), "ping prometheus") {
		t.Fatalf("Refresh() error = %v, want it to name the ping", err)
	}

	after := c.Facts().Cluster
	if after.Prometheus.Reachable {
		t.Fatal("Reachable = true after the ping failed")
	}
	if after.Prometheus.UnreachableReason == "" {
		t.Fatal("UnreachableReason is empty")
	}
	if len(after.Prometheus.UnreachableReason) > 300+len("...[clipped]") {
		t.Fatalf("UnreachableReason is unbounded: %d bytes", len(after.Prometheus.UnreachableReason))
	}
	// Everything an agent might act on survives.
	if diff := cmp.Diff(before.Prometheus.Jobs, after.Prometheus.Jobs); diff != "" {
		t.Fatalf("jobs were blanked by an unreachable Prometheus (-before +after):\n%s", diff)
	}
	if diff := cmp.Diff(before.Prometheus.MetricPrefixes, after.Prometheus.MetricPrefixes); diff != "" {
		t.Fatalf("metric prefixes were blanked (-before +after):\n%s", diff)
	}
	if after.Prometheus.Retention != before.Prometheus.Retention {
		t.Fatalf("retention was blanked: %q", after.Prometheus.Retention)
	}
	if diff := cmp.Diff(before.Kubernetes, after.Kubernetes); diff != "" {
		t.Fatalf("kubernetes facts were blanked (-before +after):\n%s", diff)
	}
	if !c.LastRefresh().Equal(clock.Now()) {
		t.Fatalf("LastRefresh was not advanced by a failed refresh")
	}
}

func TestKubernetesFacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts testutil.FakeOptions
		cfg  func(*clusterfacts.Config)
		want fleet.KubernetesInfo
	}{
		{
			name: "derived from promql when the metrics exist",
			want: fleet.KubernetesInfo{Available: true, Version: "v1.32.4", NodeCount: 12},
		},
		{
			name: "operator configuration wins over promql",
			// An operator who bothered to set these knows more than
			// kube-state-metrics does.
			cfg: func(c *clusterfacts.Config) {
				c.KubernetesVersion = "v1.30.11"
				c.KubernetesNodeCount = 3
				c.KubernetesClusterUID = "uid-9f2c"
			},
			want: fleet.KubernetesInfo{
				Available: true, Version: "v1.30.11", ClusterUID: "uid-9f2c", NodeCount: 3,
			},
		},
		{
			name: "unavailable with a reason when nothing is known",
			opts: testutil.FakeOptions{QueryResults: map[string]string{
				"kubernetes_build_info": `{"status":"success","data":{"resultType":"vector","result":[]}}`,
				"count(kube_node_info)": `{"status":"success","data":{"resultType":"vector","result":[]}}`,
			}},
			want: fleet.KubernetesInfo{
				Available:         false,
				UnavailableReason: "spoke has no Kubernetes API access by design; set PMF_CLUSTER_K8S_* or expose kubernetes_build_info to Prometheus",
			},
		},
		{
			name: "operator values rescue an unavailable cluster",
			opts: testutil.FakeOptions{QueryResults: map[string]string{
				"kubernetes_build_info": `{"status":"success","data":{"resultType":"vector","result":[]}}`,
				"count(kube_node_info)": `{"status":"success","data":{"resultType":"vector","result":[]}}`,
			}},
			cfg:  func(c *clusterfacts.Config) { c.KubernetesVersion = "v1.31.0" },
			want: fleet.KubernetesInfo{Available: true, Version: "v1.31.0"},
		},
		{
			name: "a promql failure is tolerated",
			opts: testutil.FakeOptions{FailEndpoints: map[string]int{"query": http.StatusInternalServerError}},
			cfg:  func(c *clusterfacts.Config) { c.KubernetesNodeCount = 5 },
			want: fleet.KubernetesInfo{Available: true, NodeCount: 5},
		},
		{
			name: "gitVersion label spelling",
			opts: testutil.FakeOptions{QueryResults: map[string]string{
				"kubernetes_build_info": `{"status":"success","data":{"resultType":"vector","result":` +
					`[{"metric":{"gitVersion":"v1.29.8"},"value":[1,"1"]}]}}`,
			}},
			want: fleet.KubernetesInfo{Available: true, Version: "v1.29.8", NodeCount: 12},
		},
		{
			name: "an absurd node count is discarded rather than trusted",
			opts: testutil.FakeOptions{QueryResults: map[string]string{
				"count(kube_node_info)": `{"status":"success","data":{"resultType":"vector","result":` +
					`[{"metric":{},"value":[1,"1e30"]}]}}`,
			}},
			want: fleet.KubernetesInfo{Available: true, Version: "v1.32.4"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, tc.opts)
			c, _ := newCollector(t, fake, tc.cfg)
			_ = c.Refresh(t.Context())
			if diff := cmp.Diff(tc.want, c.Facts().Cluster.Kubernetes); diff != "" {
				t.Fatalf("kubernetes facts mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRefreshUsesStatusConfigWhenEnabled proves the gated endpoint is
// authoritative for external labels and the scrape interval when an operator
// opts in, and that it is silently skipped (not reported as a failure) when
// they have not.
func TestRefreshUsesStatusConfigWhenEnabled(t *testing.T) {
	t.Parallel()

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		client, err := promclient.New(promclient.Config{
			BaseURL: fake.URL, Timeout: 5 * time.Second, AllowStatusConfig: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := clusterfacts.New(clusterfacts.Config{ClusterID: "prod", Client: client})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		got := c.Facts().Cluster.Prometheus
		want := map[string]string{
			"cluster": "prod-us-east-1", "prometheus": "monitoring/k8s", "region": "us-east-1",
		}
		if diff := cmp.Diff(want, got.ExternalLabels); diff != "" {
			t.Fatalf("external labels mismatch (-want +got):\n%s", diff)
		}
		if got.ScrapeInterval != "30s" {
			t.Fatalf("ScrapeInterval = %q", got.ScrapeInterval)
		}
		// The probe queries must not have been issued: the config answered both.
		for _, req := range fake.Requests() {
			for _, expr := range req.Form["query"] {
				if strings.Contains(expr, "prometheus_build_info") ||
					strings.Contains(expr, "prometheus_target_interval") {
					t.Fatalf("probe query issued despite the config being available: %q", expr)
				}
			}
		}
	})

	t.Run("gated off is not a failure", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c, _ := newCollector(t, fake, nil)
		if err := c.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh() error = %v, want nil: a gated endpoint is an expected outcome", err)
		}
		for _, req := range fake.Requests() {
			if req.Path == "/api/v1/status/config" {
				t.Fatal("the gated config endpoint was called")
			}
		}
	})

	t.Run("an upstream config failure is reported", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			FailEndpoints: map[string]int{"config": http.StatusInternalServerError},
		})
		client, err := promclient.New(promclient.Config{
			BaseURL: fake.URL, Timeout: 5 * time.Second, AllowStatusConfig: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := clusterfacts.New(clusterfacts.Config{ClusterID: "prod", Client: client})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Refresh(t.Context())
		if err == nil || !strings.Contains(err.Error(), "status/config") {
			t.Fatalf("Refresh() error = %v, want it to name status/config", err)
		}
		// And the probe fallbacks still filled the fields in.
		if got := c.Facts().Cluster.Prometheus.ScrapeInterval; got != "30s" {
			t.Fatalf("ScrapeInterval = %q, want the probe fallback to have run", got)
		}
	})
}

// TestRefreshPrefersScrapeIntervalFlag covers the compatible servers that do
// expose the interval as a command-line flag, which is cheaper than a probe.
func TestRefreshPrefersScrapeIntervalFlag(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// The shipped flags fixture has no scrape.interval, so the probe answers.
	if got := c.Facts().Cluster.Prometheus.ScrapeInterval; got != "30s" {
		t.Fatalf("ScrapeInterval = %q", got)
	}
}

func TestFlavorDetectionEndToEnd(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, header, want string }{
		{"prometheus", "Prometheus/3.6.0", "Prometheus"},
		{"thanos", "Thanos/0.39.2", "Thanos"},
		{"mimir", "Mimir/2.18.0", "Mimir"},
		{"cortex", "Cortex/1.19.0", "Cortex"},
		{"victoriametrics", "VictoriaMetrics/1.108.0", "VictoriaMetrics"},
		{"anonymous proxy in front", "nginx/1.27.0", "Prometheus"}, // inferred from storage.tsdb.path + version
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{ServerHeader: tc.header})
			c, _ := newCollector(t, fake, nil)
			if err := c.Refresh(t.Context()); err != nil {
				t.Fatalf("Refresh: %v", err)
			}
			if got := c.Facts().Cluster.Prometheus.Flavor; got != tc.want {
				t.Fatalf("Flavor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRefreshTwiceIsFingerprintStable is the property the hub's Describe cache
// is built on. Two refreshes against identical upstream data must produce an
// identical fingerprint; if collectedAt or LastSeen leaked in, this fails and
// the whole optimisation inverts into extra traffic.
func TestRefreshTwiceIsFingerprintStable(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, clock := newCollector(t, fake, nil)

	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	first := c.Facts()

	// Time moves on, which changes LastSeen, and the upstream is re-queried
	// from scratch, which re-derives every map and slice.
	clock.Advance(11 * time.Minute)
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}
	second := c.Facts()

	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprint churned across two identical refreshes:\n first  = %s\n second = %s",
			first.Fingerprint, second.Fingerprint)
	}
	if first.Cluster.LastSeen.Equal(second.Cluster.LastSeen) {
		t.Fatal("the test did not actually advance LastSeen, so it proves nothing")
	}
}

// TestRefreshChangesFingerprintWhenTheClusterChanges is the other half: a real
// change must be visible, or the hub would serve stale facts forever.
func TestRefreshChangesFingerprintWhenTheClusterChanges(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	before := c.Facts().Fingerprint

	fake.Close() // the Prometheus goes away, which is a real change
	_ = c.Refresh(t.Context())
	if after := c.Facts().Fingerprint; after == before {
		t.Fatal("the fingerprint did not change when the cluster became unreachable")
	}
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	current := c.Facts().Fingerprint

	t.Run("matching fingerprint transfers a hash instead of a document", func(t *testing.T) {
		t.Parallel()
		got, err := c.Describe(t.Context(), current)
		if err != nil {
			t.Fatalf("Describe: %v", err)
		}
		if got.Changed {
			t.Fatal("Changed = true for a current fingerprint")
		}
		if diff := cmp.Diff(fleet.Cluster{}, got.Cluster); diff != "" {
			t.Fatalf("an unchanged Describe carried a cluster payload (-want +got):\n%s", diff)
		}
		if got.Fingerprint != current {
			t.Fatalf("Fingerprint = %q, want %q", got.Fingerprint, current)
		}
		if got.Generation != c.Generation() {
			t.Fatalf("Generation = %d, want %d", got.Generation, c.Generation())
		}
	})

	t.Run("stale fingerprint gets the full document", func(t *testing.T) {
		t.Parallel()
		got, err := c.Describe(t.Context(), "0000000000000000000000000000000000000000000000000000000000000000")
		if err != nil {
			t.Fatalf("Describe: %v", err)
		}
		if !got.Changed {
			t.Fatal("Changed = false for a stale fingerprint")
		}
		if got.Cluster.ID != "prod-us-east-1" {
			t.Fatalf("Cluster = %+v", got.Cluster)
		}
	})

	t.Run("empty fingerprint gets the full document", func(t *testing.T) {
		t.Parallel()
		got, err := c.Describe(t.Context(), "")
		if err != nil {
			t.Fatalf("Describe: %v", err)
		}
		if !got.Changed || got.Cluster.ID == "" {
			t.Fatalf("Facts = %+v", got)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.Describe(ctx, ""); !errors.Is(err, context.Canceled) {
			t.Fatalf("Describe() error = %v, want context.Canceled", err)
		}
	})
}

// TestDescribeNeverPerformsIO proves a slow or hung Prometheus cannot delay the
// hub: collection happens on a ticker, never inline.
func TestDescribeNeverPerformsIO(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)
	fake.Reset()

	for range 10 {
		if _, err := c.Describe(t.Context(), ""); err != nil {
			t.Fatalf("Describe: %v", err)
		}
		_ = c.Facts()
	}
	if got := fake.Requests(); len(got) != 0 {
		t.Fatalf("Describe/Facts performed I/O: %+v", got)
	}
}

// TestFactsReturnsADeepCopy proves a caller cannot reach into the collector's
// cached snapshot through the maps and slices it hands out.
func TestFactsReturnsADeepCopy(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	first := c.Facts().Cluster
	first.Labels["env"] = "tampered"
	first.Prometheus.ExternalLabels["cluster"] = "tampered"
	first.Prometheus.Jobs[0] = "tampered"
	first.Prometheus.Namespaces[0] = "tampered"
	first.Prometheus.MetricPrefixes[0] = "tampered"

	second := c.Facts().Cluster
	if second.Labels["env"] != "prod" {
		t.Fatal("labels are shared with the cached snapshot")
	}
	if second.Prometheus.ExternalLabels["cluster"] != "prod-us-east-1" {
		t.Fatal("external labels are shared with the cached snapshot")
	}
	if second.Prometheus.Jobs[0] == "tampered" ||
		second.Prometheus.Namespaces[0] == "tampered" ||
		second.Prometheus.MetricPrefixes[0] == "tampered" {
		t.Fatal("sampled slices are shared with the cached snapshot")
	}
}

func TestTopNCapsEverySampledList(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) { cfg.TopN = 3 })
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got := c.Facts().Cluster.Prometheus
	for name, list := range map[string][]string{
		"jobs": got.Jobs, "namespaces": got.Namespaces, "metricPrefixes": got.MetricPrefixes,
	} {
		if len(list) != 3 {
			t.Fatalf("%s has %d entries, want the TopN cap of 3: %v", name, len(list), list)
		}
	}
	// The cap must keep the highest-count prefixes, not the alphabetically
	// first ones.
	if diff := cmp.Diff([]string{"kube_pod", "apiserver_request", "kube_node"}, got.MetricPrefixes); diff != "" {
		t.Fatalf("metric prefixes mismatch (-want +got):\n%s", diff)
	}
}

// TestCapSizeTruncatesSampledListsFirst proves the byte cap is enforced, that
// it eats the sampled lists rather than the operator's own text, and that it
// says so. A spoke that scrapes forty thousand jobs must not be able to push a
// megabyte of registry data at the hub on every reconnect.
func TestCapSizeTruncatesSampledListsFirst(t *testing.T) {
	t.Parallel()

	// A cluster far larger than the fixtures describe.
	bulk := func(prefix string, n int) []string {
		out := make([]string, 0, n)
		for i := range n {
			out = append(out, fmt.Sprintf("%s-with-a-fairly-long-name-%04d", prefix, i))
		}
		return out
	}
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
		LabelValues: map[string][]string{
			"job":       bulk("job", 400),
			"namespace": bulk("namespace", 400),
		},
	})
	c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) {
		cfg.TopN = 400
		cfg.MaxFactsBytes = 2000
	})
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got := c.Facts().Cluster

	serialized, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) > 2000 {
		t.Fatalf("serialized facts are %d bytes, cap is 2000", len(serialized))
	}
	if !strings.Contains(got.Description, "sampled lists were shortened") {
		t.Fatalf("truncation was silent; description = %q", got.Description)
	}
	if got.ID != "prod-us-east-1" || got.DisplayName != "Production US East" {
		t.Fatalf("truncation discarded operator-supplied identity: %+v", got)
	}
	if !strings.HasPrefix(got.Description, "customer-facing API tier") {
		t.Fatalf("truncation discarded the operator's description: %q", got.Description)
	}
	// Namespaces are sacrificed before metric prefixes, which are the single
	// most informative fact an agent gets from a cluster it has never queried.
	if len(got.Prometheus.MetricPrefixes) == 0 {
		t.Fatalf("metric prefixes were dropped while %d namespaces survived",
			len(got.Prometheus.Namespaces))
	}
	if len(got.Prometheus.Namespaces) >= len(got.Prometheus.Jobs) {
		t.Fatalf("namespaces (%d) were not shortened before jobs (%d)",
			len(got.Prometheus.Namespaces), len(got.Prometheus.Jobs))
	}
	// What survives is still a prefix of the ranked list, so the most
	// significant entries are the ones kept.
	if got.Prometheus.MetricPrefixes[0] != "kube_pod" {
		t.Fatalf("truncation did not keep the top-ranked prefix: %v", got.Prometheus.MetricPrefixes)
	}
}

// TestCapSizeIsNotAppliedWhenItIsNotNeeded proves a normal cluster carries no
// truncation note, so the note stays meaningful.
func TestCapSizeIsNotAppliedWhenItIsNotNeeded(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := c.Facts().Cluster.Description; got != "customer-facing API tier" {
		t.Fatalf("description = %q, want it untouched", got)
	}
}

// TestCapSizeStopsWhenOnlyOperatorTextIsLeft proves the loop terminates rather
// than silently discarding text the operator wrote.
func TestCapSizeStopsWhenOnlyOperatorTextIsLeft(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) {
		cfg.Description = strings.Repeat("a very long operator description. ", 40)
		cfg.MaxFactsBytes = 64 // impossible to satisfy
	})
	if err := c.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got := c.Facts().Cluster
	if !strings.Contains(got.Description, "a very long operator description") {
		t.Fatalf("the operator's description was discarded: %q", got.Description)
	}
	if len(got.Prometheus.Jobs) != 0 || len(got.Prometheus.Namespaces) != 0 {
		t.Fatalf("sampled lists survived an impossible cap: %+v", got.Prometheus)
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("refreshes immediately and then on the ticker", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) {
			cfg.RefreshInterval = 5 * time.Millisecond
		})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); c.Run(ctx) }()

		deadline := time.After(5 * time.Second)
		for {
			if c.Facts().Cluster.Prometheus.Reachable {
				break
			}
			select {
			case <-deadline:
				t.Fatal("Run did not publish collected facts")
			case <-time.After(time.Millisecond):
			}
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after its context was cancelled")
		}
	})

	t.Run("keeps running when a refresh fails", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		base := fake.URL
		fake.Close()
		client, err := promclient.New(promclient.Config{BaseURL: base, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := clusterfacts.New(clusterfacts.Config{
			ClusterID: "prod", Client: client, RefreshInterval: 2 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Millisecond)
		defer cancel()
		c.Run(ctx) // must return on its own rather than panicking or spinning forever
		if c.Facts().Cluster.Prometheus.Reachable {
			t.Fatal("an unreachable Prometheus was reported as reachable")
		}
	})

	t.Run("an already cancelled context returns promptly", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c, _ := newCollector(t, fake, func(cfg *clusterfacts.Config) {
			cfg.RefreshInterval = time.Hour
		})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		done := make(chan struct{})
		go func() { defer close(done); c.Run(ctx) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run ignored a cancelled context")
		}
	})
}

// TestConcurrentAccess is the concurrency guarantee the package doc makes: a
// refresh running against a stream of Facts and Describe calls must be race
// free and must never publish a torn snapshot.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c, _ := newCollector(t, fake, nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	for range 4 {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				default:
				}
				f := c.Facts()
				if f.Fingerprint == "" {
					panic("published a snapshot with no fingerprint")
				}
				if _, err := c.Describe(ctx, f.Fingerprint); err != nil && ctx.Err() == nil {
					panic("Describe: " + err.Error())
				}
				_ = c.LastRefresh()
			}
		}()
	}
	for range 5 {
		if err := c.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	}
	close(done)
}

// TestMultiSampleProbesAreOrderStable proves the probe queries pick the same
// series every time when a cluster returns several. Without the canonical
// ordering, a multi-replica Prometheus would make the external labels — and
// therefore the fingerprint — flip between refreshes of an unchanged cluster.
func TestMultiSampleProbesAreOrderStable(t *testing.T) {
	t.Parallel()

	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{QueryResults: map[string]string{
		"prometheus_build_info": `{"status":"success","data":{"resultType":"vector","result":[` +
			`{"metric":{"replica":"b","cluster":"prod"},"value":[1,"1"]},` +
			`{"metric":{"replica":"a","cluster":"prod"},"value":[1,"1"]}]}}`,
		`prometheus_target_interval_length_seconds{quantile="0.99"}`: `{"status":"success","data":{"resultType":"vector","result":[` +
			`{"metric":{"job":"z"},"value":[1,"30"]},` +
			`{"metric":{"interval":"15s","job":"a"},"value":[1,"15"]}]}}`,
	}})

	var first string
	for i := range 25 {
		c, _ := newCollector(t, fake, nil)
		if err := c.Refresh(t.Context()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		got := c.Facts().Cluster.Prometheus
		// The lexically first label set wins, deterministically.
		if diff := cmp.Diff(map[string]string{"cluster": "prod", "replica": "a"}, got.ExternalLabels); diff != "" {
			t.Fatalf("external labels mismatch (-want +got):\n%s", diff)
		}
		// A series without the interval label is skipped rather than treated as
		// an empty answer.
		if got.ScrapeInterval != "15s" {
			t.Fatalf("ScrapeInterval = %q, want 15s", got.ScrapeInterval)
		}
		if i == 0 {
			first = c.Facts().Fingerprint
		} else if c.Facts().Fingerprint != first {
			t.Fatal("fingerprint churned across refreshes of a multi-series cluster")
		}
	}
}
