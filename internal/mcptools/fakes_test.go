// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
)

// fixtures are recorded Prometheus API responses. They are real envelopes
// rather than minimal stubs, including the credential-bearing scrape URLs that
// the targets redaction test exists to prove never escape.
//
//go:embed testdata/fixtures/*.json
var fixtures embed.FS

// fixture reads one recorded response.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fixtures.ReadFile("testdata/fixtures/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// fakeResponse is one canned upstream answer.
type fakeResponse struct {
	// body is the response body. Empty means the endpoint's default fixture.
	body []byte
	// status is the upstream HTTP status. Zero means 200.
	status int
	// err is returned instead of a result, for exercising the promproxy
	// failure paths.
	err error
	// delay is slept before answering, honouring the context so a per-cluster
	// deadline can be exercised.
	delay time.Duration
}

// fakeProm is a [Prometheus] that answers from fixtures. Keys are matched most
// specific first: "cluster/endpoint/label", "cluster/endpoint",
// "endpoint/label", "endpoint".
type fakeProm struct {
	mu        sync.Mutex
	responses map[string]fakeResponse
	calls     []promproxy.Call
	// denyClusters causes Do to return promproxy.ErrForbidden, which is what
	// the proxy's own second scope check produces.
	denyClusters map[string]bool
	// unreachable models the registry state the real proxy consults: a cluster
	// with no tunnel yields NotConnectedError and a degraded one yields an
	// upstream failure, so a test cannot accidentally query a cluster the fleet
	// could not actually have answered.
	unreachable map[string]error
}

// newFakeProm returns a fake wired to the standard fixtures.
func newFakeProm(t *testing.T) *fakeProm {
	t.Helper()
	f := &fakeProm{
		responses:    map[string]fakeResponse{},
		denyClusters: map[string]bool{},
		unreachable:  map[string]error{},
	}
	for _, c := range testClusters() {
		switch c.State {
		case fleet.StateDisconnected:
			f.unreachable[c.ID] = &promproxy.NotConnectedError{
				ClusterID: c.ID, LastSeen: c.LastSeen, Since: testNow.Sub(c.LastSeen),
			}
		case fleet.StateDegraded:
			f.unreachable[c.ID] = fmt.Errorf("cluster %s: %w: %s",
				c.ID, promproxy.ErrUpstream, c.Prometheus.UnreachableReason)
		}
	}
	for endpoint, file := range map[promapi.Endpoint]string{
		promapi.EndpointQuery:       "query.json",
		promapi.EndpointQueryRange:  "query_range.json",
		promapi.EndpointSeries:      "series.json",
		promapi.EndpointLabels:      "labels.json",
		promapi.EndpointMetadata:    "metadata.json",
		promapi.EndpointTargets:     "targets.json",
		promapi.EndpointRules:       "rules.json",
		promapi.EndpointAlerts:      "alerts.json",
		promapi.EndpointTSDBStatus:  "status_tsdb.json",
		promapi.EndpointRuntimeInfo: "status_runtimeinfo.json",
		promapi.EndpointBuildInfo:   "status_buildinfo.json",
		promapi.EndpointFlags:       "status_flags.json",
	} {
		f.responses[string(endpoint)] = fakeResponse{body: fixture(t, file)}
	}
	f.responses[string(promapi.EndpointLabelValues)+"/__name__"] =
		fakeResponse{body: fixture(t, "label_values___name__.json")}
	f.responses[string(promapi.EndpointLabelValues)+"/job"] =
		fakeResponse{body: fixture(t, "label_values_job.json")}
	f.responses[string(promapi.EndpointLabelValues)] =
		fakeResponse{body: []byte(`{"status":"success","data":[]}`)}
	return f
}

// set installs a response under an explicit key.
func (f *fakeProm) set(key string, r fakeResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[key] = r
}

// Do implements [Prometheus].
func (f *fakeProm) Do(
	ctx context.Context, p *fleet.Principal, call promproxy.Call,
) (*promproxy.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	deny := f.denyClusters[call.ClusterID]
	down := f.unreachable[call.ClusterID]
	r, ok := f.lookupLocked(call)
	f.mu.Unlock()

	if deny {
		return nil, fmt.Errorf("cluster %s: %w", call.ClusterID, promproxy.ErrForbidden)
	}
	if p == nil || p.Scope == nil {
		return nil, fmt.Errorf("cluster %s: %w", call.ClusterID, promproxy.ErrForbidden)
	}
	if !p.Scope.AllowsCluster(call.ClusterID, nil) {
		// The real proxy re-checks the cluster scope; so does the fake, so a
		// test cannot pass by relying on the tool layer's check alone.
		return nil, fmt.Errorf("cluster %s: %w", call.ClusterID, promproxy.ErrForbidden)
	}
	if down != nil {
		return nil, down
	}
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("cluster %s: %w", call.ClusterID, ctx.Err())
		case <-timer.C:
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if !ok {
		return nil, fmt.Errorf("cluster %s %s: %w: no fixture",
			call.ClusterID, call.Endpoint, promproxy.ErrUpstream)
	}
	status := r.status
	if status == 0 {
		status = 200
	}
	return &promproxy.Result{
		Body:    r.body,
		Status:  status,
		Bytes:   int64(len(r.body)),
		Latency: 3 * time.Millisecond,
	}, nil
}

// lookupLocked resolves the most specific configured response.
func (f *fakeProm) lookupLocked(call promproxy.Call) (fakeResponse, bool) {
	ep := string(call.Endpoint)
	keys := []string{
		call.ClusterID + "/" + ep + "/" + call.LabelName,
		call.ClusterID + "/" + ep,
		ep + "/" + call.LabelName,
		ep,
	}
	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			continue
		}
		if r, ok := f.responses[k]; ok {
			return r, true
		}
	}
	return fakeResponse{}, false
}

// endpoints returns the endpoints the fake was asked for, in order.
func (f *fakeProm) endpoints() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, string(c.Endpoint))
	}
	return out
}

// lastForm returns the form of the last call to an endpoint.
func (f *fakeProm) lastForm(e promapi.Endpoint) map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].Endpoint == e {
			return f.calls[i].Form
		}
	}
	return nil
}

// fakeClusters is a [Clusters] over a fixed list.
type fakeClusters struct {
	entries []fleet.Cluster
}

// Visible implements [Clusters].
func (f *fakeClusters) Visible(p *fleet.Principal) []fleet.Cluster {
	if p == nil || p.Scope == nil {
		return nil
	}
	out := make([]fleet.Cluster, 0, len(f.entries))
	for _, c := range f.entries {
		if p.Scope.AllowsCluster(c.ID, c.Labels) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b fleet.Cluster) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Cluster implements [Clusters].
func (f *fakeClusters) Cluster(id string) (fleet.Cluster, bool) {
	for _, c := range f.entries {
		if c.ID == id {
			return c, true
		}
	}
	return fleet.Cluster{}, false
}

// Nearest implements [Clusters]. It mirrors the real registry: it ranges over
// every known cluster, leaving visibility filtering to the caller.
func (f *fakeClusters) Nearest(id string, n int) []string {
	if n <= 0 {
		return nil
	}
	type scored struct {
		id string
		d  int
	}
	cands := make([]scored, 0, len(f.entries))
	for _, c := range f.entries {
		cands = append(cands, scored{
			id: c.ID,
			d:  editDistance([]rune(strings.ToLower(id)), []rune(strings.ToLower(c.ID))),
		})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].d != cands[j].d {
			return cands[i].d < cands[j].d
		}
		return cands[i].id < cands[j].id
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.id
	}
	return out
}

// countingMetrics records what the instrumentation was told.
type countingMetrics struct {
	mu    sync.Mutex
	calls map[string]int
}

// ToolCall implements [Metrics].
func (m *countingMetrics) ToolCall(tool, result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls == nil {
		m.calls = map[string]int{}
	}
	m.calls[tool+"/"+result]++
}

// ToolDuration implements [Metrics].
func (m *countingMetrics) ToolDuration(string, time.Duration) {}

// count reports how many times a tool produced a result.
func (m *countingMetrics) count(tool, result string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[tool+"/"+result]
}

// testNow is the clock every test runs against, so relative times and staleness
// thresholds are deterministic.
var testNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// testClusters is the fixture fleet.
func testClusters() []fleet.Cluster {
	return []fleet.Cluster{
		{
			ID:           "eu-west-prod-1",
			DisplayName:  "EU West Production",
			Description:  "customer-facing API tier",
			Labels:       map[string]string{"env": "prod", "region": "eu-west"},
			State:        fleet.StateConnected,
			LastSeen:     testNow.Add(-30 * time.Second),
			AgentVersion: "1.2.3",
			Prometheus: fleet.PrometheusInfo{
				Reachable: true, Flavor: "prometheus", Version: "3.6.0",
				Retention: "15d", ScrapeInterval: "30s", LookbackDelta: "5m",
				ActiveSeries: 482913, MetricNames: 2211,
				ExternalLabels: map[string]string{"cluster": "eu-west-prod-1"},
				Jobs:           []string{"apiserver", "kubelet", "node-exporter", "prometheus"},
				Namespaces:     []string{"default", "kube-system", "monitoring"},
				MetricPrefixes: []string{"kube_", "container_", "node_", "apiserver_"},
				RuleGroups:     12, AlertingRules: 84, FiringAlerts: 2,
				HasAlertmanager: true,
			},
		},
		{
			ID:       "us-east-prod-2",
			Labels:   map[string]string{"env": "prod", "region": "us-east"},
			State:    fleet.StateConnected,
			LastSeen: testNow.Add(-45 * time.Second),
			Prometheus: fleet.PrometheusInfo{
				Reachable: true, Version: "3.5.1", ScrapeInterval: "15s",
				ActiveSeries: 190000, Jobs: []string{"kubelet"}, FiringAlerts: 1,
			},
		},
		{
			ID:       "ap-south-stage-1",
			Labels:   map[string]string{"env": "stage", "region": "ap-south"},
			State:    fleet.StateDisconnected,
			LastSeen: testNow.Add(-2 * time.Hour),
			Prometheus: fleet.PrometheusInfo{
				Reachable: false, UnreachableReason: "dial tcp: connection refused",
			},
		},
		{
			ID:       "degraded-1",
			Labels:   map[string]string{"env": "stage"},
			State:    fleet.StateDegraded,
			LastSeen: testNow.Add(-10 * time.Minute),
			Prometheus: fleet.PrometheusInfo{
				Reachable: false, UnreachableReason: "context deadline exceeded",
			},
		},
	}
}

// fullScope authorises every cluster and every tool.
func fullScope() *fleet.Scope {
	return &fleet.Scope{
		Role:     fleet.RoleOperator,
		Clusters: fleet.ClusterScope{Allow: []string{"*"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	}
}

// principal builds a test principal with the given scope.
func principal(s *fleet.Scope) *fleet.Principal {
	return &fleet.Principal{KID: "kid-test", Name: "test", Class: fleet.ClassAgent,
		Role: fleet.RoleOperator, Scope: s}
}

// harness bundles a Tools with the fakes behind it.
type harness struct {
	tools    *Tools
	prom     *fakeProm
	clusters *fakeClusters
	metrics  *countingMetrics
	p        *fleet.Principal
}

// newHarness builds a Tools over the fixture fleet and the fixture responses.
func newHarness(t *testing.T, opts ...func(*Options)) *harness {
	t.Helper()
	prom := newFakeProm(t)
	clusters := &fakeClusters{entries: testClusters()}
	metrics := &countingMetrics{}
	o := Options{
		Prometheus: prom,
		Clusters:   clusters,
		Metrics:    metrics,
		Clock:      func() time.Time { return testNow },
	}
	for _, f := range opts {
		f(&o)
	}
	tools, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{
		tools: tools, prom: prom, clusters: clusters, metrics: metrics,
		p: principal(fullScope()),
	}
}

// request builds the tool request a handler sees.
func request(tool string, p *fleet.Principal) *mcpsurface.Request {
	return &mcpsurface.Request{
		ToolName: tool,
		Token:    &mcpsurface.TokenInfo{Subject: "kid-test", Principal: p},
	}
}

// mustJSON marshals a value or fails the test.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// ctx returns a context bounded by the test's own deadline.
func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}
