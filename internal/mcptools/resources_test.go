// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
)

// resourceRequest builds the request a resource handler sees.
func resourceRequest(uri string, p *fleet.Principal) *mcpsurface.ResourceRequest {
	return &mcpsurface.ResourceRequest{
		URI:   uri,
		Token: &mcpsurface.TokenInfo{Subject: "kid-test", Principal: p},
	}
}

// TestResourceClusters covers fleet://clusters.
func TestResourceClusters(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got, err := h.tools.readClusters(ctx(t), resourceRequest(ResourceClusters, h.p))
	if err != nil {
		t.Fatalf("readClusters: %v", err)
	}
	if got.MIMEType != mcpsurface.MIMETypeJSON {
		t.Errorf("mimeType = %q", got.MIMEType)
	}
	var out ListClustersOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("resource body is not the list_clusters payload: %v", err)
	}
	if len(out.Clusters) != 4 {
		t.Errorf("clusters = %d, want 4", len(out.Clusters))
	}
	if out.Untrusted == "" {
		t.Error("no untrusted notice on a resource carrying remote data")
	}
}

// TestResourceCluster covers the fleet://clusters/{name} template, including
// the substitution the client performs.
func TestResourceCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got, err := h.tools.readCluster(ctx(t),
		resourceRequest("fleet://clusters/"+okCluster, h.p))
	if err != nil {
		t.Fatalf("readCluster: %v", err)
	}
	var out DescribeClusterOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("resource body is not the describe_cluster payload: %v", err)
	}
	if out.Name != okCluster || len(out.Jobs) == 0 {
		t.Errorf("out = %+v", out)
	}

	if _, err := h.tools.readCluster(ctx(t),
		resourceRequest("fleet://clusters/no-such-cluster", h.p)); err == nil {
		t.Error("an unknown cluster resource read succeeded")
	}
}

// TestResourceFiringAlerts covers the fleet-wide alert resource, including its
// coverage accounting.
func TestResourceFiringAlerts(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got, err := h.tools.readFiringAlerts(ctx(t), resourceRequest(ResourceFiringAlerts, h.p))
	if err != nil {
		t.Fatalf("readFiringAlerts: %v", err)
	}
	var out FleetAlertsOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("resource body: %v", err)
	}
	// Two clusters are connected and two are not, so coverage is partial and
	// must say so rather than presenting a partial fleet as the whole one.
	if out.Coverage.Requested != 4 || out.Coverage.OK != 2 || out.Coverage.Failed != 2 {
		t.Fatalf("coverage = %+v", out.Coverage)
	}
	if out.Coverage.Complete {
		t.Error("coverage claims completeness")
	}
	if !strings.HasPrefix(out.Preamble, "Partial result: 2 of 4 clusters.") {
		t.Errorf("preamble = %q", out.Preamble)
	}
	if len(out.Failed) != 2 {
		t.Errorf("failed = %+v", out.Failed)
	}
	if len(out.Alerts) == 0 {
		t.Fatal("no alerts")
	}
	for _, a := range out.Alerts {
		if a.Cluster == "" {
			t.Error("an alert carries no cluster")
		}
		if a.Alert.State != AlertFiring {
			t.Errorf("a %q alert reached the firing resource", a.Alert.State)
		}
	}
	// Critical and firing sort first so a truncated list keeps what matters.
	for i := 1; i < len(out.Alerts); i++ {
		if alertRank(out.Alerts[i].Alert) < alertRank(out.Alerts[i-1].Alert) {
			t.Fatalf("alerts are not ranked: %+v", out.Alerts)
		}
	}
}

// TestResourceFiringAlertsComplete covers the all-answered preamble.
func TestResourceFiringAlertsComplete(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	narrow := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: connectedClusters},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
	got, err := h.tools.readFiringAlerts(ctx(t), resourceRequest(ResourceFiringAlerts, narrow))
	if err != nil {
		t.Fatalf("readFiringAlerts: %v", err)
	}
	var out FleetAlertsOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("resource body: %v", err)
	}
	if !out.Coverage.Complete || !strings.HasPrefix(out.Preamble, "Complete result") {
		t.Errorf("coverage = %+v preamble = %q", out.Coverage, out.Preamble)
	}
}

// TestResourceFiringAlertsAlertnameTieBreak covers the sort's final
// tie-break: two alerts on the *same* cluster with equal rank (state and
// severity) fall back to comparing alertname. The multi-cluster fixture in
// TestResourceFiringAlerts always resolves ties on the cluster comparison
// first, so this branch needs alerts confined to a single cluster.
func TestResourceFiringAlertsAlertnameTieBreak(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlerts), fakeResponse{
		body: []byte(`{"status":"success","data":{"alerts":[
			{"labels":{"alertname":"ZLast","severity":"critical"},"annotations":{},
			 "state":"firing","activeAt":"2026-08-26T10:00:00Z","value":"1"},
			{"labels":{"alertname":"AFirst","severity":"critical"},"annotations":{},
			 "state":"firing","activeAt":"2026-08-26T10:00:00Z","value":"1"}
		]}}`),
	})
	single := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{okCluster}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
	got, err := h.tools.readFiringAlerts(ctx(t), resourceRequest(ResourceFiringAlerts, single))
	if err != nil {
		t.Fatalf("readFiringAlerts: %v", err)
	}
	var out FleetAlertsOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("resource body: %v", err)
	}
	if len(out.Alerts) != 2 {
		t.Fatalf("alerts = %+v, want 2 on one cluster", out.Alerts)
	}
	if out.Alerts[0].Alert.Alertname != "AFirst" || out.Alerts[1].Alert.Alertname != "ZLast" {
		t.Errorf("alerts sorted as %q then %q, want the alertname tie-break to order them "+
			"alphabetically", out.Alerts[0].Alert.Alertname, out.Alerts[1].Alert.Alertname)
	}
}

// TestResourceFiringAlertsClusterTieBreak proves that when two alerts from
// different clusters share both a rank (state and severity) and an
// alertname, the cluster name breaks the tie in the stable sort — the step
// between the rank compare and the final alertname compare.
func TestResourceFiringAlertsClusterTieBreak(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	sameAlert := []byte(`{"status":"success","data":{"alerts":[
		{"labels":{"alertname":"SameName","severity":"critical"},"annotations":{},
		 "state":"firing","activeAt":"2026-08-26T10:00:00Z","value":"1"}
	]}}`)
	h.prom.set("eu-west-prod-1/"+string(promapi.EndpointAlerts), fakeResponse{body: sameAlert})
	h.prom.set("us-east-prod-2/"+string(promapi.EndpointAlerts), fakeResponse{body: sameAlert})

	got, err := h.tools.readFiringAlerts(ctx(t), resourceRequest(ResourceFiringAlerts, h.p))
	if err != nil {
		t.Fatalf("readFiringAlerts: %v", err)
	}
	var out FleetAlertsOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("resource body: %v", err)
	}
	var clusters []string
	for _, a := range out.Alerts {
		if a.Alert.Alertname == "SameName" {
			clusters = append(clusters, a.Cluster)
		}
	}
	if len(clusters) != 2 || clusters[0] != "eu-west-prod-1" || clusters[1] != "us-east-prod-2" {
		t.Errorf("clusters = %v, want the identical-rank pair tie-broken by cluster name", clusters)
	}
}

// TestResourceCheatsheet covers the static document.
func TestResourceCheatsheet(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got, err := h.tools.readCheatsheet(ctx(t), resourceRequest(ResourceCheatsheet, h.p))
	if err != nil {
		t.Fatalf("readCheatsheet: %v", err)
	}
	if got.MIMEType != mcpsurface.MIMETypeMarkdown {
		t.Errorf("mimeType = %q", got.MIMEType)
	}
	// The document exists to stop the agent guessing at the conventions it
	// cannot infer, so those must actually be in it.
	for _, want := range []string{
		"now-6h", "downsampled", "hub_token_ceiling", "top_20_by_max",
		"compact", "coverage.complete", "_untrusted", "predict_linear",
	} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("cheatsheet does not document %q", want)
		}
	}
}

// TestResourceScopeIsEnforced proves a resource is not a way around the tool
// scope whose payload it mirrors.
func TestResourceScopeIsEnforced(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uri  string
		tool string
		read func(*Tools) mcpsurface.ResourceFunc
	}{
		{
			name: "clusters", uri: ResourceClusters, tool: ToolListClusters,
			read: func(t *Tools) mcpsurface.ResourceFunc { return t.readClusters },
		},
		{
			name: "cluster", uri: "fleet://clusters/" + okCluster, tool: ToolDescribeCluster,
			read: func(t *Tools) mcpsurface.ResourceFunc { return t.readCluster },
		},
		{
			name: "firing alerts", uri: ResourceFiringAlerts, tool: ToolAlerts,
			read: func(t *Tools) mcpsurface.ResourceFunc { return t.readFiringAlerts },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			// A scope with every tool except the one this resource mirrors.
			allow := make([]string, 0, len(toolNames))
			for _, n := range toolNames {
				if n != tc.tool {
					allow = append(allow, n)
				}
			}
			p := principal(&fleet.Scope{
				Role:     fleet.RoleViewer,
				Clusters: fleet.ClusterScope{Allow: []string{"*"}},
				Tools:    fleet.ToolScope{Allow: allow},
			})
			_, err := tc.read(h.tools)(ctx(t), resourceRequest(tc.uri, p))
			if err == nil {
				t.Fatal("an out-of-scope resource read succeeded")
			}
			code, ok := mcpsurface.ErrorCode(err)
			if !ok || code != mcpsurface.CodeForbidden {
				t.Errorf("err = %v (code %d), want a forbidden protocol error", err, code)
			}

			// And with no principal at all.
			_, err = tc.read(h.tools)(ctx(t), &mcpsurface.ResourceRequest{URI: tc.uri})
			code, ok = mcpsurface.ErrorCode(err)
			if !ok || code != mcpsurface.CodeUnauthenticated {
				t.Errorf("unauthenticated err = %v (code %d)", err, code)
			}
		})
	}
}

// TestResourceListClustersFailure covers the error path of the clusters
// resource, which cannot be reached through its own arguments.
func TestResourceListClustersFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlerts),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	got, err := h.tools.readFiringAlerts(ctx(t), resourceRequest(ResourceFiringAlerts, h.p))
	if err != nil {
		t.Fatalf("readFiringAlerts: %v", err)
	}
	var out FleetAlertsOut
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Coverage.OK != 0 || out.Coverage.Failed != 4 {
		t.Errorf("coverage = %+v", out.Coverage)
	}
}

// TestPrompts covers every prompt's rendering, its required arguments and the
// token discipline each one must carry.
func TestPrompts(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	tests := []struct {
		name     string
		fn       mcpsurface.PromptFunc
		args     map[string]string
		wantErr  bool
		contains []string
	}{
		{
			name: PromptInvestigateAlert, fn: h.tools.investigateAlert,
			args:     map[string]string{"cluster": okCluster, "alertname": "KubePodCrashLooping"},
			contains: []string{"alerts(", "rules(", "query_range(", "targets(", "KubePodCrashLooping"},
		},
		{
			name: PromptInvestigateAlert + "/missing cluster", fn: h.tools.investigateAlert,
			args: map[string]string{"alertname": "X"}, wantErr: true,
		},
		{
			name: PromptInvestigateAlert + "/missing alertname", fn: h.tools.investigateAlert,
			args: map[string]string{"cluster": okCluster}, wantErr: true,
		},
		{
			name: PromptCardinalityHotspot, fn: h.tools.cardinalityHotspot,
			args:     map[string]string{"cluster": okCluster, "topN": "50"},
			contains: []string{"tsdb_stats(", "label_values(", "metric_relabel_configs", "50"},
		},
		{
			name: PromptCardinalityHotspot + "/missing cluster", fn: h.tools.cardinalityHotspot,
			args: map[string]string{}, wantErr: true,
		},
		{
			name: PromptCompareClusters, fn: h.tools.compareClusters,
			args: map[string]string{"query": "sum(up)", "clusters": "a, b"},
			contains: []string{"explain_promql(", "fanout_query(",
				`clusters: ["a", "b"]`, "coverage.complete", "cluster_original"},
		},
		{
			name: PromptCompareClusters + "/by selector", fn: h.tools.compareClusters,
			args:     map[string]string{"query": "sum(up)", "labelSelector": "env=prod,region=eu"},
			contains: []string{`labelSelector: {"env": "prod", "region": "eu"}`},
		},
		{
			name: PromptCompareClusters + "/missing query", fn: h.tools.compareClusters,
			args: map[string]string{}, wantErr: true,
		},
		{
			name: PromptCapacityCheck, fn: h.tools.capacityCheck,
			args:     map[string]string{"cluster": okCluster, "resource": "disk", "horizon": "14d"},
			contains: []string{"predict_linear", "disk", "14d", "describe_cluster("},
		},
		{
			name: PromptCapacityCheck + "/missing cluster", fn: h.tools.capacityCheck,
			args: map[string]string{}, wantErr: true,
		},
		{
			name: PromptFleetHealthSweep, fn: h.tools.fleetHealthSweep,
			args:     map[string]string{},
			contains: []string{`list_clusters(status: "all")`, "blast radius", "unreachable"},
		},
		{
			name: PromptFleetHealthSweep + "/with selector", fn: h.tools.fleetHealthSweep,
			args:     map[string]string{"labelSelector": "env=prod"},
			contains: []string{`labelSelector: {"env": "prod"}`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := tc.fn(ctx(t), tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("a missing required argument was accepted")
				}
				if code, ok := mcpsurface.ErrorCode(err); !ok ||
					code != mcpsurface.CodeInvalidParams {
					t.Errorf("err = %v (code %d), want invalid params", err, code)
				}
				return
			}
			if err != nil {
				t.Fatalf("prompt: %v", err)
			}
			if len(res.Messages) != 1 || res.Messages[0].Role != mcpsurface.RoleUser {
				t.Fatalf("messages = %+v", res.Messages)
			}
			body := res.Messages[0].Text
			for _, want := range tc.contains {
				if !strings.Contains(body, want) {
					t.Errorf("prompt body does not mention %q:\n%s", want, body)
				}
			}
			// Every prompt teaches the cost discipline in its own text: a model
			// that read a tool description three calls ago will not remember it.
			if !strings.Contains(body, tokenDiscipline) {
				t.Error("prompt does not embed the token discipline")
			}
			if res.Description == "" {
				t.Error("prompt has no description")
			}
		})
	}
}

// TestPromptDefaults covers the defaulted arguments.
func TestPromptDefaults(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	res, err := h.tools.investigateAlert(ctx(t),
		map[string]string{"cluster": okCluster, "alertname": "X"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Messages[0].Text, "now-1h") {
		t.Error("since did not default to 1h")
	}
	res, err = h.tools.capacityCheck(ctx(t), map[string]string{"cluster": okCluster})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Messages[0].Text, "cpu") ||
		!strings.Contains(res.Messages[0].Text, "7d") {
		t.Error("resource and horizon did not default")
	}
}

// TestKVPairs covers the selector argument parser.
func TestKVPairs(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{in: "env=prod", want: `"env": "prod"`},
		{in: " env = prod , region=eu ", want: `"env": "prod", "region": "eu"`},
		{in: "novalue", want: ""},
		{in: "=orphan", want: ""},
		{in: "", want: ""},
	}
	for _, tc := range tests {
		if got := kvPairs(tc.in); got != tc.want {
			t.Errorf("kvPairs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResourceURIs pins the published URIs.
func TestResourceURIs(t *testing.T) {
	t.Parallel()
	want := []string{
		"fleet://clusters", "fleet://clusters/{name}",
		"fleet://alerts/firing", "fleet://promql/cheatsheet",
	}
	if diff := cmp.Diff(want, ResourceURIs()); diff != "" {
		t.Errorf("ResourceURIs (-want +got):\n%s", diff)
	}
}
