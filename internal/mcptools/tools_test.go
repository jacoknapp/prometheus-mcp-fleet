// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

const okCluster = "eu-west-prod-1"

// TestScopeDeniesEveryTool proves the first of the two independent
// authorization checks. A credential whose scope omits a tool must be refused
// as a *protocol* error before any argument is examined: a model that receives
// "forbidden" as tool output tries to fix it by rewriting its PromQL.
func TestScopeDeniesEveryTool(t *testing.T) {
	t.Parallel()

	// A scope that allows every tool except the one under test, so the test
	// cannot pass by accident on an empty allow-list.
	scopeExcept := func(name string) *fleet.Scope {
		allow := make([]string, 0, len(toolNames))
		for _, n := range toolNames {
			if n != name {
				allow = append(allow, n)
			}
		}
		return &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"*"}},
			Tools:    fleet.ToolScope{Allow: allow},
		}
	}

	for _, name := range ToolNames() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			p := principal(scopeExcept(name))
			err := callTool(t, h, name, p)
			if err == nil {
				t.Fatal("out-of-scope call succeeded")
			}
			code, ok := mcpsurface.ErrorCode(err)
			if !ok {
				t.Fatalf("scope denial was not a protocol error: %v", err)
			}
			if code != mcpsurface.CodeForbidden {
				t.Errorf("code = %d, want %d (forbidden)", code, mcpsurface.CodeForbidden)
			}
			if h.metrics.count(name, "FORBIDDEN") != 1 {
				t.Error("denial was not counted")
			}
			if got := len(h.prom.calls); got != 0 {
				t.Errorf("%d upstream calls made for a denied tool, want 0", got)
			}
		})
	}
}

// TestRoleTierGatesOperationalTools proves the second authorization check: a
// viewer's "*" wildcard does not include the operational surfaces, an operator
// role does, and naming the tool in tools.allow overrides the tier for either.
// Non-operational tools are untouched by role entirely.
func TestRoleTierGatesOperationalTools(t *testing.T) {
	t.Parallel()

	scope := func(role fleet.Role, allow ...string) *fleet.Scope {
		return &fleet.Scope{
			Role:     role,
			Clusters: fleet.ClusterScope{Allow: []string{"*"}},
			Tools:    fleet.ToolScope{Allow: allow},
		}
	}

	for name := range operationalTools {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			t.Run("viewer wildcard is refused", func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				err := callTool(t, h, name, principal(scope(fleet.RoleViewer, "*")))
				code, ok := mcpsurface.ErrorCode(err)
				if !ok || code != mcpsurface.CodeForbidden {
					t.Fatalf("err = %v, want a forbidden protocol error", err)
				}
				if got := len(h.prom.calls); got != 0 {
					t.Errorf("%d upstream calls made for a role-denied tool, want 0", got)
				}
			})

			t.Run("viewer naming the tool is allowed", func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				if err := callTool(t, h, name, principal(scope(fleet.RoleViewer, name))); err != nil {
					if code, ok := mcpsurface.ErrorCode(err); ok && code == mcpsurface.CodeForbidden {
						t.Fatalf("an explicit by-name allow was refused: %v", err)
					}
				}
			})

			t.Run("operator wildcard is allowed", func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				if err := callTool(t, h, name, principal(scope(fleet.RoleOperator, "*"))); err != nil {
					if code, ok := mcpsurface.ErrorCode(err); ok && code == mcpsurface.CodeForbidden {
						t.Fatalf("an operator wildcard was refused: %v", err)
					}
				}
			})
		})
	}

	t.Run("a viewer wildcard still reaches a non-operational tool", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		if err := callTool(t, h, ToolListClusters, principal(scope(fleet.RoleViewer, "*"))); err != nil {
			if code, ok := mcpsurface.ErrorCode(err); ok && code == mcpsurface.CodeForbidden {
				t.Fatalf("role tier leaked onto a non-operational tool: %v", err)
			}
		}
	})
}

// TestUnauthenticatedIsProtocolError proves a missing principal never becomes a
// tool result either.
func TestUnauthenticatedIsProtocolError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	fn := run(h.tools, ToolListClusters,
		func() *ListClustersOut { return &ListClustersOut{} }, h.tools.listClusters)
	_, _, err := fn(ctx(t), &mcpsurface.Request{ToolName: ToolListClusters}, ListClustersIn{})
	code, ok := mcpsurface.ErrorCode(err)
	if !ok || code != mcpsurface.CodeUnauthenticated {
		t.Fatalf("err = %v (code %d, protocol %v), want unauthenticated protocol error",
			err, code, ok)
	}
}

// TestRunAttachesToolErrorToZeroResult covers run's own business-error path
// directly: a *ToolError from the wrapped function must produce a fresh zero
// result carrying that error, marked as an MCP tool error (not a protocol
// error) and counted under the error's own code rather than "ok". Every other
// test in this package calls a tool method directly and inspects the
// returned *ToolError itself, never through run, so this line of run was
// otherwise unexercised.
func TestRunAttachesToolErrorToZeroResult(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	fn := run(h.tools, ToolDescribeCluster,
		func() *DescribeClusterOut { return &DescribeClusterOut{} }, h.tools.describeCluster)
	out, res, err := fn(ctx(t), request(ToolDescribeCluster, h.p),
		DescribeClusterIn{Cluster: "no-such-cluster"})
	if err != nil {
		t.Fatalf("a business error became a Go error: %v", err)
	}
	if !res.IsError {
		t.Error("res.IsError is false for a tool that returned a *ToolError")
	}
	if out == nil {
		t.Fatal("nil result")
	}
	if out.Error == nil || out.Error.Code != CodeUnknownCluster {
		t.Errorf("out.Error = %+v, want UNKNOWN_CLUSTER", out.Error)
	}
	// setError clears Untrusted: an error body is text this project authored,
	// not remote data, and it must not carry the untrusted notice.
	if out.Untrusted != "" {
		t.Errorf("untrusted = %q, want cleared on an error result", out.Untrusted)
	}
	// The zero() factory built a fresh result rather than reusing whatever fn
	// partially populated before failing.
	if out.Name != "" || out.Prometheus.Version != "" {
		t.Errorf("out = %+v, want the zero value plus only the error", out)
	}
	if h.metrics.count(ToolDescribeCluster, CodeUnknownCluster) != 1 {
		t.Error("the failure was not counted under its own code")
	}
	if h.metrics.count(ToolDescribeCluster, "ok") != 0 {
		t.Error("a failed call was counted as ok")
	}
}

// callTool invokes one tool through the shared wrapper with minimally valid
// arguments, returning the wrapper's error.
func callTool(t *testing.T, h *harness, name string, p *fleet.Principal) error {
	t.Helper()
	c := ctx(t)
	req := request(name, p)
	var err error
	switch name {
	case ToolListClusters:
		_, _, err = run(h.tools, name, func() *ListClustersOut { return &ListClustersOut{} },
			h.tools.listClusters)(c, req, ListClustersIn{})
	case ToolDescribeCluster:
		_, _, err = run(h.tools, name, func() *DescribeClusterOut { return &DescribeClusterOut{} },
			h.tools.describeCluster)(c, req, DescribeClusterIn{Cluster: okCluster})
	case ToolQuery:
		_, _, err = run(h.tools, name, func() *QueryOut { return &QueryOut{} },
			h.tools.query)(c, req, QueryIn{Cluster: okCluster, Query: "up"})
	case ToolQueryRange:
		_, _, err = run(h.tools, name, func() *QueryRangeOut { return &QueryRangeOut{} },
			h.tools.queryRange)(c, req, QueryRangeIn{Cluster: okCluster, Query: "up"})
	case ToolExplainPromQL:
		_, _, err = run(h.tools, name, func() *ExplainPromQLOut { return &ExplainPromQLOut{} },
			h.tools.explainPromQL)(c, req, ExplainPromQLIn{Query: "up"})
	case ToolQueryExemplars:
		_, _, err = run(h.tools, name, func() *QueryExemplarsOut { return &QueryExemplarsOut{} },
			h.tools.queryExemplars)(c, req, QueryExemplarsIn{Cluster: okCluster, Query: "up"})
	case ToolSearchMetrics:
		_, _, err = run(h.tools, name, func() *SearchMetricsOut { return &SearchMetricsOut{} },
			h.tools.searchMetrics)(c, req, SearchMetricsIn{Cluster: okCluster, Pattern: "up"})
	case ToolMetricMetadata:
		_, _, err = run(h.tools, name, func() *MetricMetadataOut { return &MetricMetadataOut{} },
			h.tools.metricMetadata)(c, req, MetricMetadataIn{Cluster: okCluster})
	case ToolTargetMetadata:
		_, _, err = run(h.tools, name, func() *TargetMetadataOut { return &TargetMetadataOut{} },
			h.tools.targetMetadata)(c, req, TargetMetadataIn{Cluster: okCluster})
	case ToolSeries:
		_, _, err = run(h.tools, name, func() *SeriesOut { return &SeriesOut{} },
			h.tools.series)(c, req, SeriesIn{Cluster: okCluster, Matchers: []string{"up"}})
	case ToolLabelNames:
		_, _, err = run(h.tools, name, func() *LabelNamesOut { return &LabelNamesOut{} },
			h.tools.labelNames)(c, req, LabelNamesIn{Cluster: okCluster})
	case ToolLabelValues:
		_, _, err = run(h.tools, name, func() *LabelValuesOut { return &LabelValuesOut{} },
			h.tools.labelValues)(c, req, LabelValuesIn{Cluster: okCluster, Label: "job"})
	case ToolTargets:
		_, _, err = run(h.tools, name, func() *TargetsOut { return &TargetsOut{} },
			h.tools.targets)(c, req, TargetsIn{Cluster: okCluster})
	case ToolRules:
		_, _, err = run(h.tools, name, func() *RulesOut { return &RulesOut{} },
			h.tools.rules)(c, req, RulesIn{Cluster: okCluster})
	case ToolAlerts:
		_, _, err = run(h.tools, name, func() *AlertsOut { return &AlertsOut{} },
			h.tools.alerts)(c, req, AlertsIn{Cluster: okCluster})
	case ToolAlertmanagers:
		_, _, err = run(h.tools, name, func() *AlertmanagersOut { return &AlertmanagersOut{} },
			h.tools.alertmanagers)(c, req, AlertmanagersIn{Cluster: okCluster})
	case ToolTSDBStats:
		_, _, err = run(h.tools, name, func() *TSDBStatsOut { return &TSDBStatsOut{} },
			h.tools.tsdbStats)(c, req, TSDBStatsIn{Cluster: okCluster})
	case ToolRuntimeInfo:
		_, _, err = run(h.tools, name, func() *RuntimeInfoOut { return &RuntimeInfoOut{} },
			h.tools.runtimeInfo)(c, req, RuntimeInfoIn{Cluster: okCluster})
	case ToolFanoutQuery:
		_, _, err = run(h.tools, name, func() *FanoutQueryOut { return &FanoutQueryOut{} },
			h.tools.fanoutQuery)(c, req, FanoutQueryIn{Query: "up", Clusters: []string{okCluster}})
	default:
		t.Fatalf("callTool has no case for %q; a new tool was added without a denial test", name)
	}
	return err
}

// TestUnknownClusterDidYouMean covers the typo self-correction path.
func TestUnknownClusterDidYouMean(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cluster    string
		wantFirst  string
		wantNoneOf []string
	}{
		{name: "transposed", cluster: "eu-west-prod1", wantFirst: "eu-west-prod-1"},
		{name: "capitalised", cluster: "EU-WEST-PROD-1", wantFirst: "eu-west-prod-1"},
		{name: "wrong region", cluster: "us-east-prod-1", wantFirst: "us-east-prod-2"},
		{name: "nothing like it", cluster: "zzz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			_, terr := h.tools.describeCluster(ctx(t), h.p, DescribeClusterIn{Cluster: tc.cluster})
			if terr == nil {
				t.Fatal("unknown cluster did not error")
			}
			if terr.Code != CodeUnknownCluster {
				t.Fatalf("code = %s, want %s", terr.Code, CodeUnknownCluster)
			}
			if terr.Retryable == nil || *terr.Retryable {
				t.Error("an unknown cluster is not retryable")
			}
			if terr.Hint == "" {
				t.Error("no hint")
			}
			if terr.Input["cluster"] == nil {
				t.Error("the offending input was not echoed")
			}
			if len(terr.DidYouMean) > DidYouMeanCount {
				t.Errorf("didYouMean has %d entries, want at most %d",
					len(terr.DidYouMean), DidYouMeanCount)
			}
			if tc.wantFirst != "" {
				if len(terr.DidYouMean) == 0 || terr.DidYouMean[0] != tc.wantFirst {
					t.Errorf("didYouMean = %v, want %q first", terr.DidYouMean, tc.wantFirst)
				}
			}
		})
	}
}

// TestUnknownClusterDoesNotEnumerateFleet proves the did-you-mean list cannot
// be used to discover clusters the credential may not reach, and that a denied
// cluster is reported identically to one that does not exist.
func TestUnknownClusterDoesNotEnumerateFleet(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	narrow := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{"us-east-prod-2"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})

	_, terr := h.tools.describeCluster(ctx(t), narrow, DescribeClusterIn{Cluster: "eu-west-prod-2"})
	if terr == nil || terr.Code != CodeUnknownCluster {
		t.Fatalf("terr = %v, want UNKNOWN_CLUSTER", terr)
	}
	for _, s := range terr.DidYouMean {
		if s != "us-east-prod-2" {
			t.Errorf("didYouMean leaked %q, which this credential cannot reach", s)
		}
	}

	// A cluster that exists but is out of scope must produce the same code and
	// the same shape as one that does not exist at all.
	_, denied := h.tools.describeCluster(ctx(t), narrow, DescribeClusterIn{Cluster: okCluster})
	if denied == nil || denied.Code != CodeUnknownCluster {
		t.Fatalf("denied = %v, want UNKNOWN_CLUSTER for an out-of-scope cluster", denied)
	}
	// The two results must be identical in every field a caller could use to
	// distinguish "does not exist" from "exists but denied" — code, hint
	// wording and the suggestion list — not merely share a code.
	_, nonexistent := h.tools.describeCluster(ctx(t), narrow,
		DescribeClusterIn{Cluster: "totally-nonexistent-cluster"})
	if nonexistent == nil || nonexistent.Code != CodeUnknownCluster {
		t.Fatalf("nonexistent = %v, want UNKNOWN_CLUSTER", nonexistent)
	}
	if denied.Hint != nonexistent.Hint {
		t.Errorf("hint differs between denied and nonexistent: %q vs %q",
			denied.Hint, nonexistent.Hint)
	}
	if diff := cmp.Diff(nonexistent.DidYouMean, denied.DidYouMean); diff != "" {
		t.Errorf("didYouMean differs between denied and nonexistent (-nonexistent +denied):\n%s", diff)
	}
	if *denied.Retryable != *nonexistent.Retryable {
		t.Error("retryable differs between denied and nonexistent")
	}
}

// TestUnknownClusterEmptyVisibleScope covers the credential-can-see-nothing
// case: didYouMean must be empty (not merely short) and the hint must not
// dangle a promise of suggestions that were never offered. No other test
// principal has an empty Clusters.Allow, so this path — and the "else" branch
// of unknownCluster's hint choice — was otherwise unreached.
func TestUnknownClusterEmptyVisibleScope(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	blind := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{}, // no Allow, no MatchLabels: authorizes nothing.
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
	_, terr := h.tools.describeCluster(ctx(t), blind, DescribeClusterIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeUnknownCluster {
		t.Fatalf("terr = %v, want UNKNOWN_CLUSTER", terr)
	}
	if terr.DidYouMean != nil {
		t.Errorf("didYouMean = %v, want nil when the credential can see no clusters at all",
			terr.DidYouMean)
	}
	if strings.Contains(terr.Hint, "didYouMean") {
		t.Errorf("hint references didYouMean despite there being none: %q", terr.Hint)
	}
	if !strings.Contains(terr.Hint, "list_clusters") {
		t.Errorf("hint does not point at list_clusters: %q", terr.Hint)
	}
}

// TestUnknownClusterDidYouMeanCapsAtFive proves didYouMean stops at
// DidYouMeanCount even when more visible clusters are plausible neighbours,
// covering the loop's own break — every other did-you-mean test has too few
// clusters in the fleet to fill it.
func TestUnknownClusterDidYouMeanCapsAtFive(t *testing.T) {
	t.Parallel()
	entries := make([]fleet.Cluster, 0, 8)
	for _, suffix := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		entries = append(entries, fleet.Cluster{
			ID: "prod-" + suffix, State: fleet.StateConnected, LastSeen: testNow,
			Labels: map[string]string{"env": "prod"},
		})
	}
	big := &fakeClusters{entries: entries}
	h := newHarness(t, func(o *Options) { o.Clusters = big })
	p := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{"*"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
	terr := h.tools.unknownCluster(p, "prod-x")
	if len(terr.DidYouMean) != DidYouMeanCount {
		t.Fatalf("didYouMean = %v, want exactly %d entries", terr.DidYouMean, DidYouMeanCount)
	}
}

// TestListClusters covers filtering, the table encoding and the untrusted
// notice.
func TestListClusters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   ListClustersIn
		want []string
	}{
		{name: "all", in: ListClustersIn{},
			want: []string{"ap-south-stage-1", "degraded-1", "eu-west-prod-1", "us-east-prod-2"}},
		{name: "by label", in: ListClustersIn{LabelSelector: map[string]string{"env": "prod"}},
			want: []string{"eu-west-prod-1", "us-east-prod-2"}},
		{name: "by status healthy", in: ListClustersIn{Status: StatusHealthy},
			want: []string{"eu-west-prod-1", "us-east-prod-2"}},
		{name: "by status degraded", in: ListClustersIn{Status: StatusDegraded},
			want: []string{"degraded-1"}},
		{name: "by status unreachable", in: ListClustersIn{Status: StatusUnreachable},
			want: []string{"ap-south-stage-1"}},
		{name: "by filter", in: ListClustersIn{Filter: "EU-WEST"},
			want: []string{"eu-west-prod-1"}},
		{name: "by description", in: ListClustersIn{Filter: "customer-facing"},
			want: []string{"eu-west-prod-1"}},
		{name: "no match", in: ListClustersIn{Filter: "nothing"}, want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			out, terr := h.tools.listClusters(ctx(t), h.p, tc.in)
			if terr != nil {
				t.Fatalf("listClusters: %v", terr)
			}
			got := make([]string, 0, len(out.Clusters))
			for _, c := range out.Clusters {
				got = append(got, c.Name)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("clusters (-want +got):\n%s", diff)
			}
			if out.Untrusted != render.UntrustedNotice {
				t.Error("result carrying remote data has no untrusted notice")
			}
			if len(h.prom.calls) != 0 {
				t.Error("list_clusters made an upstream call; it must answer from cached facts")
			}
		})
	}
}

// TestListClustersDecisionComplete pins the facts an agent routes on, because
// a listing that forces a follow-up call defeats the point of the tool.
func TestListClustersDecisionComplete(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.listClusters(ctx(t), h.p, ListClustersIn{Filter: okCluster})
	if terr != nil {
		t.Fatalf("listClusters: %v", terr)
	}
	if len(out.Clusters) != 1 {
		t.Fatalf("got %d clusters, want 1", len(out.Clusters))
	}
	got := out.Clusters[0]
	want := ClusterSummary{
		Name:            okCluster,
		DisplayName:     "EU West Production",
		Description:     "customer-facing API tier",
		Status:          StatusHealthy,
		Labels:          map[string]string{"env": "prod", "region": "eu-west"},
		PromVersion:     "3.6.0",
		PromFlavor:      "prometheus",
		Retention:       "15d",
		ScrapeInterval:  "30s",
		ActiveSeries:    482913,
		JobCount:        4,
		AlertsFiring:    2,
		RuleGroups:      12,
		Alertmanager:    true,
		FactsAgeSeconds: 30,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("summary (-want +got):\n%s", diff)
	}
}

// TestListClustersTable checks the fixed-width encoding replaces the rows
// rather than duplicating them.
func TestListClustersTable(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.listClusters(ctx(t), h.p,
		ListClustersIn{Format: string(render.FormatTable)})
	if terr != nil {
		t.Fatalf("listClusters: %v", terr)
	}
	if out.Clusters != nil {
		t.Error("table format still carried the structured rows; the tokens are paid twice")
	}
	if !strings.Contains(out.Table, "NAME") || !strings.Contains(out.Table, okCluster) {
		t.Errorf("table looks wrong:\n%s", out.Table)
	}
	if _, terr := h.tools.listClusters(ctx(t), h.p,
		ListClustersIn{Format: "json"}); terr == nil {
		t.Error("format json was accepted by a tool with no upstream payload")
	}
}

// TestListClustersInvalidStatus covers the status validation the input
// schema's enum already forecloses for a real MCP client, but which remains
// live business logic for any direct caller of the Go method — the same
// defence describeCluster and friends apply to their own enum arguments.
func TestListClustersInvalidStatus(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.listClusters(ctx(t), h.p, ListClustersIn{Status: "bogus"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestListClustersTokenCeiling proves the hub's own token budget beats a
// listing that fits under limit but not under the ceiling.
func TestListClustersTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 40
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	out, terr := h.tools.listClusters(ctx(t), h.p, ListClustersIn{})
	if terr != nil {
		t.Fatalf("listClusters: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 4 {
		t.Errorf("total = %d, want the honest 4", out.Truncated.Total)
	}
}

// TestDescribeCluster covers the include sections and the staleness report.
func TestDescribeCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.describeCluster(ctx(t), h.p, DescribeClusterIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("describeCluster: %v", terr)
	}
	if out.Counts.ActiveSeries != 482913 || out.Counts.Jobs != 4 {
		t.Errorf("counts = %+v", out.Counts)
	}
	if diff := cmp.Diff([]string{"apiserver", "kubelet", "node-exporter", "prometheus"},
		out.Jobs); diff != "" {
		t.Errorf("jobs (-want +got):\n%s", diff)
	}
	if len(out.MetricPrefixes) != 4 {
		t.Errorf("metricPrefixes = %v", out.MetricPrefixes)
	}
	if out.Namespaces != nil {
		t.Error("namespaces returned without being requested")
	}
	if out.Alertmanager == nil || !out.Alertmanager.Present {
		t.Error("alertmanager section missing")
	}
	if out.Counts.RuleGroups != 12 || out.Counts.AlertingRules != 84 {
		t.Errorf("rule counts = %+v", out.Counts)
	}
	if out.Stale {
		t.Error("30-second-old facts were reported stale")
	}
	if len(h.prom.calls) != 0 {
		t.Error("describe_cluster made an upstream call")
	}

	full, terr := h.tools.describeCluster(ctx(t), h.p,
		DescribeClusterIn{Cluster: okCluster, Include: allIncludes})
	if terr != nil {
		t.Fatalf("describeCluster all: %v", terr)
	}
	if len(full.Namespaces) != 3 || full.Kubernetes == nil ||
		full.Prometheus.ExternalLabels["cluster"] != okCluster {
		t.Errorf("full include did not populate every section: %+v", full)
	}
}

// TestDescribeClusterStaleAndUnreachable covers the two facts-are-not-fresh
// paths, which call for different answers.
func TestDescribeClusterStaleAndUnreachable(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	out, terr := h.tools.describeCluster(ctx(t), h.p, DescribeClusterIn{Cluster: "degraded-1"})
	if terr != nil {
		t.Fatalf("degraded cluster errored: %v", terr)
	}
	if !out.Stale || out.StaleNotice == "" {
		t.Error("ten-minute-old facts were not reported stale")
	}
	if out.Status != StatusDegraded {
		t.Errorf("status = %q, want degraded", out.Status)
	}

	_, terr = h.tools.describeCluster(ctx(t), h.p, DescribeClusterIn{Cluster: "ap-south-stage-1"})
	if terr == nil || terr.Code != CodeSpokeUnreachable {
		t.Fatalf("terr = %v, want SPOKE_UNREACHABLE", terr)
	}
	if !strings.Contains(terr.Message, "ago") {
		t.Errorf("unreachable message does not say how long ago: %q", terr.Message)
	}
	if terr.Retryable == nil || !*terr.Retryable {
		t.Error("a disconnected spoke is retryable")
	}
}

// TestDescribeClusterBadInclude covers the closed-set check.
func TestDescribeClusterBadInclude(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.describeCluster(ctx(t), h.p,
		DescribeClusterIn{Cluster: okCluster, Include: []string{"everything"}})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestDescribeClusterTopNTruncation covers the per-section truncation marker.
func TestDescribeClusterTopNTruncation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.describeCluster(ctx(t), h.p,
		DescribeClusterIn{Cluster: okCluster, TopN: 2})
	if terr != nil {
		t.Fatalf("describeCluster: %v", terr)
	}
	if len(out.Jobs) != 2 {
		t.Errorf("jobs = %v, want 2", out.Jobs)
	}
	if out.Truncated == nil {
		t.Fatal("truncation was silent")
	}
	if out.Truncated.Total != 4 || out.Truncated.Returned != 2 {
		t.Errorf("truncation = %+v", out.Truncated)
	}
	if out.Truncated.Selection == "" || out.Truncated.Hint == "" {
		t.Error("truncation did not name its selection or a next action")
	}
}

// TestDescribeClusterKeepsLargerSectionOverflow proves that when topN cuts
// more than one section, the reported truncation names the section that lost
// the most entries, not simply the last one processed.
func TestDescribeClusterKeepsLargerSectionOverflow(t *testing.T) {
	t.Parallel()
	custom := testClusters()
	for i := range custom {
		if custom[i].ID != okCluster {
			continue
		}
		custom[i].Prometheus.Jobs = []string{"a", "b", "c"}
		custom[i].Prometheus.MetricPrefixes = []string{
			"p1_", "p2_", "p3_", "p4_", "p5_", "p6_", "p7_", "p8_", "p9_", "p10_",
		}
	}
	h := newHarness(t, func(o *Options) { o.Clusters = &fakeClusters{entries: custom} })

	out, terr := h.tools.describeCluster(ctx(t), h.p, DescribeClusterIn{Cluster: okCluster, TopN: 2})
	if terr != nil {
		t.Fatalf("describeCluster: %v", terr)
	}
	if out.Truncated == nil {
		t.Fatal("truncation was silent")
	}
	// Jobs overflowed by 1 (3 -> 2), metricPrefixes by 8 (10 -> 2): the
	// larger overflow must win regardless of processing order.
	if out.Truncated.Selection != "metricPrefixes_first_2" {
		t.Errorf("selection = %q, want the metricPrefixes section (larger overflow)",
			out.Truncated.Selection)
	}
	if out.Truncated.Total != 10 || out.Truncated.Returned != 2 {
		t.Errorf("truncation = %+v", out.Truncated)
	}
}

// TestDescribeClusterStaleBoundary pins the age > StaleFactsAfter boundary:
// facts exactly StaleFactsAfter old must not be reported stale, only facts
// strictly older than that.
func TestDescribeClusterStaleBoundary(t *testing.T) {
	t.Parallel()
	atBoundary := testClusters()
	pastBoundary := testClusters()
	for i := range atBoundary {
		if atBoundary[i].ID != okCluster {
			continue
		}
		atBoundary[i].LastSeen = testNow.Add(-StaleFactsAfter)
		pastBoundary[i].LastSeen = testNow.Add(-StaleFactsAfter - time.Nanosecond)
	}

	hAt := newHarness(t, func(o *Options) { o.Clusters = &fakeClusters{entries: atBoundary} })
	outAt, terr := hAt.tools.describeCluster(ctx(t), hAt.p, DescribeClusterIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("describeCluster: %v", terr)
	}
	if outAt.Stale {
		t.Errorf("Stale = true at age exactly StaleFactsAfter, want false")
	}

	hPast := newHarness(t, func(o *Options) { o.Clusters = &fakeClusters{entries: pastBoundary} })
	outPast, terr := hPast.tools.describeCluster(ctx(t), hPast.p, DescribeClusterIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("describeCluster: %v", terr)
	}
	if !outPast.Stale || outPast.StaleNotice == "" {
		t.Errorf("Stale = %v at age StaleFactsAfter+1ns, want true with a notice", outPast.Stale)
	}
}

// TestQueryInstant covers the columnar instant encoding and the time forms.
func TestQueryInstant(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up"})
	if terr != nil {
		t.Fatalf("query: %v", terr)
	}
	if out.ResultType != "vector" {
		t.Errorf("resultType = %q", out.ResultType)
	}
	if diff := cmp.Diff(render.InstantColumns, out.Columns); diff != "" {
		t.Errorf("columns (-want +got):\n%s", diff)
	}
	if len(out.Rows) != 2 || out.Total != 2 {
		t.Fatalf("rows = %d, total = %d, want 2 and 2", len(out.Rows), out.Total)
	}
	// Ranked by descending value: the up target must come before the down one.
	if got := mustJSON(t, out.Rows[0][2]); got != "1" {
		t.Errorf("first row value = %s, want the largest (1)", got)
	}
	// The labels common to both samples are factored out and paid for once.
	if out.SharedLabels["job"] != "node-exporter" {
		t.Errorf("sharedLabels = %v, want job factored out", out.SharedLabels)
	}
	if _, ok := out.Rows[0][1].(map[string]string)["job"]; ok {
		t.Error("a shared label was repeated on the row")
	}
	if out.Untrusted != render.UntrustedNotice {
		t.Error("no untrusted notice on a result carrying remote labels")
	}
}

// TestQueryTimeParsing covers relative and absolute times reaching the wire.
func TestQueryTimeParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		arg  string
		want time.Time
	}{
		{name: "default is now", arg: "", want: testNow},
		{name: "now", arg: "now", want: testNow},
		{name: "relative with now prefix", arg: "now-6h", want: testNow.Add(-6 * time.Hour)},
		{name: "bare relative", arg: "-15m", want: testNow.Add(-15 * time.Minute)},
		{name: "bare relative forward", arg: "+30m", want: testNow.Add(30 * time.Minute)},
		{name: "relative days", arg: "now-2d", want: testNow.Add(-48 * time.Hour)},
		{name: "rfc3339", arg: "2026-08-29T09:30:00Z",
			want: time.Date(2026, 8, 29, 9, 30, 0, 0, time.UTC)},
		{name: "rfc3339 fractional", arg: "2026-08-29T09:30:00.500Z",
			want: time.Date(2026, 8, 29, 9, 30, 0, 500000000, time.UTC)},
		{name: "unix seconds", arg: "1787047200",
			want: time.Unix(1787047200, 0).UTC()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			_, terr := h.tools.query(ctx(t), h.p,
				QueryIn{Cluster: okCluster, Query: "up", Time: tc.arg})
			if terr != nil {
				t.Fatalf("query: %v", terr)
			}
			form := h.prom.lastForm(promapi.EndpointQuery)
			if len(form["time"]) != 1 {
				t.Fatalf("no time parameter sent: %v", form)
			}
			want := formatUpstreamTime(tc.want)
			if form["time"][0] != want {
				t.Errorf("time sent upstream = %s, want %s", form["time"][0], want)
			}
		})
	}
}

// TestQueryBadTime covers the unparseable-time path and its hint.
func TestQueryBadTime(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, bad := range []string{"yesterday", "now-", "now-3x", "6h ago"} {
		_, terr := h.tools.query(ctx(t), h.p,
			QueryIn{Cluster: okCluster, Query: "up", Time: bad})
		if terr == nil || terr.Code != CodeInvalidTime {
			t.Errorf("time %q: terr = %v, want INVALID_TIME", bad, terr)
			continue
		}
		if !strings.Contains(terr.Hint, "now-6h") {
			t.Errorf("time %q: hint does not show the reliable form: %q", bad, terr.Hint)
		}
	}
}

// TestQueryPromQLParseError proves Prometheus' own message and a caret reach
// the agent.
func TestQueryPromQLParseError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		status: 400,
		body: []byte(`{"status":"error","errorType":"bad_data",` +
			`"error":"parse error at char 34: unexpected \"}\" in label matching, expected string"}`),
	})
	bad := `rate(http_requests_total{job=api}[5m])`
	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: bad})
	if terr == nil || terr.Code != CodePromQLParse {
		t.Fatalf("terr = %v, want PROMQL_PARSE", terr)
	}
	if !strings.Contains(terr.Message, "unexpected") {
		t.Errorf("upstream message was not passed through: %q", terr.Message)
	}
	if terr.Caret == "" || strings.TrimSpace(terr.Caret) != "^" {
		t.Errorf("caret = %q", terr.Caret)
	}
	if len(terr.Caret) != 34 {
		t.Errorf("caret is %d characters, want 34 so it lands under char 34", len(terr.Caret))
	}
	if terr.Input["query"] != bad {
		t.Errorf("offending query was not echoed: %v", terr.Input)
	}
	if !strings.Contains(terr.Hint, "explain_promql") {
		t.Errorf("hint does not name the recovery call: %q", terr.Hint)
	}
	if terr.Retryable == nil || *terr.Retryable {
		t.Error("a parse error is not retryable")
	}
}

// TestQueryRangeAutoStep covers automatic step selection and the downsampled
// report, which is what stops a model reading averaged data as raw.
func TestQueryRangeAutoStep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		in         QueryRangeIn
		wantStep   string
		wantReason string
	}{
		{
			name:       "six hours snaps to five minutes",
			in:         QueryRangeIn{Start: "now-6h"},
			wantStep:   "5m",
			wantReason: render.StepReasonMaxPoints,
		},
		{
			name:       "one hour floors at the scrape interval",
			in:         QueryRangeIn{Start: "now-1h", MaxPoints: 500},
			wantStep:   "30s",
			wantReason: render.StepReasonScrapeInterval,
		},
		{
			name:       "requested step on the ladder is honoured",
			in:         QueryRangeIn{Start: "now-1h", Step: "5m"},
			wantStep:   "5m",
			wantReason: render.StepReasonRequested,
		},
		{
			name:       "requested step off the ladder snaps up",
			in:         QueryRangeIn{Start: "now-1h", Step: "2m"},
			wantStep:   "5m",
			wantReason: render.StepReasonLadder,
		},
		{
			name:       "a day at the default budget",
			in:         QueryRangeIn{Start: "now-24h"},
			wantStep:   "15m",
			wantReason: render.StepReasonMaxPoints,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			in := tc.in
			in.Cluster = okCluster
			in.Query = "up"
			out, terr := h.tools.queryRange(ctx(t), h.p, in)
			if terr != nil {
				t.Fatalf("queryRange: %v", terr)
			}
			if out.Downsampled == nil {
				t.Fatal("no downsampled report; an agent cannot tell raw from averaged")
			}
			if out.Downsampled.AppliedStep != tc.wantStep {
				t.Errorf("appliedStep = %q, want %q", out.Downsampled.AppliedStep, tc.wantStep)
			}
			if out.Downsampled.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", out.Downsampled.Reason, tc.wantReason)
			}
			want := tc.in.Step
			if want == "" {
				want = "auto"
			}
			if out.Downsampled.RequestedStep != want {
				t.Errorf("requestedStep = %q, want %q", out.Downsampled.RequestedStep, want)
			}
			form := h.prom.lastForm(promapi.EndpointQueryRange)
			if form["step"][0] != tc.wantStep {
				t.Errorf("step sent upstream = %s, want %s", form["step"][0], tc.wantStep)
			}
		})
	}
}

// TestQueryRangeColumnar checks the encoding an agent actually reads.
func TestQueryRangeColumnar(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// The fixture's samples run from 1787046900 at a one-minute spacing, so the
	// window is stated in the same Unix seconds the Prometheus API itself uses.
	out, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "up",
		Start: "1787046900", End: "1787047140", Step: "1m",
	})
	if terr != nil {
		t.Fatalf("queryRange: %v", terr)
	}
	if out.StepSeconds != 60 || out.Points != 5 {
		t.Errorf("stepSeconds = %v, points = %d, want 60 and 5", out.StepSeconds, out.Points)
	}
	if len(out.Series) != 1 {
		t.Fatalf("series = %d, want 1", len(out.Series))
	}
	if len(out.Series[0].Values) != out.Points {
		t.Errorf("values has %d entries, want %d", len(out.Series[0].Values), out.Points)
	}
	// Every label of a single series is common to it, so all of them factor out.
	if out.SharedLabels["job"] != "node-exporter" || out.Series[0].Labels != nil {
		t.Errorf("labels were not factored: shared=%v per-series=%v",
			out.SharedLabels, out.Series[0].Labels)
	}
	// The fixture's fourth sample is a zero and the rest are ones.
	encoded := mustJSON(t, out.Series[0].Values)
	if !strings.Contains(encoded, "0") || strings.Contains(encoded, `"`) {
		t.Errorf("values are not bare JSON numbers: %s", encoded)
	}
}

// TestQueryRangeTruncationSelectsTopN proves series truncation is explicit and
// keeps the largest series, naming the strategy it used.
func TestQueryRangeTruncationSelectsTopN(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: syntheticMatrix(t, 40, 10, testNow.Add(-10*time.Minute), time.Minute),
	})
	out, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "x", Start: "now-10m", Step: "1m", MaxSeries: 5,
	})
	if terr != nil {
		t.Fatalf("queryRange: %v", terr)
	}
	if len(out.Series) != 5 {
		t.Fatalf("series = %d, want 5", len(out.Series))
	}
	if out.Truncated == nil {
		t.Fatal("truncation was silent")
	}
	if out.Truncated.Reason != render.ReasonMaxSeries {
		t.Errorf("reason = %q, want %q", out.Truncated.Reason, render.ReasonMaxSeries)
	}
	if out.Truncated.Selection != "top_5_by_max" {
		t.Errorf("selection = %q, want top_5_by_max", out.Truncated.Selection)
	}
	if out.Truncated.Total != 40 || out.Truncated.Returned != 5 {
		t.Errorf("truncation = %+v", out.Truncated)
	}
	if !strings.Contains(out.Truncated.Hint, "sum by") {
		t.Errorf("hint does not suggest aggregating: %q", out.Truncated.Hint)
	}
	// Top-N by max: series i has max i, so the survivors are 39..35.
	for i, s := range out.Series {
		want := float64(39 - i)
		if s.Max == nil || *s.Max != want {
			t.Errorf("series %d max = %v, want %v (top-N by max is not ranking)", i, s.Max, want)
		}
	}
}

// TestHubTokenCeilingOverridesLimit is the guardrail that stops an agent
// blowing its own context by asking for it.
func TestHubTokenCeilingOverridesLimit(t *testing.T) {
	t.Parallel()
	const ceiling = 2000
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: syntheticMatrix(t, 200, 120, testNow.Add(-2*time.Hour), time.Minute),
	})
	out, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "x", Start: "now-2h", Step: "1m",
		// An explicit, maximal limit. The ceiling must beat it.
		MaxSeries: 200, MaxPoints: 500,
	})
	if terr != nil {
		t.Fatalf("queryRange: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
	if len(out.Series) >= 200 {
		t.Errorf("returned %d series despite the ceiling", len(out.Series))
	}
	if got := render.EstimateTokens(out); got > ceiling*2 {
		t.Errorf("result estimates %d tokens against a ceiling of %d", got, ceiling)
	}
	if !strings.Contains(out.Truncated.Hint, "regardless of") {
		t.Errorf("hint does not explain that limit cannot lift the ceiling: %q", out.Truncated.Hint)
	}
}

// TestTokenCeilingAppliesToPassthrough proves format "json" cannot be used to
// route around the ceiling.
func TestTokenCeilingAppliesToPassthrough(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.TokenCeiling = 500 })
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: syntheticMatrix(t, 100, 60, testNow.Add(-1*time.Hour), time.Minute),
	})
	out, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "x", Start: "now-1h", Step: "1m", Format: "json",
	})
	if terr != nil {
		t.Fatalf("queryRange: %v", terr)
	}
	if out.Raw != nil {
		t.Error("an oversized passthrough payload was returned anyway")
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v", out.Truncated)
	}
	if !strings.Contains(out.Truncated.Hint, "compact") {
		t.Errorf("hint does not point at the cheap encoding: %q", out.Truncated.Hint)
	}
}

// TestQueryRangeTooLarge covers the corrected argument object.
func TestQueryRangeTooLarge(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.MaxLookback = 24 * time.Hour })
	_, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "up", Start: "now-30d",
	})
	if terr == nil || terr.Code != CodeRangeTooLarge {
		t.Fatalf("terr = %v, want RANGE_TOO_LARGE", terr)
	}
	if terr.Corrected == nil {
		t.Fatal("no corrected argument object to copy")
	}
	if terr.Corrected["start"] != "now-1d" {
		t.Errorf("corrected start = %v, want now-1d", terr.Corrected["start"])
	}
	if terr.Corrected["cluster"] != okCluster || terr.Corrected["query"] != "up" {
		t.Errorf("corrected object is not a complete argument set: %v", terr.Corrected)
	}
	// The corrected object must actually work.
	fixed := QueryRangeIn{
		Cluster: fmt.Sprint(terr.Corrected["cluster"]),
		Query:   fmt.Sprint(terr.Corrected["query"]),
		Start:   fmt.Sprint(terr.Corrected["start"]),
		End:     fmt.Sprint(terr.Corrected["end"]),
	}
	if _, terr := h.tools.queryRange(ctx(t), h.p, fixed); terr != nil {
		t.Errorf("the corrected arguments still failed: %v", terr)
	}
}

// TestQueryRangeRejectsInvertedRange covers the end-before-start case.
func TestQueryRangeRejectsInvertedRange(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "up", Start: "now", End: "now-1h",
	})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestQueryRangeArgumentValidationErrors covers queryRange's own
// argument-validation call sites: format, an empty query, a malformed step
// and a malformed timeout. Each pure helper (parseFormat, validateExpr,
// ParseDuration) is unit-tested elsewhere, but queryRange's own "if err !=
// nil { return }" statements around each call were otherwise never reached.
func TestQueryRangeArgumentValidationErrors(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.queryRange(ctx(t), h.p,
		QueryRangeIn{Cluster: okCluster, Query: "up", Format: "yaml"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("bad format: terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.queryRange(ctx(t), h.p, QueryRangeIn{Cluster: okCluster, Query: ""})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("empty query: terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.queryRange(ctx(t), h.p,
		QueryRangeIn{Cluster: okCluster, Query: "up", Step: "not-a-duration"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Errorf("bad step: terr = %v, want INVALID_TIME", terr)
	}

	_, terr = h.tools.queryRange(ctx(t), h.p,
		QueryRangeIn{Cluster: okCluster, Query: "up", Timeout: "not-a-duration"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Errorf("bad timeout: terr = %v, want INVALID_TIME", terr)
	}
}

// TestQueryRangeBadStartAndEnd covers resolveRange's own two time-parsing
// error returns, including str()'s use to echo the cluster in the error's
// input even though the caller passes it through an `any` map.
func TestQueryRangeBadStartAndEnd(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.queryRange(ctx(t), h.p,
		QueryRangeIn{Cluster: okCluster, Query: "up", Start: "not-a-time"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("bad start: terr = %v, want INVALID_TIME", terr)
	}
	if terr.Input["cluster"] != okCluster {
		t.Errorf("bad start: input cluster = %v, want %q echoed via str()", terr.Input, okCluster)
	}
	if terr.Input["start"] != "not-a-time" {
		t.Errorf("bad start: input = %v, did not echo the offending value", terr.Input)
	}

	_, terr = h.tools.queryRange(ctx(t), h.p,
		QueryRangeIn{Cluster: okCluster, Query: "up", End: "not-a-time"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("bad end: terr = %v, want INVALID_TIME", terr)
	}
	if terr.Input["cluster"] != okCluster {
		t.Errorf("bad end: input cluster = %v, want %q echoed via str()", terr.Input, okCluster)
	}
}

// TestQueryRangeStartTooOldWithoutSpanTooLarge covers resolveRange's second
// RANGE_TOO_LARGE branch: a short window that is nonetheless far in the past,
// which is a different fault from TestQueryRangeTooLarge's over-wide span and
// takes a different corrected object (only start moves; end stays put).
func TestQueryRangeStartTooOldWithoutSpanTooLarge(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.MaxLookback = 24 * time.Hour })
	_, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{
		Cluster: okCluster, Query: "up", Start: "now-100h", End: "now-99h",
	})
	if terr == nil || terr.Code != CodeRangeTooLarge {
		t.Fatalf("terr = %v, want RANGE_TOO_LARGE", terr)
	}
	if !strings.Contains(terr.Message, "in the past") {
		t.Errorf("message = %q, want it to explain the fault is age, not span", terr.Message)
	}
	if terr.Corrected == nil || terr.Corrected["start"] != "now-1d" {
		t.Errorf("corrected = %v, want start moved to now-1d", terr.Corrected)
	}
	if _, hasEnd := terr.Corrected["end"]; hasEnd && terr.Corrected["end"] != "now-99h" {
		t.Errorf("corrected end = %v, want the caller's own end left alone", terr.Corrected["end"])
	}
}

// TestQueryRangeUpstreamFailure covers the fetch failure path directly on
// queryRange: TestUpstreamFailureMapping only ever drives it through query.
func TestQueryRangeUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryRange),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	_, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{Cluster: okCluster, Query: "up"})
	if terr == nil || terr.Code != CodeUpstreamError {
		t.Fatalf("terr = %v, want UPSTREAM_ERROR", terr)
	}
}

// TestQueryRangeMalformedResponseBody covers a well-formed envelope with no
// data member (DecodeQueryData) and a matrix result member that does not
// decode as a matrix (DecodeMatrix) — two distinct malformed-payload faults.
func TestQueryRangeMalformedResponseBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: []byte(`{"status":"success"}`),
	})
	_, terr := h.tools.queryRange(ctx(t), h.p, QueryRangeIn{Cluster: okCluster, Query: "up"})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("no-data body: terr = %v, want MALFORMED_UPSTREAM", terr)
	}

	h.prom.set(string(promapi.EndpointQueryRange), fakeResponse{
		body: []byte(`{"status":"success","data":{"resultType":"matrix","result":"not-an-array"}}`),
	})
	_, terr = h.tools.queryRange(ctx(t), h.p, QueryRangeIn{Cluster: okCluster, Query: "up"})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("bad matrix body: terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestQueryRangePassthroughFormatUnderCeiling covers format "json"'s success
// path on queryRange: a payload small enough to stay under the token ceiling
// is passed through verbatim. TestTokenCeilingAppliesToPassthrough only
// exercises the over-ceiling branch of this same block.
func TestQueryRangePassthroughFormatUnderCeiling(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.queryRange(ctx(t), h.p,
		QueryRangeIn{Cluster: okCluster, Query: "up", Format: "json"})
	if terr != nil {
		t.Fatalf("queryRange: %v", terr)
	}
	if out.Raw == nil {
		t.Fatal("format json returned no raw payload")
	}
	if out.Series != nil {
		t.Error("passthrough also carried the compact series; the tokens are paid twice")
	}
}

// TestQueryWrongResultType covers the two "you wanted the other tool" paths.
func TestQueryWrongResultType(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		body: fixture(t, "query_range.json"),
	})
	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up[5m]"})
	if terr == nil || !strings.Contains(terr.Hint, "query_range") {
		t.Fatalf("terr = %v, want a pointer at query_range", terr)
	}

	h2 := newHarness(t)
	h2.prom.set(string(promapi.EndpointQueryRange), fakeResponse{body: fixture(t, "query.json")})
	_, terr = h2.tools.queryRange(ctx(t), h2.p, QueryRangeIn{Cluster: okCluster, Query: "up"})
	if terr == nil || !strings.Contains(terr.Hint, "Call query") {
		t.Fatalf("terr = %v, want a pointer at query", terr)
	}
}

// TestQueryScalarAndString covers the non-vector instant results.
func TestQueryScalarAndString(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		body: []byte(`{"status":"success","data":{"resultType":"scalar",` +
			`"result":[1787047200,"42.5"]}}`),
	})
	out, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "42.5"})
	if terr != nil {
		t.Fatalf("query: %v", terr)
	}
	if out.ResultType != "scalar" || len(out.Rows) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if got := mustJSON(t, out.Rows[0][2]); got != "42.5" {
		t.Errorf("scalar value = %s", got)
	}

	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		body: []byte(`{"status":"success","data":{"resultType":"string",` +
			`"result":[1787047200,"hello"]}}`),
	})
	out, terr = h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: `"hello"`})
	if terr != nil {
		t.Fatalf("query: %v", terr)
	}
	if out.Rows[0][2] != "hello" {
		t.Errorf("string value = %v", out.Rows[0][2])
	}
}

// TestQueryArgumentValidationErrors covers the query-level error returns
// that TestValidateExpr and TestParseDuration only exercise as direct calls
// to the pure helpers, never through the query method's own call sites.
func TestQueryArgumentValidationErrors(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: ""})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Errorf("empty query: terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.query(ctx(t), h.p,
		QueryIn{Cluster: okCluster, Query: "up", Timeout: "not-a-duration"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Errorf("bad timeout: terr = %v, want INVALID_TIME", terr)
	}
}

// TestQueryMalformedResponseBody covers a Prometheus API envelope that
// decodes but carries no data member at all, distinct from a body that is not
// JSON (TestMalformedUpstream) or a well-formed vector/matrix mismatch
// (TestQueryWrongResultType).
func TestQueryMalformedResponseBody(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		body: []byte(`{"status":"success"}`),
	})
	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up"})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestQueryMalformedScalar covers a scalar result whose value is not the
// [timestamp, "value"] pair Prometheus documents, which is a different
// failure than the response having no data member at all.
func TestQueryMalformedScalar(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{
		body: []byte(`{"status":"success","data":{"resultType":"scalar","result":"not-a-pair"}}`),
	})
	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "42"})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestQueryPassthroughFormat covers format "json".
func TestQueryPassthroughFormat(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.query(ctx(t), h.p,
		QueryIn{Cluster: okCluster, Query: "up", Format: "json"})
	if terr != nil {
		t.Fatalf("query: %v", terr)
	}
	if out.Raw == nil {
		t.Fatal("format json returned no raw payload")
	}
	var decoded struct {
		ResultType string `json:"resultType"`
	}
	raw, ok := out.Raw.(json.RawMessage)
	if !ok {
		t.Fatalf("raw is %T, want json.RawMessage", out.Raw)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("raw is not the upstream shape: %v", err)
	}
	if decoded.ResultType != "vector" {
		t.Errorf("resultType = %q", decoded.ResultType)
	}
	if out.Rows != nil {
		t.Error("passthrough also carried the compact rows; the tokens are paid twice")
	}
}

// TestQueryPassthroughTokenCeiling proves format "json" cannot be used to
// route around the hub's token ceiling on an instant query, mirroring the
// query_range equivalent (TestTokenCeilingAppliesToPassthrough) which never
// exercised this instant-only code path.
func TestQueryPassthroughTokenCeiling(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) { o.TokenCeiling = 200 })
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{body: syntheticVector(t, 100)})
	out, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up", Format: "json"})
	if terr != nil {
		t.Fatalf("query: %v", terr)
	}
	if out.Raw != nil {
		t.Error("an oversized passthrough payload was returned anyway")
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncated = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if !strings.Contains(out.Truncated.Hint, "compact") {
		t.Errorf("hint does not point at the cheap encoding: %q", out.Truncated.Hint)
	}
}

// TestQueryTableFormat covers the fixed-width instant rendering.
func TestQueryTableFormat(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.query(ctx(t), h.p,
		QueryIn{Cluster: okCluster, Query: "up", Format: "table"})
	if terr != nil {
		t.Fatalf("query: %v", terr)
	}
	if !strings.Contains(out.Table, "METRIC") || !strings.Contains(out.Table, "up") {
		t.Errorf("table:\n%s", out.Table)
	}
	if out.Rows != nil || out.Columns != nil {
		t.Error("table format still carried the structured rows")
	}
}

// TestBadFormat covers the closed-set check on format.
func TestBadFormat(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.query(ctx(t), h.p,
		QueryIn{Cluster: okCluster, Query: "up", Format: "yaml"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
	if !strings.Contains(terr.Message, "compact") {
		t.Errorf("message does not name the valid values: %q", terr.Message)
	}
}

// syntheticMatrix builds a Prometheus range payload with n series of p points,
// where series i has a maximum of i so top-N selection is checkable.
func syntheticMatrix(t *testing.T, n, p int, start time.Time, step time.Duration) []byte {
	t.Helper()
	m := make(render.Matrix, 0, n)
	for i := range n {
		s := render.SeriesStream{
			Metric: map[string]string{
				"__name__": "synthetic_metric_total",
				"job":      "synthetic",
				"instance": fmt.Sprintf("10.0.0.%d:9100", i%250),
				"pod":      fmt.Sprintf("workload-%04d-abcde", i),
			},
			Values: make([]render.Point, 0, p),
		}
		for j := range p {
			s.Values = append(s.Values, render.Point{
				T: float64(start.Add(time.Duration(j) * step).Unix()),
				V: float64(i) * float64(j) / float64(max(p-1, 1)),
			})
		}
		m = append(m, s)
	}
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "matrix", "result": m},
	})
	if err != nil {
		t.Fatalf("marshal synthetic matrix: %v", err)
	}
	return body
}

// TestUpstreamFailureMapping covers every promproxy sentinel reaching a stable
// code with an honest retryable flag.
func TestUpstreamFailureMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		err           error
		wantCode      string
		wantRetryable bool
		wantHintPart  string
	}{
		{
			name:          "spoke gone",
			err:           &promproxy.NotConnectedError{ClusterID: okCluster, LastSeen: testNow.Add(-time.Minute), Since: time.Minute},
			wantCode:      CodeSpokeUnreachable,
			wantRetryable: true,
			wantHintPart:  "list_clusters",
		},
		{
			name: "hub busy",
			err: &promproxy.BusyError{
				ClusterID: okCluster, Budget: "cluster-inflight", Limit: 8,
				RetryAfter: promproxy.ClusterBusyRetryAfter,
			},
			wantCode:      CodeHubBusy,
			wantRetryable: true,
			wantHintPart:  "retry",
		},
		{
			name:          "response too large",
			err:           fmt.Errorf("x: %w", promproxy.ErrTooLarge),
			wantCode:      CodeResponseTooLarge,
			wantRetryable: false,
			wantHintPart:  "aggregate",
		},
		{
			name:          "deadline",
			err:           fmt.Errorf("x: %w", context.DeadlineExceeded),
			wantCode:      CodeQueryTimeout,
			wantRetryable: true,
			wantHintPart:  "timeout",
		},
		{
			name:          "cancelled",
			err:           fmt.Errorf("x: %w", context.Canceled),
			wantCode:      CodeCanceled,
			wantRetryable: false,
		},
		{
			name:          "invalid param",
			err:           fmt.Errorf("x: %w", promapi.ErrInvalidParam),
			wantCode:      CodeInvalidArgument,
			wantRetryable: false,
		},
		{
			name:          "gated endpoint",
			err:           fmt.Errorf("x: %w", promapi.ErrEndpointGated),
			wantCode:      CodeInvalidArgument,
			wantRetryable: false,
			wantHintPart:  "credentials",
		},
		{
			name:          "anything else",
			err:           fmt.Errorf("x: %w", promproxy.ErrUpstream),
			wantCode:      CodeUpstreamError,
			wantRetryable: true,
			wantHintPart:  "Retry",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.prom.set(string(promapi.EndpointQuery), fakeResponse{err: tc.err})
			_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up"})
			if terr == nil {
				t.Fatal("no error")
			}
			if terr.Code != tc.wantCode {
				t.Errorf("code = %s, want %s", terr.Code, tc.wantCode)
			}
			if terr.Retryable == nil {
				t.Fatal("retryable was not stated; a model will retry forever")
			}
			if *terr.Retryable != tc.wantRetryable {
				t.Errorf("retryable = %v, want %v", *terr.Retryable, tc.wantRetryable)
			}
			if tc.wantHintPart != "" && !strings.Contains(terr.Hint, tc.wantHintPart) {
				t.Errorf("hint = %q, want it to mention %q", terr.Hint, tc.wantHintPart)
			}
			if terr.Input["cluster"] != okCluster {
				t.Errorf("offending cluster was not echoed: %v", terr.Input)
			}
		})
	}
}

// TestForbiddenFromProxyIsUnknownCluster proves the proxy's own denial is
// reported identically to a nonexistent cluster, so the second check cannot be
// used to enumerate the fleet either.
func TestForbiddenFromProxyIsUnknownCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.denyClusters[okCluster] = true
	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up"})
	if terr == nil || terr.Code != CodeUnknownCluster {
		t.Fatalf("terr = %v, want UNKNOWN_CLUSTER", terr)
	}
}

// TestMalformedUpstream covers a body that is not the Prometheus envelope.
func TestMalformedUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointQuery), fakeResponse{body: []byte(`<html>login</html>`)})
	_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up"})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
	if !strings.Contains(terr.Hint, "runtime_info") {
		t.Errorf("hint = %q", terr.Hint)
	}
}

// TestUpstreamErrorTypes covers Prometheus' own errorType classification.
func TestUpstreamErrorTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		errorType string
		message   string
		want      string
	}{
		{errorType: "timeout", message: "query timed out", want: CodeQueryTimeout},
		{errorType: "canceled", message: "query was canceled", want: CodeCanceled},
		{errorType: "execution", message: "found duplicate series", want: CodePromQLExec},
		{errorType: "internal", message: "boom", want: CodeUpstreamError},
		{errorType: "unavailable", message: "not ready", want: CodeUpstreamError},
		{errorType: "bad_data", message: "1:5: parse error: unexpected end", want: CodePromQLParse},
		{errorType: "bad_data", message: "invalid expression type", want: CodePromQLExec},
	}
	for _, tc := range tests {
		t.Run(tc.errorType+"/"+tc.want, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			body, err := json.Marshal(map[string]string{
				"status": "error", "errorType": tc.errorType, "error": tc.message,
			})
			if err != nil {
				t.Fatal(err)
			}
			h.prom.set(string(promapi.EndpointQuery), fakeResponse{status: 400, body: body})
			_, terr := h.tools.query(ctx(t), h.p, QueryIn{Cluster: okCluster, Query: "up"})
			if terr == nil || terr.Code != tc.want {
				t.Fatalf("terr = %v, want %s", terr, tc.want)
			}
		})
	}
}

// TestSelectorToolsClassifyBadMatchers proves a matcher mistake is reported as
// one, not as a PromQL parse error.
func TestSelectorToolsClassifyBadMatchers(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointSeries), fakeResponse{
		status: 400,
		body: []byte(`{"status":"error","errorType":"bad_data",` +
			`"error":"invalid parameter \"match[]\": unexpected end of input"}`),
	})
	_, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{`up{job=`}})
	if terr == nil || terr.Code != CodeBadMatcher {
		t.Fatalf("terr = %v, want BAD_MATCHER", terr)
	}
	if !strings.Contains(terr.Hint, "label_values") {
		t.Errorf("hint does not name a discovery call: %q", terr.Hint)
	}
}

// TestValidateMatchersRejectsBareLabel catches the classic model mistake before
// a round trip.
func TestValidateMatchersRejectsBareLabel(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{`job="api"`}})
	if terr == nil || terr.Code != CodeBadMatcher {
		t.Fatalf("terr = %v, want BAD_MATCHER", terr)
	}
	if len(h.prom.calls) != 0 {
		t.Error("a malformed matcher was still sent upstream")
	}

	_, terr = h.tools.series(ctx(t), h.p, SeriesIn{Cluster: okCluster, Matchers: nil})
	if terr == nil || terr.Code != CodeBadMatcher {
		t.Fatalf("terr = %v, want BAD_MATCHER for an empty matcher list", terr)
	}
}

// TestSeriesColumnar covers the union-of-columns encoding.
func TestSeriesColumnar(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}})
	if terr != nil {
		t.Fatalf("series: %v", terr)
	}
	want := []string{"__name__", "instance", "job", "namespace"}
	if diff := cmp.Diff(want, out.Columns); diff != "" {
		t.Errorf("columns (-want +got):\n%s", diff)
	}
	if len(out.Rows) != 3 || out.Total != 3 {
		t.Fatalf("rows = %d, total = %d", len(out.Rows), out.Total)
	}
	for _, r := range out.Rows {
		if len(r) != len(want) {
			t.Errorf("row has %d cells, want %d", len(r), len(want))
		}
	}

	tbl, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}, Format: "table"})
	if terr != nil {
		t.Fatalf("series table: %v", terr)
	}
	if !strings.Contains(tbl.Table, "__NAME__") || tbl.Rows != nil {
		t.Errorf("table:\n%s", tbl.Table)
	}
}

// TestLabelNamesAndValues covers the two label tools including the
// empty-not-error rule.
func TestLabelNamesAndValues(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	names, terr := h.tools.labelNames(ctx(t), h.p, LabelNamesIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("labelNames: %v", terr)
	}
	if !slices.Contains(names.Names, "namespace") || names.Total != 9 {
		t.Errorf("names = %v (total %d)", names.Names, names.Total)
	}

	vals, terr := h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "job"})
	if terr != nil {
		t.Fatalf("labelValues: %v", terr)
	}
	if !slices.Contains(vals.Values, "kubelet") || vals.Label != "job" {
		t.Errorf("values = %v", vals.Values)
	}

	filtered, terr := h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "job", Pattern: "KUBE"})
	if terr != nil {
		t.Fatalf("labelValues filtered: %v", terr)
	}
	if diff := cmp.Diff([]string{"kube-state-metrics", "kubelet"}, filtered.Values); diff != "" {
		t.Errorf("filtered (-want +got):\n%s", diff)
	}

	// A label that does not exist is an empty list, not an error: an error
	// would push a model into a retry loop over a question already answered.
	empty, terr := h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "no_such_label"})
	if terr != nil {
		t.Fatalf("unknown label errored: %v", terr)
	}
	if len(empty.Values) != 0 {
		t.Errorf("values = %v, want empty", empty.Values)
	}

	if _, terr := h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "bad label"}); terr == nil {
		t.Error("an invalid label name was accepted into a URL path")
	}
}

// TestLabelNamesScopedByMatchers proves a matcher list actually reaches the
// upstream call as match[], which the unscoped calls above never exercise.
func TestLabelNamesScopedByMatchers(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.labelNames(ctx(t), h.p,
		LabelNamesIn{Cluster: okCluster, Matchers: []string{`up{job="api"}`}})
	if terr != nil {
		t.Fatalf("labelNames: %v", terr)
	}
	if len(out.Names) == 0 {
		t.Fatal("no names returned")
	}
	form := h.prom.lastForm(promapi.EndpointLabels)
	if diff := cmp.Diff([]string{`up{job="api"}`}, form["match[]"]); diff != "" {
		t.Errorf("match[] (-want +got):\n%s", diff)
	}
}

// TestSearchMetrics covers both modes, the metadata join and BAD_REGEX.
func TestSearchMetrics(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	sub, terr := h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: "CPU"})
	if terr != nil {
		t.Fatalf("searchMetrics: %v", terr)
	}
	if len(sub.Metrics) == 0 {
		t.Fatal("case-insensitive substring search found nothing")
	}
	for _, m := range sub.Metrics {
		if !strings.Contains(strings.ToLower(m.Name), "cpu") {
			t.Errorf("%q does not match the pattern", m.Name)
		}
	}
	if sub.Scanned == 0 {
		t.Error("scanned was not reported, so a zero result is ambiguous")
	}

	re, terr := h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: "^node_", Mode: ModeRegex,
			WithMetadata: true})
	if terr != nil {
		t.Fatalf("searchMetrics regex: %v", terr)
	}
	var found bool
	for _, m := range re.Metrics {
		if m.Name == "node_cpu_seconds_total" {
			found = true
			if m.Type != "counter" || m.Unit != "seconds" || m.Help == "" {
				t.Errorf("metadata was not joined: %+v", m)
			}
		}
	}
	if !found {
		t.Errorf("regex search missed node_cpu_seconds_total: %v", re.Metrics)
	}

	_, terr = h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: "(unclosed", Mode: ModeRegex})
	if terr == nil || terr.Code != CodeBadRegex {
		t.Fatalf("terr = %v, want BAD_REGEX", terr)
	}
	if !strings.Contains(terr.Hint, "substring") {
		t.Errorf("hint does not offer the simpler mode: %q", terr.Hint)
	}
}

// TestSearchMetricsSurvivesMissingMetadata proves the enrichment call failing
// does not fail the search.
func TestSearchMetricsSurvivesMissingMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointMetadata),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	out, terr := h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: "node_", WithMetadata: true})
	if terr != nil {
		t.Fatalf("searchMetrics: %v", terr)
	}
	if len(out.Metrics) == 0 {
		t.Fatal("no metrics returned")
	}
	if out.Metrics[0].Type != "" {
		t.Error("metadata appeared despite the enrichment call failing")
	}
}

// TestMetricMetadata covers the metadata tool and its metric-name validation.
func TestMetricMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.metricMetadata(ctx(t), h.p, MetricMetadataIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("metricMetadata: %v", terr)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}
	if out.Metadata[0].Name != "kube_pod_info" {
		t.Errorf("entries are not sorted by name: %v", out.Metadata)
	}
	if _, terr := h.tools.metricMetadata(ctx(t), h.p,
		MetricMetadataIn{Cluster: okCluster, Metric: "not a metric"}); terr == nil {
		t.Error("an invalid metric name was accepted")
	}
}

// TestRuntimeInfo covers the section selection and the partial report.
func TestRuntimeInfo(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.runtimeInfo(ctx(t), h.p, RuntimeInfoIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("runtimeInfo: %v", terr)
	}
	if out.Build == nil || out.Build.Version != "3.6.0" {
		t.Errorf("build = %+v", out.Build)
	}
	if out.Runtime == nil || !out.Runtime.ReloadSuccess || out.Runtime.StorageRetention != "15d" {
		t.Errorf("runtime = %+v", out.Runtime)
	}
	if out.Flags != nil {
		t.Error("flags returned without being requested")
	}

	all, terr := h.tools.runtimeInfo(ctx(t), h.p,
		RuntimeInfoIn{Cluster: okCluster, Include: allSections})
	if terr != nil {
		t.Fatalf("runtimeInfo all: %v", terr)
	}
	if all.Flags["storage.tsdb.retention.time"] != "15d" {
		t.Errorf("flags = %v", all.Flags)
	}

	// One section failing must be named, not silently omitted.
	h.prom.set(string(promapi.EndpointFlags),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	partial, terr := h.tools.runtimeInfo(ctx(t), h.p,
		RuntimeInfoIn{Cluster: okCluster, Include: allSections})
	if terr != nil {
		t.Fatalf("runtimeInfo partial: %v", terr)
	}
	if diff := cmp.Diff([]string{SectionFlags}, partial.Partial); diff != "" {
		t.Errorf("partial (-want +got):\n%s", diff)
	}

	// Every section failing is a failure, not an empty success.
	h.prom.set(string(promapi.EndpointBuildInfo),
		fakeResponse{err: fmt.Errorf("x: %w", promproxy.ErrUpstream)})
	if _, terr := h.tools.runtimeInfo(ctx(t), h.p,
		RuntimeInfoIn{Cluster: okCluster, Include: []string{SectionBuild}}); terr == nil {
		t.Error("a wholly failed runtime_info reported success")
	}
}

// TestTSDBStats covers each dimension and the unavailable path.
func TestTSDBStats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		dimension string
		wantTop   string
		wantPct   bool
	}{
		{dimension: "", wantTop: "kube_pod_container_status_restarts_total", wantPct: true},
		{dimension: DimensionMetric, wantTop: "kube_pod_container_status_restarts_total", wantPct: true},
		{dimension: DimensionLabelName, wantTop: "pod"},
		{dimension: DimensionLabelValuePairs, wantTop: "job=kubelet", wantPct: true},
		{dimension: DimensionLabelMemory, wantTop: "pod"},
	}
	for _, tc := range tests {
		t.Run("dimension="+tc.dimension, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			out, terr := h.tools.tsdbStats(ctx(t), h.p,
				TSDBStatsIn{Cluster: okCluster, Dimension: tc.dimension})
			if terr != nil {
				t.Fatalf("tsdbStats: %v", terr)
			}
			if out.Head.Series != 482913 {
				t.Errorf("head.series = %d", out.Head.Series)
			}
			if len(out.Top) == 0 || out.Top[0].Name != tc.wantTop {
				t.Fatalf("top = %+v, want %q first", out.Top, tc.wantTop)
			}
			if tc.wantPct && out.Top[0].PercentOfTotal == 0 {
				t.Error("no percentOfTotal; the raw count alone is not a decision")
			}
			for i := 1; i < len(out.Top); i++ {
				if out.Top[i].Value > out.Top[i-1].Value {
					t.Fatalf("ranking is not descending at %d: %+v", i, out.Top)
				}
			}
		})
	}
}

// TestTSDBStatsUnavailable proves a server without the endpoint gets the
// specific code and the PromQL workaround, not a retry loop.
func TestTSDBStatsUnavailable(t *testing.T) {
	t.Parallel()
	for _, status := range []int{404, 501} {
		h := newHarness(t)
		h.prom.set(string(promapi.EndpointTSDBStatus), fakeResponse{
			status: status, body: []byte("404 page not found\n"),
		})
		_, terr := h.tools.tsdbStats(ctx(t), h.p, TSDBStatsIn{Cluster: okCluster})
		if terr == nil || terr.Code != CodeTSDBStatsUnavailable {
			t.Fatalf("status %d: terr = %v, want TSDB_STATS_UNAVAILABLE", status, terr)
		}
		if !strings.Contains(terr.Hint, "count by(__name__)") {
			t.Errorf("hint does not name the workaround query: %q", terr.Hint)
		}
		if terr.Retryable == nil || *terr.Retryable {
			t.Error("a missing endpoint is not retryable")
		}
	}
}

// TestTSDBStatsBadDimension covers the closed-set check.
func TestTSDBStatsBadDimension(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.tsdbStats(ctx(t), h.p,
		TSDBStatsIn{Cluster: okCluster, Dimension: "everything"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestRules covers the rule listing, its ordering and includeExpr.
func TestRules(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if len(out.Groups) == 0 || len(out.Rules) == 0 {
		t.Fatalf("out = %+v", out)
	}
	for _, r := range out.Rules {
		if r.Expr != "" {
			t.Error("an expression was returned without includeExpr")
		}
	}
	// Alert instances are the alerts tool's job; asking for them here would
	// double the payload.
	if form := h.prom.lastForm(promapi.EndpointRules); form["exclude_alerts"][0] != "true" {
		t.Errorf("rules did not exclude alert instances: %v", form)
	}

	withExpr, terr := h.tools.rules(ctx(t), h.p,
		RulesIn{Cluster: okCluster, IncludeExpr: true})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	var any bool
	for _, r := range withExpr.Rules {
		if r.Expr != "" {
			any = true
		}
	}
	if !any {
		t.Error("includeExpr returned no expressions")
	}

	one, terr := h.tools.rules(ctx(t), h.p,
		RulesIn{Cluster: okCluster, RuleName: "KubePodCrashLooping"})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if len(one.Rules) != 1 || one.Rules[0].Name != "KubePodCrashLooping" {
		t.Errorf("ruleName filter = %+v", one.Rules)
	}
	// Pins the *1000 conversion from seconds to milliseconds for both the
	// rule's own evaluationTime (0.002101s) and its group's (0.004112s): an
	// ARITHMETIC_BASE mutation turning * into / or + would land far from
	// these values.
	if one.Rules[0].EvalMillis != 2.1 {
		t.Errorf("rule EvalMillis = %v, want 2.1 (0.002101s * 1000, rounded)", one.Rules[0].EvalMillis)
	}
	var appsGroup *RuleGroupInfo
	for i := range out.Groups {
		if out.Groups[i].Name == "kubernetes-apps" {
			appsGroup = &out.Groups[i]
		}
	}
	if appsGroup == nil || appsGroup.EvalMillis != 4.11 {
		t.Errorf("kubernetes-apps group EvalMillis = %+v, want 4.11 (0.004112s * 1000, rounded)", appsGroup)
	}

	if _, terr := h.tools.rules(ctx(t), h.p,
		RulesIn{Cluster: okCluster, Type: "nonsense"}); terr == nil {
		t.Error("an invalid rule type was accepted")
	}
}

// TestAlerts covers filtering, the summary and annotation handling.
func TestAlerts(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	firing, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if firing.Summary.Firing != 2 || firing.Summary.Pending != 0 {
		t.Errorf("summary = %+v, want the default firing-only filter", firing.Summary)
	}
	for _, a := range firing.Alerts {
		if a.State != AlertFiring {
			t.Errorf("state filter leaked a %q alert", a.State)
		}
	}

	all, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster, State: AlertAll})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if all.Total != 3 || all.Summary.Pending != 1 {
		t.Errorf("summary = %+v total = %d", all.Summary, all.Total)
	}
	if all.Summary.BySeverity["warning"] != 2 {
		t.Errorf("bySeverity = %v", all.Summary.BySeverity)
	}

	warn, terr := h.tools.alerts(ctx(t), h.p,
		AlertsIn{Cluster: okCluster, State: AlertAll, Severity: "warning"})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if warn.Total != 2 {
		t.Errorf("severity filter total = %d, want 2", warn.Total)
	}

	sel, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{
		Cluster: okCluster, State: AlertAll,
		LabelSelector: map[string]string{"namespace": "default"},
	})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if sel.Total != 1 {
		t.Errorf("labelSelector total = %d, want 1", sel.Total)
	}

	withAnn, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{
		Cluster: okCluster, IncludeAnnotations: true,
	})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if withAnn.Alerts[0].Annotations["summary"] == "" {
		t.Error("annotations were requested but not returned")
	}
	if withAnn.Alerts[0].Runbook != nil {
		t.Error("the fixture has no runbook_url but one was reported")
	}
}

// TestAlertsFiringFirst proves a truncated alert listing keeps what matters.
func TestAlertsFiringFirst(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster, State: AlertAll})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	seenPending := false
	for _, a := range out.Alerts {
		if a.State == AlertPending {
			seenPending = true
		} else if seenPending {
			t.Fatalf("a firing alert sorted after a pending one: %+v", out.Alerts)
		}
	}
}

// TestRoleAllowsNilScope pins the guard's independence from call order: the
// dispatch path happens to nil-check through AllowsTool first, but roleAllows
// must not panic if that ordering ever changes.
func TestRoleAllowsNilScope(t *testing.T) {
	t.Parallel()
	if roleAllows(nil, ToolTargets) {
		t.Error("roleAllows(nil) = true, want false: a scopeless principal has no tier")
	}
	if roleAllows(nil, ToolQuery) {
		t.Error("roleAllows(nil) granted a non-operational tool to a scopeless principal")
	}
}

// TestRawFormatRefusedUnderScopeLimits pins that format "json" cannot be used
// to read past a scope's maxSeries or maxPoints: the raw payload bypasses the
// encoder that applies them, so the format is refused rather than honoured
// unbounded. Range queries additionally refuse under maxPoints alone; instant
// queries have no point dimension and ignore it.
func TestRawFormatRefusedUnderScopeLimits(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	series := principal(fullScope())
	series.Scope.Limits.MaxSeries = 3
	points := principal(fullScope())
	points.Scope.Limits.MaxPoints = 50

	if _, terr := h.tools.query(ctx(t), series,
		QueryIn{Cluster: okCluster, Query: "up", Format: "json"}); terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("query json under maxSeries: terr = %v, want INVALID_ARGUMENT", terr)
	}
	if _, terr := h.tools.queryRange(ctx(t), series,
		QueryRangeIn{Cluster: okCluster, Query: "up", Format: "json"}); terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("query_range json under maxSeries: terr = %v, want INVALID_ARGUMENT", terr)
	}
	if _, terr := h.tools.queryRange(ctx(t), points,
		QueryRangeIn{Cluster: okCluster, Query: "up", Format: "json"}); terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("query_range json under maxPoints: terr = %v, want INVALID_ARGUMENT", terr)
	}
	// An instant query has no points to cap, so maxPoints alone leaves json
	// available to it.
	if _, terr := h.tools.query(ctx(t), points,
		QueryIn{Cluster: okCluster, Query: "up", Format: "json"}); terr != nil {
		t.Fatalf("query json under maxPoints only: %v", terr)
	}
	// The cap must not leak into the other formats.
	out, terr := h.tools.query(ctx(t), series, QueryIn{Cluster: okCluster, Query: "up"})
	if terr != nil {
		t.Fatalf("query compact under maxSeries: %v", terr)
	}
	if len(out.Rows) > 3 {
		t.Fatalf("compact returned %d rows past maxSeries 3", len(out.Rows))
	}
}
