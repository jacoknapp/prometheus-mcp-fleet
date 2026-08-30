// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// describe_cluster include sections. Closed set.
const (
	// IncludeJobs adds the scrape job names.
	IncludeJobs = "jobs"
	// IncludeMetricPrefixes adds the two-segment metric prefixes, which is the
	// single highest-value fact about a cluster: "kube_", "istio_", "jvm_"
	// tells an agent instantly what stack it is looking at.
	IncludeMetricPrefixes = "metricPrefixes"
	// IncludeNamespaces adds the sampled Kubernetes namespaces.
	IncludeNamespaces = "namespaces"
	// IncludeAlertmanager adds the Alertmanager summary.
	IncludeAlertmanager = "alertmanager"
	// IncludeRulesSummary adds rule and alert counts.
	IncludeRulesSummary = "rulesSummary"
	// IncludeKubernetes adds the Kubernetes context, when the spoke was given
	// the RBAC to collect it.
	IncludeKubernetes = "kubernetes"
	// IncludeExternalLabels adds the server's external labels, which is what a
	// federated or remote-write setup is identified by.
	IncludeExternalLabels = "externalLabels"
)

// defaultIncludes is what describe_cluster returns when the caller says
// nothing. It is the set that answers "what is this cluster" in one call
// without paying for the long lists.
var defaultIncludes = []string{
	IncludeJobs, IncludeMetricPrefixes, IncludeAlertmanager, IncludeRulesSummary,
}

// allIncludes is the closed set the schema advertises.
var allIncludes = []string{
	IncludeJobs, IncludeMetricPrefixes, IncludeNamespaces, IncludeAlertmanager,
	IncludeRulesSummary, IncludeKubernetes, IncludeExternalLabels,
}

// DescribeClusterIn is the argument object of describe_cluster.
type DescribeClusterIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Include selects optional sections.
	Include []string `json:"include,omitempty" jsonschema:"Optional sections to include. Defaults to jobs, metricPrefixes, alertmanager and rulesSummary."`
	// TopN caps each list.
	TopN int `json:"topN,omitempty" jsonschema:"Maximum entries in each list section."`
}

// ClusterCounts are the size facts an agent needs before deciding how
// expensive a query against this cluster will be.
type ClusterCounts struct {
	// ActiveSeries is the head-block series count.
	ActiveSeries int64 `json:"activeSeries,omitempty"`
	// MetricNames is how many distinct metric names exist.
	MetricNames int64 `json:"metricNames,omitempty"`
	// Jobs is how many scrape jobs are configured.
	Jobs int `json:"jobs,omitempty"`
	// RuleGroups, AlertingRules and AlertsFiring summarise the rule engine.
	RuleGroups    int32 `json:"ruleGroups,omitempty"`
	AlertingRules int32 `json:"alertingRules,omitempty"`
	AlertsFiring  int32 `json:"alertsFiring,omitempty"`
}

// ClusterPrometheus describes the monitored server itself.
type ClusterPrometheus struct {
	// Flavor distinguishes Prometheus from Thanos, Mimir or Cortex, which
	// changes which endpoints exist.
	Flavor string `json:"flavor,omitempty"`
	// Version is the server version.
	Version string `json:"version,omitempty"`
	// Reachable reports whether the spoke can currently talk to it.
	Reachable bool `json:"reachable,omitempty"`
	// UnreachableReason is the spoke's own explanation when it cannot.
	UnreachableReason string `json:"unreachableReason,omitempty"`
	// Retention is the configured retention window.
	Retention string `json:"retention,omitempty"`
	// ScrapeInterval is the global scrape interval and the floor query_range
	// will not step below.
	ScrapeInterval string `json:"scrapeInterval,omitempty"`
	// LookbackDelta is the query engine's staleness window.
	LookbackDelta string `json:"lookbackDelta,omitempty"`
	// ExternalLabels identify this server in a federated setup.
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
}

// ClusterKubernetes is the optional Kubernetes context.
type ClusterKubernetes struct {
	Available         bool   `json:"available,omitempty"`
	UnavailableReason string `json:"unavailableReason,omitempty"`
	Version           string `json:"version,omitempty"`
	NodeCount         int32  `json:"nodeCount,omitempty"`
}

// ClusterAlertmanager summarises alert routing.
type ClusterAlertmanager struct {
	// Present reports whether an Alertmanager is configured. When it is false,
	// "why was I not paged" has an answer before any query is run.
	Present bool `json:"present,omitempty"`
	// AlertsFiring is how many alerts are firing.
	AlertsFiring int32 `json:"alertsFiring,omitempty"`
}

// DescribeClusterOut is the result of describe_cluster.
type DescribeClusterOut struct {
	Envelope
	// Name is the cluster's identity.
	Name string `json:"name,omitempty"`
	// DisplayName and Description are the operator's own labels for it.
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description,omitempty"`
	// Status is one of the Status constants.
	Status string `json:"status,omitempty"`
	// Labels are the routing selectors.
	Labels map[string]string `json:"labels,omitempty"`
	// Prometheus describes the monitored server.
	Prometheus ClusterPrometheus `json:"prometheus,omitzero"`
	// Counts are the size facts.
	Counts ClusterCounts `json:"counts,omitzero"`
	// Jobs are the scrape job names, when requested.
	Jobs []string `json:"jobs,omitempty"`
	// MetricPrefixes are the dominant metric-name prefixes, when requested.
	MetricPrefixes []string `json:"metricPrefixes,omitempty"`
	// Namespaces are sampled Kubernetes namespaces, when requested.
	Namespaces []string `json:"namespaces,omitempty"`
	// Alertmanager summarises alert routing, when requested.
	Alertmanager *ClusterAlertmanager `json:"alertmanager,omitempty"`
	// Kubernetes is the cluster context, when requested and collected.
	Kubernetes *ClusterKubernetes `json:"kubernetes,omitempty"`
	// AgentVersion is the spoke's build.
	AgentVersion string `json:"agentVersion,omitempty"`
	// FactsAgeSeconds is how long ago these facts were published.
	FactsAgeSeconds int64 `json:"factsAgeSeconds,omitempty"`
	// Stale marks facts older than the hub's staleness threshold. It is
	// reported rather than refused: month-old facts are still the best answer
	// available, provided the agent is told they are month-old.
	Stale bool `json:"stale,omitempty"`
	// StaleNotice explains Stale in words the model will not misread.
	StaleNotice string `json:"staleNotice,omitempty"`
	// Truncated is set when a list section was cut to topN.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// describeCluster answers entirely from the facts the spoke published. It
// issues no upstream call, so it is cheap enough to be the second call of
// every investigation.
func (t *Tools) describeCluster(
	_ context.Context, p *fleet.Principal, in DescribeClusterIn,
) (*DescribeClusterOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	now := t.now()
	if terr := requireConnected(c, now); terr != nil {
		return nil, terr
	}
	include := dedupe(in.Include)
	if len(include) == 0 {
		include = defaultIncludes
	}
	for _, s := range include {
		if !includes(allIncludes, s) {
			return nil, newError(CodeInvalidArgument,
				fmt.Sprintf("include value %q is not one of %s",
					render.ClipRunes(s, 64), strings.Join(allIncludes, ", ")), false).
				WithInput(map[string]any{"cluster": c.ID, "include": in.Include})
		}
	}
	topN := clampInt(in.TopN, 25, 1, 100)

	age := factsAge(c, now)
	out := &DescribeClusterOut{
		Envelope:    untrusted(),
		Name:        c.ID,
		DisplayName: render.ClipRunes(c.DisplayName, 128),
		Description: render.ClipRunes(c.Description, 200),
		Status:      clusterStatus(c),
		Labels:      render.Labels(c.Labels),
		Prometheus: ClusterPrometheus{
			Flavor:            render.ClipRunes(c.Prometheus.Flavor, 32),
			Version:           render.ClipRunes(c.Prometheus.Version, 64),
			Reachable:         c.Prometheus.Reachable,
			UnreachableReason: render.ClipRunes(c.Prometheus.UnreachableReason, 300),
			Retention:         render.ClipRunes(c.Prometheus.Retention, 32),
			ScrapeInterval:    render.ClipRunes(c.Prometheus.ScrapeInterval, 32),
			LookbackDelta:     render.ClipRunes(c.Prometheus.LookbackDelta, 32),
		},
		Counts: ClusterCounts{
			ActiveSeries: maxZero(c.Prometheus.ActiveSeries),
			MetricNames:  maxZero(c.Prometheus.MetricNames),
			Jobs:         len(c.Prometheus.Jobs),
		},
		AgentVersion:    render.ClipRunes(c.AgentVersion, 64),
		FactsAgeSeconds: int64(age.Seconds()),
	}
	if age > StaleFactsAfter {
		out.Stale = true
		out.StaleNotice = fmt.Sprintf(
			"These facts are %s old, past the hub's %s freshness threshold. "+
				"Counts and job lists may have moved on; live queries are unaffected.",
			age.Truncate(1e9), StaleFactsAfter)
	}

	var trunc *render.Truncation
	if includes(include, IncludeJobs) {
		out.Jobs, trunc = clipList(sanitizeList(c.Prometheus.Jobs), topN, trunc,
			"jobs", "Raise topN, or call label_values with label \"job\" for the full list.")
	}
	if includes(include, IncludeMetricPrefixes) {
		out.MetricPrefixes, trunc = clipList(sanitizeList(c.Prometheus.MetricPrefixes), topN, trunc,
			"metricPrefixes", "Raise topN, or call search_metrics with a pattern.")
	}
	if includes(include, IncludeNamespaces) {
		out.Namespaces, trunc = clipList(sanitizeList(c.Prometheus.Namespaces), topN, trunc,
			"namespaces", "Raise topN, or call label_values with label \"namespace\".")
	}
	if includes(include, IncludeRulesSummary) {
		out.Counts.RuleGroups = c.Prometheus.RuleGroups
		out.Counts.AlertingRules = c.Prometheus.AlertingRules
		out.Counts.AlertsFiring = c.Prometheus.FiringAlerts
	}
	if includes(include, IncludeAlertmanager) {
		out.Alertmanager = &ClusterAlertmanager{
			Present:      c.Prometheus.HasAlertmanager,
			AlertsFiring: c.Prometheus.FiringAlerts,
		}
	}
	if includes(include, IncludeKubernetes) {
		out.Kubernetes = &ClusterKubernetes{
			Available:         c.Kubernetes.Available,
			UnavailableReason: render.ClipRunes(c.Kubernetes.UnavailableReason, 300),
			Version:           render.ClipRunes(c.Kubernetes.Version, 64),
			NodeCount:         c.Kubernetes.NodeCount,
		}
	}
	if includes(include, IncludeExternalLabels) {
		out.Prometheus.ExternalLabels = render.Labels(c.Prometheus.ExternalLabels)
	}
	out.Truncated = trunc
	return out, nil
}

// maxZero returns v when positive and zero otherwise. A spoke reports -1 for a
// fact it could not collect, and -1 series is worse than no field at all.
func maxZero(v int64) int64 {
	if v <= 0 {
		return 0
	}
	return v
}

// sanitizeList cleans a list of untrusted short strings.
func sanitizeList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if c := render.ClipRunes(s, 128); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// clipList applies topN to one section and folds the result into a single
// [render.Truncation] shared by every section, naming which section was cut.
func clipList(
	in []string, topN int, prev *render.Truncation, section, hint string,
) ([]string, *render.Truncation) {
	kept, trunc := render.TruncateItems(in, topN, hint)
	if trunc == nil {
		return kept, prev
	}
	trunc.Selection = section + "_first_" + fmt.Sprint(topN)
	if prev == nil {
		return kept, trunc
	}
	// More than one section was cut. Report the larger overflow, because that
	// is the one most likely to have hidden the answer.
	if trunc.Total-trunc.Returned > prev.Total-prev.Returned {
		return kept, trunc
	}
	return kept, prev
}
