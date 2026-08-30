// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Cluster status values reported by list_clusters and accepted by its status
// filter. This is a closed set.
const (
	// StatusHealthy means the spoke holds a tunnel and its Prometheus answers.
	StatusHealthy = "healthy"
	// StatusDegraded means the tunnel is up but the cluster's Prometheus is
	// not answering, so metadata is available and queries are not.
	StatusDegraded = "degraded"
	// StatusUnreachable means no tunnel is attached.
	StatusUnreachable = "unreachable"
	// StatusAll is the filter value that selects every status.
	StatusAll = "all"
)

// ListClustersIn is the argument object of list_clusters.
type ListClustersIn struct {
	// Filter is a case-insensitive substring test.
	Filter string `json:"filter,omitempty" jsonschema:"Case-insensitive substring matched against the cluster name, display name and description."`
	// LabelSelector requires every listed label to match exactly.
	LabelSelector map[string]string `json:"labelSelector,omitempty" jsonschema:"Require every one of these labels to be present and equal, e.g. {\"env\":\"prod\",\"region\":\"eu-west\"}."`
	// Status filters by availability.
	Status string `json:"status,omitempty" jsonschema:"Availability filter."`
	// Limit caps the returned entries.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum entries to return."`
	// Format selects the encoding.
	Format string `json:"format,omitempty" jsonschema:"Output encoding. \"table\" is the cheapest for this tool; \"json\" is not supported here because there is no upstream payload to pass through."`
}

// ClusterSummary is one entry of a list_clusters result. It is deliberately
// decision-complete: an agent should be able to choose a cluster from this
// alone, without a follow-up call, so every field here is one an operator
// actually routes on.
type ClusterSummary struct {
	// Name is the cluster's stable identity, and the value every other tool's
	// cluster argument takes.
	Name string `json:"name,omitempty"`
	// DisplayName is the human-facing name, when the operator set one.
	DisplayName string `json:"displayName,omitempty"`
	// Description orients an agent, e.g. "customer-facing API tier".
	Description string `json:"description,omitempty"`
	// Status is one of the Status constants in this package.
	Status string `json:"status,omitempty"`
	// Labels are the operator-supplied selectors.
	Labels map[string]string `json:"labels,omitempty"`
	// PromVersion is the monitored server's version.
	PromVersion string `json:"promVersion,omitempty"`
	// PromFlavor distinguishes Prometheus from Thanos, Mimir or Cortex.
	PromFlavor string `json:"promFlavor,omitempty"`
	// Retention is the configured retention window.
	Retention string `json:"retention,omitempty"`
	// ScrapeInterval is the global scrape interval, which is the floor
	// query_range will not step below.
	ScrapeInterval string `json:"scrapeInterval,omitempty"`
	// ActiveSeries is the head-block series count, the fastest proxy for how
	// expensive this cluster is to query.
	ActiveSeries int64 `json:"activeSeries,omitempty"`
	// JobCount is how many scrape jobs the cluster reports.
	JobCount int `json:"jobCount,omitempty"`
	// AlertsFiring is how many alerts are firing right now.
	AlertsFiring int32 `json:"alertsFiring,omitempty"`
	// RuleGroups is how many rule groups are loaded.
	RuleGroups int32 `json:"ruleGroups,omitempty"`
	// Alertmanager reports whether an Alertmanager is wired up, which decides
	// whether "why was I not paged" is even a sensible question here.
	Alertmanager bool `json:"alertmanager,omitempty"`
	// FactsAgeSeconds is how long ago the spoke last published these facts.
	FactsAgeSeconds int64 `json:"factsAgeSeconds,omitempty"`
	// Stale marks facts older than the hub's staleness threshold.
	Stale bool `json:"stale,omitempty"`
}

// ListClustersOut is the result of list_clusters.
type ListClustersOut struct {
	Envelope
	// Clusters are the matching entries, ordered by name.
	Clusters []ClusterSummary `json:"clusters,omitempty"`
	// Total is how many matched before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when entries were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
	// Table is the fixed-width rendering, set only for format "table".
	Table string `json:"table,omitempty"`
}

// listClusters answers from the registry alone. It issues no upstream call:
// the facts it reports are published by each spoke on its own schedule, which
// is what makes "what exists in the fleet" cost a few hundred tokens instead
// of a hundred round trips.
func (t *Tools) listClusters(
	_ context.Context, p *fleet.Principal, in ListClustersIn,
) (*ListClustersOut, *ToolError) {
	format, terr := parseFormat(in.Format, false)
	if terr != nil {
		return nil, terr
	}
	status := in.Status
	if status == "" {
		status = StatusAll
	}
	switch status {
	case StatusAll, StatusHealthy, StatusDegraded, StatusUnreachable:
	default:
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("status %q is not one of all, healthy, degraded, unreachable",
				render.ClipRunes(status, 64)), false).
			WithInput(map[string]any{"status": render.ClipRunes(status, 64)})
	}

	now := t.now()
	filter := strings.ToLower(strings.TrimSpace(in.Filter))
	matched := make([]ClusterSummary, 0, 16)
	for _, c := range t.clusters.Visible(p) {
		if !matchesSelector(c.Labels, in.LabelSelector) {
			continue
		}
		if filter != "" && !matchesFilter(c, filter) {
			continue
		}
		s := summarize(c, now)
		if status != StatusAll && s.Status != status {
			continue
		}
		matched = append(matched, s)
	}

	limit := clampInt(in.Limit, 100, 1, 500)
	kept, trunc := render.TruncateItems(matched, limit,
		"Narrow with labelSelector, filter or status rather than raising limit.")

	out := &ListClustersOut{
		Envelope:  untrusted(),
		Clusters:  kept,
		Total:     len(matched),
		Truncated: trunc,
	}
	fitted, hit := render.FitTokens(kept, t.tokenCeiling, func(s []ClusterSummary) any {
		return &ListClustersOut{Clusters: s}
	})
	if hit {
		out.Clusters = fitted
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Narrow with labelSelector.", t.tokenCeiling))
		out.Truncated.Total = len(matched)
	}
	if format == render.FormatTable {
		out.Table = clusterTable(out.Clusters)
		out.Clusters = nil
	}
	return out, nil
}

// matchesFilter applies the case-insensitive substring test.
func matchesFilter(c fleet.Cluster, needle string) bool {
	return strings.Contains(strings.ToLower(c.ID), needle) ||
		strings.Contains(strings.ToLower(c.DisplayName), needle) ||
		strings.Contains(strings.ToLower(c.Description), needle)
}

// summarize projects a registry entry onto a [ClusterSummary]. Every free-text
// field is sanitised: a display name and a description are operator-supplied,
// but the operator in question runs one of a hundred monitored clusters.
func summarize(c fleet.Cluster, now time.Time) ClusterSummary {
	age := factsAge(c, now)
	s := ClusterSummary{
		Name:            c.ID,
		DisplayName:     render.ClipRunes(c.DisplayName, 128),
		Description:     render.ClipRunes(c.Description, 200),
		Status:          clusterStatus(c),
		Labels:          render.Labels(c.Labels),
		PromVersion:     render.ClipRunes(c.Prometheus.Version, 64),
		PromFlavor:      render.ClipRunes(c.Prometheus.Flavor, 32),
		Retention:       render.ClipRunes(c.Prometheus.Retention, 32),
		ScrapeInterval:  render.ClipRunes(c.Prometheus.ScrapeInterval, 32),
		JobCount:        len(c.Prometheus.Jobs),
		AlertsFiring:    c.Prometheus.FiringAlerts,
		RuleGroups:      c.Prometheus.RuleGroups,
		Alertmanager:    c.Prometheus.HasAlertmanager,
		FactsAgeSeconds: int64(age.Seconds()),
		Stale:           age > StaleFactsAfter,
	}
	if c.Prometheus.ActiveSeries > 0 {
		s.ActiveSeries = c.Prometheus.ActiveSeries
	}
	return s
}

// clusterStatus collapses the registry state and the spoke's Prometheus
// reachability into the single word an agent routes on.
func clusterStatus(c fleet.Cluster) string {
	switch {
	case c.State == fleet.StateConnected && c.Prometheus.Reachable:
		return StatusHealthy
	case c.State == fleet.StateConnected, c.State == fleet.StateDegraded:
		return StatusDegraded
	default:
		return StatusUnreachable
	}
}

// clusterTable renders a cluster listing as fixed-width text, which is the
// cheapest encoding for a wide, shallow result: a column name is paid for once
// in the header instead of once per row as a JSON object key.
func clusterTable(cs []ClusterSummary) string {
	headers := []string{"NAME", "STATUS", "VERSION", "SERIES", "JOBS", "FIRING", "AM"}
	rows := make([][]string, 0, len(cs))
	for _, c := range cs {
		rows = append(rows, []string{
			c.Name,
			c.Status,
			c.PromVersion,
			strconv.FormatInt(c.ActiveSeries, 10),
			strconv.Itoa(c.JobCount),
			strconv.FormatInt(int64(c.AlertsFiring), 10),
			strconv.FormatBool(c.Alertmanager),
		})
	}
	return render.Table(headers, rows)
}
