// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// ExplainPromQLIn is the argument object of explain_promql.
type ExplainPromQLIn struct {
	// Query is the expression to check.
	Query string `json:"query" jsonschema:"PromQL expression to check. It is never evaluated, so this is safe to call on an expression you are unsure about."`
	// Cluster optionally checks the referenced metrics exist.
	Cluster string `json:"cluster,omitempty" jsonschema:"Optional cluster to check the referenced metric names against. Costs one cheap metadata call and turns a typo into a named suggestion."`
}

// ExplainPromQLOut is the result of explain_promql.
//
// This tool never returns isError, which is the whole point of it: an invalid
// expression is the answer, not a failure, and an isError result would tell
// the model its call went wrong rather than its query.
type ExplainPromQLOut struct {
	Envelope
	// Valid reports whether the expression survived structural checking. It is
	// always present, including on a well-formed expression, because "no field"
	// is not something a model reliably reads as "yes".
	Valid bool `json:"valid"`
	// Query echoes what was checked.
	Query string `json:"query,omitempty"`
	// Message describes the fault, when there is one, in Prometheus' own
	// wording.
	Message string `json:"message,omitempty"`
	// Caret aligns under the offending character of Query.
	Caret string `json:"caret,omitempty"`
	// Summary describes in one line what the expression does.
	Summary string `json:"summary,omitempty"`
	// MetricsReferenced are the metric names the expression names.
	MetricsReferenced []string `json:"metricsReferenced,omitempty"`
	// UnknownMetrics are those the named cluster does not publish. It is set
	// only when cluster was supplied.
	UnknownMetrics []string `json:"unknownMetrics,omitempty"`
	// LabelsReferenced are the label names used in matchers and grouping.
	LabelsReferenced []string `json:"labelsReferenced,omitempty"`
	// Functions and Aggregations are the operators used.
	Functions    []string `json:"functions,omitempty"`
	Aggregations []string `json:"aggregations,omitempty"`
	// RangeWindows are the bracketed durations, e.g. "5m".
	RangeWindows []string `json:"rangeWindows,omitempty"`
	// Suggestions are advisory notes and corrections.
	Suggestions []string `json:"suggestions,omitempty"`
	// ClusterChecked names the cluster metric existence was checked against,
	// empty when no check was made.
	ClusterChecked string `json:"clusterChecked,omitempty"`
	// CheckSkipped explains why an existence check did not happen, so a caller
	// does not read an empty unknownMetrics as "everything exists".
	CheckSkipped string `json:"checkSkipped,omitempty"`
}

// explainPromQL validates and describes an expression without running it.
//
// One check costs about two hundred tokens. A query_range that fails on a
// typo, after the model has waited for it, costs the round trip and the
// recovery turn; a query_range that *succeeds* on the wrong expression costs
// far more than that. This is the cheapest tool in the catalogue and the tool
// descriptions point at it from every PromQL error.
func (t *Tools) explainPromQL(
	ctx context.Context, p *fleet.Principal, in ExplainPromQLIn,
) (*ExplainPromQLOut, *ToolError) {
	q := strings.TrimSpace(in.Query)
	out := &ExplainPromQLOut{
		Envelope: untrusted(),
		Query:    render.ClipRunes(in.Query, 1024),
	}
	if q == "" {
		out.Valid = false
		out.Message = "the expression is empty"
		out.Suggestions = []string{
			"Start from a metric name: call search_metrics with a substring of what you are " +
				"looking for, then query it.",
		}
		return out, nil
	}
	if len(q) > MaxPromQLBytes {
		out.Valid = false
		out.Message = fmt.Sprintf("the expression is %d bytes, above the %d byte limit this hub "+
			"will forward", len(q), MaxPromQLBytes)
		return out, nil
	}

	a := analyzePromQL(q)
	out.Valid = a.Valid
	out.Message = a.Message
	out.MetricsReferenced = a.Metrics
	out.LabelsReferenced = a.Labels
	out.Functions = a.Functions
	out.Aggregations = a.Aggregations
	out.RangeWindows = a.RangeWindows
	out.Suggestions = a.Suggestions
	out.Summary = summarizeAnalysis(a)
	if !a.Valid && a.Position > 0 {
		col := min(a.Position, len(q)+1)
		out.Caret = strings.Repeat(" ", col-1) + "^"
	}

	if in.Cluster == "" || len(a.Metrics) == 0 {
		if in.Cluster == "" && len(a.Metrics) > 0 {
			out.CheckSkipped = "No cluster was named, so metric existence was not checked. " +
				"Pass cluster to have the names verified."
		}
		return out, nil
	}

	// Existence checking is best-effort enrichment. A cluster that cannot be
	// reached must not turn a structural answer into a failure: the caller
	// asked whether the expression is well formed, and it is.
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		out.CheckSkipped = fmt.Sprintf(
			"Metric existence was not checked: %s. The structural answer above still holds.",
			terr.Message)
		return out, nil //nolint:nilerr // deliberate: the structural answer stands, the enrichment is best-effort.
	}
	names, terr := t.labelValuesOf(ctx, p, c.ID, MetadataName, nil, time.Time{}, time.Time{})
	if terr != nil {
		out.CheckSkipped = fmt.Sprintf(
			"Metric existence was not checked: %s. The structural answer above still holds.",
			terr.Message)
		return out, nil //nolint:nilerr // deliberate: the structural answer stands, the enrichment is best-effort.
	}
	out.ClusterChecked = c.ID
	known := make(map[string]bool, len(names))
	for _, n := range names {
		known[n] = true
	}
	for _, m := range a.Metrics {
		if known[m] {
			continue
		}
		out.UnknownMetrics = append(out.UnknownMetrics, m)
		if near := nearestNames(m, names, 3); len(near) > 0 {
			out.Suggestions = append(out.Suggestions, fmt.Sprintf(
				"%q does not exist in cluster %q. Did you mean %s?",
				m, c.ID, strings.Join(quoteAll(near), ", ")))
		} else {
			out.Suggestions = append(out.Suggestions, fmt.Sprintf(
				"%q does not exist in cluster %q. Call search_metrics to find the right name.",
				m, c.ID))
		}
	}
	return out, nil
}

// summarizeAnalysis renders the one-line description of an expression.
func summarizeAnalysis(a promQLAnalysis) string {
	if !a.Valid {
		return ""
	}
	parts := make([]string, 0, 6)
	switch a.Selectors {
	case 0:
	case 1:
		parts = append(parts, "1 series selector")
	default:
		parts = append(parts, fmt.Sprintf("%d series selectors", a.Selectors))
	}
	if len(a.Functions) > 0 {
		parts = append(parts, "functions "+strings.Join(a.Functions, ", "))
	}
	if len(a.Aggregations) > 0 {
		parts = append(parts, "aggregations "+strings.Join(a.Aggregations, ", "))
	}
	if len(a.RangeWindows) > 0 {
		parts = append(parts, "range windows "+strings.Join(a.RangeWindows, ", "))
	}
	if a.Subqueries > 0 {
		parts = append(parts, fmt.Sprintf("%d subquer%s", a.Subqueries,
			plural(a.Subqueries, "y", "ies")))
	}
	if len(parts) == 0 {
		return "a constant expression: no series are read"
	}
	return strings.Join(parts, "; ")
}

// plural picks the singular or plural suffix.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// quoteAll wraps every element in double quotes for a message.
func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
