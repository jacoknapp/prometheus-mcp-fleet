// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Search modes accepted by search_metrics.
const (
	// ModeSubstring is a case-insensitive substring test. It is the default
	// because it is what an agent means nine times in ten and cannot be
	// written wrongly.
	ModeSubstring = "substring"
	// ModeRegex is an RE2 pattern, anchored nowhere.
	ModeRegex = "regex"
)

// MetadataName is the label whose values are the metric names. It is the one
// place this package needs a magic label name, and naming it once keeps that
// visible.
const MetadataName = "__name__"

// SearchMetricsIn is the argument object of search_metrics.
type SearchMetricsIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Pattern is the search text.
	Pattern string `json:"pattern" jsonschema:"Text to search for in metric names, e.g. \"checkout\" or \"^container_cpu\"."`
	// Mode selects substring or regex matching.
	Mode string `json:"mode,omitempty" jsonschema:"How to interpret pattern."`
	// Limit caps the returned metrics.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum metric names to return."`
	// WithMetadata joins type, help and unit onto each match.
	WithMetadata bool `json:"withMetadata,omitempty" jsonschema:"Join the metric type, unit and a clipped help string onto each match. Costs one extra upstream call."`
}

// MetricInfo is one metric name with whatever metadata the cluster published.
type MetricInfo struct {
	// Name is the metric name.
	Name string `json:"name,omitempty"`
	// Type is the exposition type: counter, gauge, histogram, summary or
	// untyped. It decides whether an agent should wrap the metric in rate().
	Type string `json:"type,omitempty"`
	// Unit is the declared unit, when the exposition carried one.
	Unit string `json:"unit,omitempty"`
	// Help is the help string, clipped and sanitised. It is remote data.
	Help string `json:"help,omitempty"`
}

// SearchMetricsOut is the result of search_metrics.
type SearchMetricsOut struct {
	Envelope
	// Metrics are the matches, ordered by name.
	Metrics []MetricInfo `json:"metrics,omitempty"`
	// Total is how many names matched before truncation.
	Total int `json:"total,omitempty"`
	// Scanned is how many metric names exist in the cluster, which tells an
	// agent whether a zero-result search means "no such metric" or "this
	// cluster reports nothing".
	Scanned int `json:"scanned,omitempty"`
	// Truncated is set when matches were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// searchMetrics finds metric names, optionally joined with their metadata.
func (t *Tools) searchMetrics(
	ctx context.Context, p *fleet.Principal, in SearchMetricsIn,
) (*SearchMetricsOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	if in.Pattern == "" {
		return nil, newError(CodeInvalidArgument, "pattern is required", false).
			WithInput(map[string]any{"cluster": c.ID}).
			WithHint("Search for a substring of the metric name, e.g. \"cpu\".")
	}
	if len(in.Pattern) > 200 {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("pattern is %d bytes, above the 200 byte limit", len(in.Pattern)),
			false).WithInput(map[string]any{"cluster": c.ID})
	}
	mode := in.Mode
	if mode == "" {
		mode = ModeSubstring
	}
	var match func(string) bool
	switch mode {
	case ModeSubstring:
		needle := strings.ToLower(in.Pattern)
		match = func(s string) bool { return strings.Contains(strings.ToLower(s), needle) }
	case ModeRegex:
		re, err := regexp.Compile(in.Pattern)
		if err != nil {
			return nil, newError(CodeBadRegex, err.Error(), false).
				WithInput(map[string]any{
					"cluster": c.ID, "pattern": render.ClipRunes(in.Pattern, 200), "mode": mode}).
				WithHint("Patterns are RE2: no backreferences and no lookahead. " +
					"Retry with mode \"substring\" if you only need a plain search.")
		}
		match = re.MatchString
	default:
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("mode %q is not one of substring, regex", render.ClipRunes(mode, 32)),
			false).WithInput(map[string]any{"cluster": c.ID, "mode": render.ClipRunes(mode, 32)})
	}

	names, terr := t.labelValuesOf(ctx, p, c.ID, MetadataName, nil, time.Time{}, time.Time{})
	if terr != nil {
		return nil, terr
	}
	matched := make([]string, 0, 64)
	for _, n := range names {
		if match(n) {
			matched = append(matched, n)
		}
	}
	slices.Sort(matched)

	limit := clampInt(in.Limit, 50, 1, 500)
	kept, trunc := render.TruncateItems(matched, limit,
		"Narrow the pattern, or raise limit (max 500). Names are returned in sorted order, "+
			"so a truncated result is a prefix, not a sample.")

	out := &SearchMetricsOut{
		Envelope:  untrusted(),
		Total:     len(matched),
		Scanned:   len(names),
		Truncated: trunc,
	}
	out.Metrics = make([]MetricInfo, 0, len(kept))
	for _, n := range kept {
		out.Metrics = append(out.Metrics, MetricInfo{Name: render.ClipRunes(n, 256)})
	}
	if in.WithMetadata && len(out.Metrics) > 0 {
		meta, terr := t.metadataOf(ctx, p, c.ID, "")
		if terr != nil {
			// Metadata is an enrichment, not the answer. A cluster that does
			// not serve it must not turn a working search into a failure.
			t.log.DebugContext(ctx, "mcptools: metric metadata unavailable", "code", terr.Code)
		} else {
			for i := range out.Metrics {
				if m, ok := meta[out.Metrics[i].Name]; ok {
					out.Metrics[i].Type = m.Type
					out.Metrics[i].Unit = m.Unit
					out.Metrics[i].Help = m.Help
				}
			}
		}
	}
	fitted, hit := render.FitTokens(out.Metrics, t.tokenCeiling, func(m []MetricInfo) any {
		return &SearchMetricsOut{Metrics: m}
	})
	if hit {
		out.Metrics = fitted
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Narrow the pattern, or set withMetadata false.", t.tokenCeiling))
		out.Truncated.Total = len(matched)
	}
	return out, nil
}

// MetricMetadataIn is the argument object of metric_metadata.
type MetricMetadataIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Metric restricts the answer to one metric.
	Metric string `json:"metric,omitempty" jsonschema:"Single metric name. Omit to list metadata for every metric the cluster publishes."`
	// Limit caps the returned entries.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum entries to return."`
}

// MetricMetadataOut is the result of metric_metadata.
type MetricMetadataOut struct {
	Envelope
	// Metadata are the entries, ordered by metric name.
	Metadata []MetricInfo `json:"metadata,omitempty"`
	// Total is how many entries existed before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when entries were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// metricMetadata reports type, unit and help for metrics.
func (t *Tools) metricMetadata(
	ctx context.Context, p *fleet.Principal, in MetricMetadataIn,
) (*MetricMetadataOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	if in.Metric != "" && !metricNameRE.MatchString(in.Metric) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("%q is not a valid metric name", render.ClipRunes(in.Metric, 128)),
			false).WithInput(map[string]any{"cluster": c.ID, "metric": render.ClipRunes(in.Metric, 128)}).
			WithHint("Call search_metrics to find the exact name.")
	}
	meta, terr := t.metadataOf(ctx, p, c.ID, in.Metric)
	if terr != nil {
		return nil, terr
	}
	names := make([]string, 0, len(meta))
	for n := range meta {
		names = append(names, n)
	}
	slices.Sort(names)

	limit := clampInt(in.Limit, 100, 1, 1000)
	kept, trunc := render.TruncateItems(names, limit,
		"Pass a metric name to fetch one entry, or use search_metrics to narrow first.")

	out := &MetricMetadataOut{Envelope: untrusted(), Total: len(names), Truncated: trunc}
	out.Metadata = make([]MetricInfo, 0, len(kept))
	for _, n := range kept {
		out.Metadata = append(out.Metadata, meta[n])
	}
	fitted, hit := render.FitTokens(out.Metadata, t.tokenCeiling, func(m []MetricInfo) any {
		return &MetricMetadataOut{Metadata: m}
	})
	if hit {
		out.Metadata = fitted
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Pass a metric name instead.", t.tokenCeiling))
		out.Truncated.Total = len(names)
	}
	return out, nil
}

// metricNameRE is the Prometheus metric name grammar, including the colon
// recording rules use.
var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// upstreamMetadata is the /api/v1/metadata payload: metric name to one entry
// per exposing target.
type upstreamMetadata map[string][]struct {
	Type string `json:"type"`
	Help string `json:"help"`
	Unit string `json:"unit"`
}

// metadataOf fetches and sanitises metric metadata.
func (t *Tools) metadataOf(
	ctx context.Context, p *fleet.Principal, cluster, metric string,
) (map[string]MetricInfo, *ToolError) {
	form := url.Values{}
	if metric != "" {
		form.Set("metric", metric)
	}
	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: cluster,
		Endpoint:  promapi.EndpointMetadata,
		Form:      form,
	}, kindPlain)
	if terr != nil {
		return nil, terr
	}
	var raw upstreamMetadata
	if terr := decodeData(env, cluster, &raw); terr != nil {
		return nil, terr
	}
	out := make(map[string]MetricInfo, len(raw))
	for name, entries := range raw {
		if !metricNameRE.MatchString(name) {
			// A metric name outside the grammar cannot have come from a
			// well-formed exposition, and would become an object key an agent
			// looks up by attacker-chosen bytes.
			continue
		}
		info := MetricInfo{Name: name}
		if len(entries) > 0 {
			info.Type = render.ClipRunes(entries[0].Type, 32)
			info.Unit = render.ClipRunes(entries[0].Unit, 32)
			info.Help = render.Help(entries[0].Help)
		}
		out[name] = info
	}
	return out, nil
}

// TargetMetadataIn is the argument object of target_metadata.
type TargetMetadataIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// MatchTarget scopes the lookup to targets whose labels match.
	MatchTarget string `json:"matchTarget,omitempty" jsonschema:"Selector matching targets by their own labels, e.g. {job=\"api\",instance=\"10.0.0.1:9100\"}. Omit to match every target."`
	// Metric restricts the answer to one metric.
	Metric string `json:"metric,omitempty" jsonschema:"Single metric name. Omit to list every metric each matched target reports, which is how you catch a canary and a stable rollout disagreeing on a metric's type."`
	// Limit caps the returned entries.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum entries to return."`
}

// TargetMetadataEntry is one target's metadata for one metric.
//
// This differs from metric_metadata in exactly one way: metric_metadata
// aggregates one entry per metric across the whole cluster, which silently
// picks a winner when two targets disagree. This tool keeps every target's
// answer separate, which is the only way to see that disagreement at all —
// the case that actually matters is a mixed-version rollout where the same
// metric name means two different things depending which pod answered.
type TargetMetadataEntry struct {
	// Target is the reporting target's own labels.
	Target map[string]string `json:"target,omitempty"`
	// Metric is the metric name this entry describes.
	Metric string `json:"metric,omitempty"`
	// Type is the exposition type.
	Type string `json:"type,omitempty"`
	// Unit is the declared unit, when the exposition carried one.
	Unit string `json:"unit,omitempty"`
	// Help is the help string, clipped and sanitised. It is remote data.
	Help string `json:"help,omitempty"`
}

// TargetMetadataOut is the result of target_metadata.
type TargetMetadataOut struct {
	Envelope
	// Metadata are the entries, ordered by metric name then target.
	Metadata []TargetMetadataEntry `json:"metadata,omitempty"`
	// Total is how many entries existed before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when entries were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// upstreamTargetMetadata is the /api/v1/targets/metadata payload. Metric is
// present only when the request did not itself filter by metric; when it did,
// every entry describes that one metric and Metric arrives empty.
type upstreamTargetMetadata []struct {
	Target map[string]string `json:"target"`
	Metric string            `json:"metric"`
	Type   string            `json:"type"`
	Help   string            `json:"help"`
	Unit   string            `json:"unit"`
}

// targetMetadata reports metric metadata as individual targets report it,
// rather than aggregated across the cluster.
func (t *Tools) targetMetadata(
	ctx context.Context, p *fleet.Principal, in TargetMetadataIn,
) (*TargetMetadataOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	if in.Metric != "" && !metricNameRE.MatchString(in.Metric) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("%q is not a valid metric name", render.ClipRunes(in.Metric, 128)),
			false).WithInput(map[string]any{"cluster": c.ID, "metric": render.ClipRunes(in.Metric, 128)}).
			WithHint("Call search_metrics to find the exact name.")
	}
	matchers, terr := validateMatchers([]string{in.MatchTarget}, c.ID, false)
	if terr != nil {
		return nil, terr
	}

	form := url.Values{}
	if len(matchers) > 0 {
		form.Set("match_target", matchers[0])
	}
	if in.Metric != "" {
		form.Set("metric", in.Metric)
	}

	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointTargetsMetadata,
		Form:      form,
	}, kindSelector)
	if terr != nil {
		return nil, terr
	}
	var raw upstreamTargetMetadata
	if terr := decodeData(env, c.ID, &raw); terr != nil {
		return nil, terr
	}

	entries := make([]TargetMetadataEntry, 0, len(raw))
	for _, e := range raw {
		name := e.Metric
		if name == "" {
			name = in.Metric
		}
		if name == "" || !metricNameRE.MatchString(name) {
			// A metric name outside the grammar cannot have come from a
			// well-formed exposition, and an empty one means neither the
			// request nor the response named it.
			continue
		}
		entries = append(entries, TargetMetadataEntry{
			Target: render.Labels(e.Target),
			Metric: name,
			Type:   render.ClipRunes(e.Type, 32),
			Unit:   render.ClipRunes(e.Unit, 32),
			Help:   render.Help(e.Help),
		})
	}
	slices.SortStableFunc(entries, func(a, b TargetMetadataEntry) int {
		if v := strings.Compare(a.Metric, b.Metric); v != 0 {
			return v
		}
		return strings.Compare(labelsText(a.Target), labelsText(b.Target))
	})

	out := &TargetMetadataOut{Envelope: untrusted(), Total: len(entries)}
	limit := clampInt(in.Limit, 100, 1, 1000)
	kept, trunc := render.TruncateItems(entries, limit,
		"Pass metric or matchTarget to narrow rather than raising limit.")
	out.Truncated = trunc
	fitted, hit := render.FitTokens(kept, t.tokenCeiling, func(m []TargetMetadataEntry) any {
		return &TargetMetadataOut{Metadata: m}
	})
	if hit {
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Pass metric or matchTarget to narrow.", t.tokenCeiling))
		out.Truncated.Total = len(entries)
	}
	out.Metadata = fitted
	return out, nil
}

// SeriesIn is the argument object of series.
type SeriesIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Matchers are the series selectors.
	Matchers []string `json:"matchers" jsonschema:"One or more PromQL series selectors, e.g. [\"up{job=\\\"api\\\"}\"]. A bare label name is not a selector."`
	// Start and End bound the lookup.
	Start string `json:"start,omitempty" jsonschema:"Range start. Relative (\"now-1h\") or RFC 3339. Defaults to now-1h."`
	End   string `json:"end,omitempty" jsonschema:"Range end, same forms as start. Defaults to now."`
	// Limit caps the returned rows.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum label sets to return."`
	// Format selects the encoding.
	Format string `json:"format,omitempty" jsonschema:"Output encoding. compact is columnar; table is fixed-width text; json is the raw Prometheus shape."`
}

// SeriesOut is the result of series. It is columnar: the union of label keys
// is declared once as Columns and each row is a bare array, rather than every
// row repeating every key.
type SeriesOut struct {
	Envelope
	// Columns is the union of label names across the returned series.
	Columns []string `json:"columns,omitempty"`
	// Rows are the label values, positionally aligned with Columns.
	Rows [][]string `json:"rows,omitempty"`
	// Total is how many series matched before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when rows were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
	// Table is the fixed-width rendering, set only for format "table".
	Table string `json:"table,omitempty"`
	// Raw is the unmodified Prometheus payload, set only for format "json".
	Raw any `json:"raw,omitempty"`
}

// series lists the label sets matching a set of selectors.
func (t *Tools) series(
	ctx context.Context, p *fleet.Principal, in SeriesIn,
) (*SeriesOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	format, terr := parseFormat(in.Format, true)
	if terr != nil {
		return nil, terr
	}
	matchers, terr := validateMatchers(in.Matchers, c.ID, true)
	if terr != nil {
		return nil, terr
	}
	start, end, terr := t.resolveRange(in.Start, in.End, t.now(), map[string]any{
		"cluster": c.ID, "matchers": matchers, "start": in.Start, "end": in.End,
	})
	if terr != nil {
		return nil, terr
	}

	form := url.Values{"match[]": matchers}
	form.Set("start", formatUpstreamTime(start))
	form.Set("end", formatUpstreamTime(end))

	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointSeries,
		Form:      form,
	}, kindSelector)
	if terr != nil {
		return nil, terr
	}

	out := &SeriesOut{Envelope: untrusted()}
	if format == render.FormatJSON {
		est := render.EstimateTokensOfBytes(len(env.Data))
		if t.tokenCeiling > 0 && est > t.tokenCeiling {
			out.Truncated = tokenCeilingTruncation(est, t.tokenCeiling)
			return out, nil
		}
		out.Raw = rawMessage(env.Data)
		return out, nil
	}

	var sets []map[string]string
	if terr := decodeData(env, c.ID, &sets); terr != nil {
		return nil, terr
	}
	out.Total = len(sets)

	limit := clampInt(in.Limit, 100, 1, 1000)
	kept, trunc := render.TruncateItems(sets, limit,
		"Add a tighter matcher rather than raising limit; a series listing grows with "+
			"cardinality and is the fastest way to spend a context window.")
	out.Truncated = trunc

	fitted, hit := render.FitTokens(kept, t.tokenCeiling, func(s []map[string]string) any {
		cols, rows := columnar(s)
		return &SeriesOut{Columns: cols, Rows: rows}
	})
	if hit {
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Add a tighter matcher.", t.tokenCeiling))
		out.Truncated.Total = len(sets)
	}
	out.Columns, out.Rows = columnar(fitted)
	if format == render.FormatTable {
		headers := make([]string, len(out.Columns))
		for i, c := range out.Columns {
			headers[i] = strings.ToUpper(c)
		}
		out.Table = render.Table(headers, out.Rows)
		out.Columns, out.Rows = nil, nil
	}
	return out, nil
}

// columnar turns label sets into a shared column list and bare value rows,
// which is where the saving over one object per series comes from.
func columnar(sets []map[string]string) ([]string, [][]string) {
	keys := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			if render.ValidLabelName(k) {
				keys[k] = true
			}
		}
	}
	cols := make([]string, 0, len(keys))
	for k := range keys {
		cols = append(cols, k)
	}
	// __name__ first, then alphabetical: the metric name is what an agent
	// reads first and a stable order makes repeated calls diffable.
	slices.SortFunc(cols, func(a, b string) int {
		switch {
		case a == MetadataName:
			return -1
		case b == MetadataName:
			return 1
		}
		return strings.Compare(a, b)
	})
	rows := make([][]string, 0, len(sets))
	for _, s := range sets {
		row := make([]string, len(cols))
		for i, c := range cols {
			row[i] = render.LabelValue(s[c])
		}
		rows = append(rows, row)
	}
	return cols, rows
}

// LabelNamesIn is the argument object of label_names.
type LabelNamesIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Matchers scope the lookup.
	Matchers []string `json:"matchers,omitempty" jsonschema:"Optional series selectors scoping the lookup, e.g. [\"up{job=\\\"api\\\"}\"]."`
	// Start and End bound the lookup.
	Start string `json:"start,omitempty" jsonschema:"Range start. Relative (\"now-1h\") or RFC 3339. Defaults to now-1h."`
	End   string `json:"end,omitempty" jsonschema:"Range end, same forms as start. Defaults to now."`
	// Limit caps the returned names.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum label names to return."`
}

// LabelNamesOut is the result of label_names.
type LabelNamesOut struct {
	Envelope
	// Names are the label names, sorted.
	Names []string `json:"names,omitempty"`
	// Total is how many existed before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when names were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// labelNames lists label names, optionally scoped by matchers.
func (t *Tools) labelNames(
	ctx context.Context, p *fleet.Principal, in LabelNamesIn,
) (*LabelNamesOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	matchers, terr := validateMatchers(in.Matchers, c.ID, false)
	if terr != nil {
		return nil, terr
	}
	start, end, terr := t.resolveRange(in.Start, in.End, t.now(), map[string]any{
		"cluster": c.ID, "matchers": matchers, "start": in.Start, "end": in.End,
	})
	if terr != nil {
		return nil, terr
	}
	form := url.Values{}
	if len(matchers) > 0 {
		form["match[]"] = matchers
	}
	form.Set("start", formatUpstreamTime(start))
	form.Set("end", formatUpstreamTime(end))

	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointLabels,
		Form:      form,
	}, kindSelector)
	if terr != nil {
		return nil, terr
	}
	var names []string
	if terr := decodeData(env, c.ID, &names); terr != nil {
		return nil, terr
	}
	clean := make([]string, 0, len(names))
	for _, n := range names {
		if render.ValidLabelName(n) {
			clean = append(clean, n)
		}
	}
	slices.Sort(clean)
	limit := clampInt(in.Limit, 200, 1, 2000)
	kept, trunc := render.TruncateItems(clean, limit,
		"Scope the lookup with matchers rather than raising limit.")
	return &LabelNamesOut{
		Envelope:  untrusted(),
		Names:     kept,
		Total:     len(clean),
		Truncated: trunc,
	}, nil
}

// LabelValuesIn is the argument object of label_values.
type LabelValuesIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Label is the label whose values are wanted.
	Label string `json:"label" jsonschema:"Label name whose values to list, e.g. \"job\" or \"namespace\". Use \"__name__\" for metric names."`
	// Matchers scope the lookup.
	Matchers []string `json:"matchers,omitempty" jsonschema:"Optional series selectors scoping the lookup."`
	// Pattern filters the values at the hub.
	Pattern string `json:"pattern,omitempty" jsonschema:"Optional case-insensitive substring filter applied to the values at the hub."`
	// Start and End bound the lookup.
	Start string `json:"start,omitempty" jsonschema:"Range start. Relative (\"now-1h\") or RFC 3339. Defaults to now-1h."`
	End   string `json:"end,omitempty" jsonschema:"Range end, same forms as start. Defaults to now."`
	// Limit caps the returned values.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum values to return."`
}

// LabelValuesOut is the result of label_values.
type LabelValuesOut struct {
	Envelope
	// Label echoes the label that was queried.
	Label string `json:"label,omitempty"`
	// Values are the label's values, sorted.
	Values []string `json:"values,omitempty"`
	// Total is how many matched before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when values were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// labelValues lists the values of one label.
//
// A label that does not exist yields an empty list rather than an error: "no
// such label" and "that label has no values in this window" are the same
// observation to Prometheus, and an error would push the agent into a retry
// loop over a question that has been answered.
func (t *Tools) labelValues(
	ctx context.Context, p *fleet.Principal, in LabelValuesIn,
) (*LabelValuesOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	if err := promapi.ValidateLabelName(in.Label); err != nil {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("%q is not a valid label name", render.ClipRunes(in.Label, 128)),
			false).
			WithInput(map[string]any{"cluster": c.ID, "label": render.ClipRunes(in.Label, 128)}).
			WithHint("Call label_names to see the labels that exist on this cluster.")
	}
	matchers, terr := validateMatchers(in.Matchers, c.ID, false)
	if terr != nil {
		return nil, terr
	}
	start, end, terr := t.resolveRange(in.Start, in.End, t.now(), map[string]any{
		"cluster": c.ID, "label": in.Label, "start": in.Start, "end": in.End,
	})
	if terr != nil {
		return nil, terr
	}
	values, terr := t.labelValuesOf(ctx, p, c.ID, in.Label, matchers, start, end)
	if terr != nil {
		return nil, terr
	}
	if in.Pattern != "" {
		needle := strings.ToLower(in.Pattern)
		filtered := values[:0:0]
		for _, v := range values {
			if strings.Contains(strings.ToLower(v), needle) {
				filtered = append(filtered, v)
			}
		}
		values = filtered
	}
	limit := clampInt(in.Limit, 100, 1, 2000)
	kept, trunc := render.TruncateItems(values, limit,
		"Add matchers or a pattern rather than raising limit; a high-cardinality label "+
			"such as pod can have hundreds of thousands of values.")
	out := &LabelValuesOut{
		Envelope:  untrusted(),
		Label:     in.Label,
		Values:    kept,
		Total:     len(values),
		Truncated: trunc,
	}
	fitted, hit := render.FitTokens(kept, t.tokenCeiling, func(v []string) any {
		return &LabelValuesOut{Values: v}
	})
	if hit {
		out.Values = fitted
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Add matchers or a pattern.", t.tokenCeiling))
		out.Truncated.Total = len(values)
	}
	return out, nil
}

// labelValuesOf fetches and sanitises the values of one label.
func (t *Tools) labelValuesOf(
	ctx context.Context, p *fleet.Principal, cluster, label string,
	matchers []string, start, end time.Time,
) ([]string, *ToolError) {
	form := url.Values{}
	if len(matchers) > 0 {
		form["match[]"] = matchers
	}
	if !start.IsZero() {
		form.Set("start", formatUpstreamTime(start))
	}
	if !end.IsZero() {
		form.Set("end", formatUpstreamTime(end))
	}
	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: cluster,
		Endpoint:  promapi.EndpointLabelValues,
		LabelName: label,
		Form:      form,
	}, kindSelector)
	if terr != nil {
		return nil, terr
	}
	var values []string
	if terr := decodeData(env, cluster, &values); terr != nil {
		return nil, terr
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if c := render.LabelValue(v); c != "" {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out, nil
}

// validateMatchers screens series selectors before they are forwarded.
//
// The check is structural, not a parse: this project deliberately does not
// depend on the Prometheus parser (see docs/adr/0006), and Prometheus itself
// is the authority. What is caught here are the two mistakes a model actually
// makes — a bare label name where a selector belongs, and an empty list.
func validateMatchers(in []string, cluster string, required bool) ([]string, *ToolError) {
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if len(m) > promapi.MaxParamBytes {
			return nil, newError(CodeBadMatcher,
				fmt.Sprintf("matcher is %d bytes, above the %d byte limit",
					len(m), promapi.MaxParamBytes), false).
				WithInput(map[string]any{"cluster": cluster})
		}
		if !strings.ContainsAny(m, "{}") && !metricNameRE.MatchString(m) {
			return nil, newError(CodeBadMatcher,
				fmt.Sprintf("%q is not a series selector", render.ClipRunes(m, 200)), false).
				WithInput(map[string]any{
					"cluster": cluster, "matchers": clipAll(in, 200)}).
				WithHint(`A selector is a metric name, a brace expression, or both: ` +
					`up, {job="api"} or up{job="api"}. A bare label name is not a selector.`)
		}
		out = append(out, m)
	}
	if required && len(out) == 0 {
		return nil, newError(CodeBadMatcher, "at least one matcher is required", false).
			WithInput(map[string]any{"cluster": cluster}).
			WithHint(`Pass a selector such as {job="api"}. Call label_values with label ` +
				`"job" to find one.`)
	}
	return out, nil
}

// clipAll sanitises and clips every element of a slice for an error echo.
func clipAll(in []string, max int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, render.ClipRunes(s, max))
	}
	return out
}
