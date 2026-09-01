// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"net/url"
	"slices"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// QueryExemplarsIn is the argument object of query_exemplars.
type QueryExemplarsIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Query is a PromQL selector.
	Query string `json:"query" jsonschema:"A PromQL selector, e.g. http_request_duration_seconds_bucket{job=\"api\"}. Exemplars attach to a raw series, not to an aggregation: wrapping this in rate() or sum() returns nothing."`
	// Start and End bound the lookup.
	Start string `json:"start,omitempty" jsonschema:"Range start. Relative (\"now-1h\") or RFC 3339. Defaults to now-1h."`
	End   string `json:"end,omitempty" jsonschema:"Range end, same forms as start. Defaults to now."`
	// Limit caps the returned exemplars.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum exemplars to return across every matching series. Exemplars are returned most-recent first."`
}

// ExemplarInfo is one exemplar: a sampled value tagged with the trace or span
// that produced it, which is the shortest path from an aggregate metric to
// the one request that explains it.
type ExemplarInfo struct {
	// SeriesLabels are the labels of the series the exemplar was attached to.
	SeriesLabels map[string]string `json:"seriesLabels,omitempty"`
	// Labels are the exemplar's own labels, typically trace_id and span_id.
	// They are remote data: whoever instruments the monitored application
	// chooses them, and they are sanitised the same as any other label set.
	Labels map[string]string `json:"labels,omitempty"`
	// Value is the sampled value at the exemplar's timestamp.
	Value string `json:"value,omitempty"`
	// TimestampMillis is when the exemplar was recorded, Unix milliseconds.
	TimestampMillis int64 `json:"timestampMillis,omitempty"`
}

// QueryExemplarsOut is the result of query_exemplars.
type QueryExemplarsOut struct {
	Envelope
	// Exemplars are the matching exemplars, most recent first.
	Exemplars []ExemplarInfo `json:"exemplars,omitempty"`
	// SeriesMatched is how many distinct series carried at least one
	// exemplar in the window, before any limit.
	SeriesMatched int `json:"seriesMatched,omitempty"`
	// Total is how many exemplars matched before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when exemplars were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// upstreamExemplars is the /api/v1/query_exemplars payload: one entry per
// series that carried at least one exemplar in the window.
type upstreamExemplars []struct {
	SeriesLabels map[string]string `json:"seriesLabels"`
	Exemplars    []struct {
		Labels    map[string]string `json:"labels"`
		Value     string            `json:"value"`
		Timestamp float64           `json:"timestamp"`
	} `json:"exemplars"`
}

// queryExemplars reports exemplars for a series selector over a time range.
//
// An empty result is not evidence of "nothing happened": exemplar storage is
// an opt-in Prometheus feature and most instrumentation does not attach trace
// context to every metric, so a fleet that has never enabled either will
// always answer empty. The tool description says so; this function does not
// try to distinguish the two, because Prometheus itself does not.
func (t *Tools) queryExemplars(
	ctx context.Context, p *fleet.Principal, in QueryExemplarsIn,
) (*QueryExemplarsOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	if terr := validateExpr(in.Query, in.Cluster); terr != nil {
		return nil, terr
	}
	start, end, terr := t.resolveRange(p, in.Start, in.End, t.now(), map[string]any{
		"cluster": c.ID, "query": render.ClipRunes(in.Query, 512), "start": in.Start, "end": in.End,
	})
	if terr != nil {
		return nil, terr
	}

	form := url.Values{}
	form.Set("query", in.Query)
	form.Set("start", formatUpstreamTime(start))
	form.Set("end", formatUpstreamTime(end))

	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointQueryExemplars,
		Form:      form,
	}, kindQuery)
	if terr != nil {
		return nil, terr
	}
	var raw upstreamExemplars
	if terr := decodeData(env, c.ID, &raw); terr != nil {
		return nil, terr
	}

	flat := make([]ExemplarInfo, 0, len(raw))
	for _, series := range raw {
		sl := render.Labels(series.SeriesLabels)
		for _, e := range series.Exemplars {
			flat = append(flat, ExemplarInfo{
				SeriesLabels:    sl,
				Labels:          render.Labels(e.Labels),
				Value:           render.ClipRunes(e.Value, 64),
				TimestampMillis: int64(e.Timestamp * 1000),
			})
		}
	}
	// Most recent first: an agent chasing an incident wants the exemplar
	// nearest to "now" from a truncated result, not the oldest one in the
	// window.
	slices.SortStableFunc(flat, func(a, b ExemplarInfo) int {
		switch {
		case a.TimestampMillis > b.TimestampMillis:
			return -1
		case a.TimestampMillis < b.TimestampMillis:
			return 1
		default:
			return 0
		}
	})

	out := &QueryExemplarsOut{Envelope: untrusted(), SeriesMatched: len(raw), Total: len(flat)}
	limit := clampInt(in.Limit, 100, 1, 500)
	kept, trunc := render.TruncateItems(flat, limit,
		"Narrow the selector or the time range rather than raising limit; exemplars are "+
			"returned most-recent first, so a truncated result drops the oldest.")
	out.Truncated = trunc
	fitted, hit := render.FitTokens(kept, t.tokenCeiling, func(s []ExemplarInfo) any {
		return &QueryExemplarsOut{Exemplars: s}
	})
	if hit {
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Narrow the selector or the time range.", t.tokenCeiling))
		out.Truncated.Total = len(flat)
	}
	out.Exemplars = fitted
	return out, nil
}
