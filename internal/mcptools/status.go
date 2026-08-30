// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// tsdb_stats dimensions. Closed set, matching the four lists Prometheus'
// head-block statistics endpoint publishes.
const (
	// DimensionMetric ranks metric names by series count. It is the default
	// because "which metric is eating the head block" is the question.
	DimensionMetric = "metric"
	// DimensionLabelName ranks label names by distinct value count.
	DimensionLabelName = "labelName"
	// DimensionLabelValuePairs ranks label=value pairs by series count.
	DimensionLabelValuePairs = "labelValuePairs"
	// DimensionLabelMemory ranks label names by bytes of memory.
	DimensionLabelMemory = "labelMemory"
)

// allDimensions is the closed set the schema advertises.
var allDimensions = []string{
	DimensionMetric, DimensionLabelName, DimensionLabelValuePairs, DimensionLabelMemory,
}

// TSDBStatsIn is the argument object of tsdb_stats.
type TSDBStatsIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Dimension selects which ranking to return.
	Dimension string `json:"dimension,omitempty" jsonschema:"Which cardinality ranking to return."`
	// TopN caps the ranking.
	TopN int `json:"topN,omitempty" jsonschema:"How many entries of the ranking to return."`
}

// TSDBHead describes the head block itself.
type TSDBHead struct {
	// Series is the head-block series count.
	Series int64 `json:"series,omitempty"`
	// Chunks is the head-block chunk count.
	Chunks int64 `json:"chunks,omitempty"`
	// LabelPairs is how many distinct label pairs exist.
	LabelPairs int64 `json:"labelPairs,omitempty"`
	// MinTimeMillis and MaxTimeMillis bound the head block.
	MinTimeMillis int64 `json:"minTimeMillis,omitempty"`
	MaxTimeMillis int64 `json:"maxTimeMillis,omitempty"`
}

// TSDBEntry is one row of a cardinality ranking.
type TSDBEntry struct {
	// Name is the metric name, label name or label=value pair.
	Name string `json:"name,omitempty"`
	// Value is the count or byte figure for this dimension.
	Value int64 `json:"value,omitempty"`
	// PercentOfTotal is Value as a percentage of the head-block series count,
	// which is what turns "41203" into a decision.
	PercentOfTotal float64 `json:"percentOfTotal,omitempty"`
}

// TSDBStatsOut is the result of tsdb_stats.
type TSDBStatsOut struct {
	Envelope
	// Head describes the head block.
	Head TSDBHead `json:"head,omitzero"`
	// Dimension echoes which ranking Top holds.
	Dimension string `json:"dimension,omitempty"`
	// Top is the ranking, largest first.
	Top []TSDBEntry `json:"top,omitempty"`
	// Truncated is set when the ranking was cut to topN.
	Truncated *render.Truncation `json:"truncated,omitempty"`
}

// upstreamTSDB is the /api/v1/status/tsdb payload.
type upstreamTSDB struct {
	HeadStats struct {
		NumSeries     int64 `json:"numSeries"`
		NumLabelPairs int64 `json:"numLabelPairs"`
		ChunkCount    int64 `json:"chunkCount"`
		MinTime       int64 `json:"minTime"`
		MaxTime       int64 `json:"maxTime"`
	} `json:"headStats"`
	SeriesCountByMetricName     []tsdbPair `json:"seriesCountByMetricName"`
	LabelValueCountByLabelName  []tsdbPair `json:"labelValueCountByLabelName"`
	MemoryInBytesByLabelName    []tsdbPair `json:"memoryInBytesByLabelName"`
	SeriesCountByLabelValuePair []tsdbPair `json:"seriesCountByLabelValuePair"`
}

// tsdbPair is one name/value entry of a cardinality list.
type tsdbPair struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// tsdbStats reports head-block cardinality, which is where a cluster's cost
// actually lives.
func (t *Tools) tsdbStats(
	ctx context.Context, p *fleet.Principal, in TSDBStatsIn,
) (*TSDBStatsOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	dim := in.Dimension
	if dim == "" {
		dim = DimensionMetric
	}
	if !includes(allDimensions, dim) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("dimension %q is not one of %s",
				render.ClipRunes(dim, 32), strings.Join(allDimensions, ", ")), false).
			WithInput(map[string]any{"cluster": c.ID, "dimension": render.ClipRunes(dim, 32)})
	}
	topN := clampInt(in.TopN, 20, 1, 100)

	form := url.Values{}
	form.Set("limit", fmt.Sprint(topN))

	env, res, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointTSDBStatus,
		Form:      form,
	}, kindPlain)
	if terr != nil {
		return nil, tsdbUnavailable(c.ID, res, terr)
	}
	var raw upstreamTSDB
	if terr := decodeData(env, c.ID, &raw); terr != nil {
		return nil, terr
	}

	var list []tsdbPair
	switch dim {
	case DimensionMetric:
		list = raw.SeriesCountByMetricName
	case DimensionLabelName:
		list = raw.LabelValueCountByLabelName
	case DimensionLabelValuePairs:
		list = raw.SeriesCountByLabelValuePair
	default:
		list = raw.MemoryInBytesByLabelName
	}
	total := raw.HeadStats.NumSeries

	entries := make([]TSDBEntry, 0, len(list))
	for _, e := range list {
		entry := TSDBEntry{Name: render.ClipRunes(e.Name, 256), Value: e.Value}
		if total > 0 && (dim == DimensionMetric || dim == DimensionLabelValuePairs) {
			entry.PercentOfTotal = round2(float64(e.Value) * 100 / float64(total))
		}
		entries = append(entries, entry)
	}
	slices.SortStableFunc(entries, func(a, b TSDBEntry) int {
		if a.Value != b.Value {
			return int(min(max(b.Value-a.Value, -1), 1))
		}
		return strings.Compare(a.Name, b.Name)
	})
	kept, trunc := render.TruncateItems(entries, topN,
		"Raise topN (max 100), or switch dimension to see the hotspot from another angle.")
	if trunc != nil {
		trunc.Selection = render.SelectionTopNByMax(len(kept))
	}

	return &TSDBStatsOut{
		Envelope:  untrusted(),
		Dimension: dim,
		Top:       kept,
		Truncated: trunc,
		Head: TSDBHead{
			Series:        raw.HeadStats.NumSeries,
			Chunks:        raw.HeadStats.ChunkCount,
			LabelPairs:    raw.HeadStats.NumLabelPairs,
			MinTimeMillis: raw.HeadStats.MinTime,
			MaxTimeMillis: raw.HeadStats.MaxTime,
		},
	}, nil
}

// tsdbUnavailable converts a 404 or an unreadable body into the specific code
// and the specific workaround, rather than a generic upstream failure.
//
// Not every Prometheus-compatible server implements the head-statistics
// endpoint. Thanos and Mimir in particular do not, and "UPSTREAM_ERROR, retry"
// would send an agent round a loop that can never succeed. The hint names the
// PromQL that answers the same question the slow way.
func tsdbUnavailable(cluster string, res *promproxy.Result, terr *ToolError) *ToolError {
	unavailable := terr.Code == CodeMalformedUpstream
	if res != nil && (res.Status == 404 || res.Status == 501) {
		unavailable = true
	}
	if !unavailable {
		return terr
	}
	e := newError(CodeTSDBStatsUnavailable,
		fmt.Sprintf("cluster %q does not serve head-block statistics", cluster), false).
		WithInput(map[string]any{"cluster": cluster})
	e.Hint = "Thanos, Mimir and Cortex do not implement this endpoint. Get the same ranking " +
		"with query: topk(20, count by(__name__)({__name__=~\".+\"})) — it is far more " +
		"expensive, so keep topk small."
	return e
}

// runtime_info include sections. Closed set.
const (
	// SectionBuild is version, revision and Go version.
	SectionBuild = "build"
	// SectionRuntime is uptime, goroutines, retention and reload state.
	SectionRuntime = "runtime"
	// SectionFlags is the server's command-line flags.
	SectionFlags = "flags"
)

// allSections is the closed set the schema advertises.
var allSections = []string{SectionBuild, SectionRuntime, SectionFlags}

// defaultSections is what runtime_info returns when the caller says nothing.
var defaultSections = []string{SectionBuild, SectionRuntime}

// RuntimeInfoIn is the argument object of runtime_info.
type RuntimeInfoIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Include selects sections. Each costs one upstream call.
	Include []string `json:"include,omitempty" jsonschema:"Sections to include; each costs one upstream call. Defaults to build and runtime."`
}

// BuildInfo is the monitored server's build.
type BuildInfo struct {
	Version   string `json:"version,omitempty"`
	Revision  string `json:"revision,omitempty"`
	Branch    string `json:"branch,omitempty"`
	GoVersion string `json:"goVersion,omitempty"`
}

// RuntimeState is the monitored server's process state.
type RuntimeState struct {
	// StartTime is when the process started, RFC 3339.
	StartTime string `json:"startTime,omitempty"`
	// ReloadSuccess reports whether the last configuration reload worked. A
	// false here explains a great many "my rule is not firing" questions.
	ReloadSuccess bool `json:"reloadSuccess,omitempty"`
	// LastConfigTime is when the configuration was last loaded.
	LastConfigTime string `json:"lastConfigTime,omitempty"`
	// StorageRetention is the configured retention.
	StorageRetention string `json:"storageRetention,omitempty"`
	// Goroutines and GOMAXPROCS describe the process' concurrency.
	Goroutines int   `json:"goroutines,omitempty"`
	GOMAXPROCS int   `json:"gomaxprocs,omitempty"`
	GOMEMLIMIT int64 `json:"gomemlimit,omitempty"`
	// CorruptionCount is how many WAL corruptions have been recovered from.
	CorruptionCount int64 `json:"corruptionCount,omitempty"`
}

// RuntimeInfoOut is the result of runtime_info.
type RuntimeInfoOut struct {
	Envelope
	// Build is the server's build, when requested.
	Build *BuildInfo `json:"build,omitempty"`
	// Runtime is the server's process state, when requested.
	Runtime *RuntimeState `json:"runtime,omitempty"`
	// Flags are the command-line flags, when requested. Values are sanitised;
	// a flag value can be a file path an operator chose.
	Flags map[string]string `json:"flags,omitempty"`
	// Partial names the sections that could not be collected, so a missing
	// section is never mistaken for an absent feature.
	Partial []string `json:"partial,omitempty"`
}

// runtimeInfo reports the monitored server's build, runtime and flags.
func (t *Tools) runtimeInfo(
	ctx context.Context, p *fleet.Principal, in RuntimeInfoIn,
) (*RuntimeInfoOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	include := dedupe(in.Include)
	if len(include) == 0 {
		include = defaultSections
	}
	for _, s := range include {
		if !includes(allSections, s) {
			return nil, newError(CodeInvalidArgument,
				fmt.Sprintf("include value %q is not one of %s",
					render.ClipRunes(s, 32), strings.Join(allSections, ", ")), false).
				WithInput(map[string]any{"cluster": c.ID, "include": in.Include})
		}
	}

	out := &RuntimeInfoOut{Envelope: untrusted()}
	var first *ToolError

	if includes(include, SectionBuild) {
		var b struct {
			Version   string `json:"version"`
			Revision  string `json:"revision"`
			Branch    string `json:"branch"`
			GoVersion string `json:"goVersion"`
		}
		if terr := t.status(ctx, p, c.ID, promapi.EndpointBuildInfo, &b); terr != nil {
			out.Partial = append(out.Partial, SectionBuild)
			first = firstErr(first, terr)
		} else {
			out.Build = &BuildInfo{
				Version:   render.ClipRunes(b.Version, 64),
				Revision:  render.ClipRunes(b.Revision, 64),
				Branch:    render.ClipRunes(b.Branch, 64),
				GoVersion: render.ClipRunes(b.GoVersion, 32),
			}
		}
	}
	if includes(include, SectionRuntime) {
		var r struct {
			StartTime           string `json:"startTime"`
			ReloadConfigSuccess bool   `json:"reloadConfigSuccess"`
			LastConfigTime      string `json:"lastConfigTime"`
			CorruptionCount     int64  `json:"corruptionCount"`
			GoroutineCount      int    `json:"goroutineCount"`
			GOMAXPROCS          int    `json:"GOMAXPROCS"`
			GOMEMLIMIT          int64  `json:"GOMEMLIMIT"`
			StorageRetention    string `json:"storageRetention"`
		}
		if terr := t.status(ctx, p, c.ID, promapi.EndpointRuntimeInfo, &r); terr != nil {
			out.Partial = append(out.Partial, SectionRuntime)
			first = firstErr(first, terr)
		} else {
			out.Runtime = &RuntimeState{
				StartTime:        render.ClipRunes(r.StartTime, 40),
				ReloadSuccess:    r.ReloadConfigSuccess,
				LastConfigTime:   render.ClipRunes(r.LastConfigTime, 40),
				StorageRetention: render.ClipRunes(r.StorageRetention, 32),
				Goroutines:       r.GoroutineCount,
				GOMAXPROCS:       r.GOMAXPROCS,
				GOMEMLIMIT:       r.GOMEMLIMIT,
				CorruptionCount:  r.CorruptionCount,
			}
		}
	}
	if includes(include, SectionFlags) {
		var f map[string]string
		if terr := t.status(ctx, p, c.ID, promapi.EndpointFlags, &f); terr != nil {
			out.Partial = append(out.Partial, SectionFlags)
			first = firstErr(first, terr)
		} else {
			clean := make(map[string]string, len(f))
			for k, v := range f {
				clean[render.ClipRunes(k, 128)] = render.ClipRunes(v, 256)
			}
			if len(clean) > 0 {
				out.Flags = clean
			}
		}
	}
	// Every requested section failed: there is nothing to report but the
	// failure, so report it rather than an empty success.
	if len(out.Partial) == len(include) && first != nil {
		return nil, first
	}
	return out, nil
}

// status fetches one status endpoint and decodes its data member.
func (t *Tools) status(
	ctx context.Context, p *fleet.Principal, cluster string, e promapi.Endpoint, v any,
) *ToolError {
	env, _, terr := t.fetch(ctx, p, promproxy.Call{ClusterID: cluster, Endpoint: e}, kindPlain)
	if terr != nil {
		return terr
	}
	return decodeData(env, cluster, v)
}

// firstErr keeps the first failure of a multi-section call.
func firstErr(first, next *ToolError) *ToolError {
	if first != nil {
		return first
	}
	return next
}
