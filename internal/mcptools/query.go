// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// MaxPromQLBytes bounds a PromQL expression this hub will forward. It mirrors
// internal/promapi's own limit so a caller learns the expression is too long
// before a round trip rather than after one.
const MaxPromQLBytes = promapi.MaxPromQLBytes

// QueryIn is the argument object of query.
type QueryIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Query is the PromQL expression.
	Query string `json:"query" jsonschema:"PromQL expression to evaluate at a single instant, e.g. sum by(job) (up == 0)."`
	// Time is the evaluation instant.
	Time string `json:"time,omitempty" jsonschema:"Evaluation instant. Relative (\"now\", \"now-15m\", \"-1h\") or RFC 3339 (\"2026-08-29T12:00:00Z\") or a Unix timestamp. Defaults to now."`
	// Timeout bounds the evaluation.
	Timeout string `json:"timeout,omitempty" jsonschema:"Upstream evaluation timeout, e.g. \"30s\". Maximum 120s."`
	// Limit caps the returned rows.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum rows to return. Rows are ranked by descending value, so a truncated result keeps the largest."`
	// Format selects the encoding.
	Format string `json:"format,omitempty" jsonschema:"Output encoding. compact is columnar and is what you want; json is the raw Prometheus shape and costs ten to fifty times more tokens; table is fixed-width text."`
}

// QueryOut is the result of query.
type QueryOut struct {
	Envelope
	// ResultType is Prometheus' own result type: vector, scalar or string.
	ResultType string `json:"resultType,omitempty"`
	// Time is the evaluation instant in Unix seconds.
	Time int64 `json:"time,omitempty"`
	// Columns names the members of each row: __name__, labels, value.
	Columns []string `json:"columns,omitempty"`
	// Rows are the samples, ranked by descending value.
	Rows []render.Row `json:"rows,omitempty"`
	// SharedLabels are the labels every row has in common, factored out so
	// they are paid for once.
	SharedLabels map[string]string `json:"sharedLabels,omitempty"`
	// Total is how many samples matched before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when rows were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
	// Warnings are the query engine's own non-fatal notes.
	Warnings []string `json:"warnings,omitempty"`
	// ExecMillis is the round-trip time, hub to cluster and back.
	ExecMillis float64 `json:"execMillis,omitempty"`
	// Raw is the unmodified Prometheus payload, set only for format "json".
	Raw any `json:"raw,omitempty"`
	// Table is the fixed-width rendering, set only for format "table".
	Table string `json:"table,omitempty"`
}

// query evaluates PromQL at one instant.
func (t *Tools) query(
	ctx context.Context, p *fleet.Principal, in QueryIn,
) (*QueryOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	format, terr := parseFormat(in.Format, true)
	if terr != nil {
		return nil, terr
	}
	if terr := validateExpr(in.Query, in.Cluster); terr != nil {
		return nil, terr
	}
	now := t.now()
	at, err := ParseTime(in.Time, now)
	if err != nil {
		return nil, invalidTime("time", in.Time, in.Cluster, err)
	}
	if at.IsZero() {
		at = now
	}
	if terr := t.checkLookback(p, at, in.Cluster, map[string]any{
		"cluster": in.Cluster, "query": render.ClipRunes(in.Query, 512), "time": in.Time,
	}); terr != nil {
		return nil, terr
	}
	timeout, err := ParseDuration(in.Timeout)
	if err != nil {
		return nil, invalidTime("timeout", in.Timeout, in.Cluster, err)
	}
	timeout = effectiveTimeout(timeout, DefaultQueryTimeout)

	form := url.Values{}
	form.Set("query", in.Query)
	form.Set("time", formatUpstreamTime(at))
	form.Set("timeout", render.FormatDuration(timeout))

	env, res, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointQuery,
		Form:      form,
		Timeout:   timeout,
	}, kindQuery)
	if terr != nil {
		return nil, terr
	}

	out := &QueryOut{Envelope: untrusted(), Time: at.Unix()}
	if res != nil {
		out.ExecMillis = round2(float64(res.Latency.Microseconds()) / 1000)
	}
	if format == render.FormatJSON {
		return t.passthroughInstant(out, env)
	}

	data, derr := render.DecodeQueryData(env.Data)
	if derr != nil {
		return nil, malformed(c.ID, derr)
	}
	input := render.InstantInput{
		ResultType: data.ResultType,
		At:         at,
		Warnings:   append(env.Warnings, env.Infos...),
	}
	switch data.ResultType {
	case "matrix":
		return nil, newError(CodeInvalidArgument,
			"that expression returns a range vector; use query_range instead", false).
			WithInput(map[string]any{
				"cluster": c.ID, "query": render.ClipRunes(in.Query, 512)}).
			WithHint("Call query_range with the same expression, or wrap it in a function " +
				"such as rate(...) to get an instant vector.")
	case "scalar":
		pt, err := render.DecodeScalar(data.Result)
		if err != nil {
			return nil, malformed(c.ID, err)
		}
		input.Scalar = &pt
	case "string":
		var pair []any
		if err := json.Unmarshal(data.Result, &pair); err == nil && len(pair) == 2 {
			s, _ := pair[1].(string)
			input.StringValue = s
		}
	default:
		vec, err := render.DecodeVector(data.Result)
		if err != nil {
			return nil, malformed(c.ID, err)
		}
		input.Vector = vec
	}

	limit := clampInt(in.Limit, 100, 1, 1000)
	if l := p.Scope.Limits; l.MaxSeries > 0 {
		limit = min(limit, l.MaxSeries)
	}
	enc := render.EncodeInstant(input, render.Options{
		MaxItems:     limit,
		TokenCeiling: t.tokenCeiling,
	})
	out.ResultType = enc.ResultType
	out.Columns = enc.Columns
	out.Rows = enc.Rows
	out.SharedLabels = enc.SharedLabels
	out.Total = enc.Total
	out.Truncated = enc.Truncated
	out.Warnings = enc.Warnings
	if format == render.FormatTable {
		out.Table = instantTable(enc)
		out.Rows = nil
		out.Columns = nil
	}
	return out, nil
}

// passthroughInstant fills the raw payload for format "json", enforcing the
// token ceiling on bytes because the columnar encoder is bypassed.
func (t *Tools) passthroughInstant(
	out *QueryOut, env *render.APIResponse,
) (*QueryOut, *ToolError) {
	est := render.EstimateTokensOfBytes(len(env.Data))
	if t.tokenCeiling > 0 && est > t.tokenCeiling {
		out.Truncated = tokenCeilingTruncation(est, t.tokenCeiling)
		return out, nil
	}
	out.Raw = env.Data
	out.Warnings = slices.Concat(env.Warnings, env.Infos)
	return out, nil
}

// instantTable renders an instant result as fixed-width text.
//
// Every row of enc.Rows is a 3-tuple: render.EncodeInstant's three branches
// (scalar, string, vector) each build rows of exactly {name, labels, value},
// so there is deliberately no defensive short-row skip here — it could never
// fire and would be an untested branch.
func instantTable(enc *render.InstantResult) string {
	rows := make([][]string, 0, len(enc.Rows))
	for _, r := range enc.Rows {
		name, _ := r[0].(string)
		labels, _ := r[1].(map[string]string)
		rows = append(rows, []string{name, labelsText(labels), valueText(r[2])})
	}
	return render.Table([]string{"METRIC", "LABELS", "VALUE"}, rows)
}

// QueryRangeIn is the argument object of query_range.
type QueryRangeIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// Query is the PromQL expression.
	Query string `json:"query" jsonschema:"PromQL expression to evaluate over the range, e.g. rate(http_requests_total[5m])."`
	// Start bounds the range.
	Start string `json:"start,omitempty" jsonschema:"Range start. Relative (\"now-6h\", \"-15m\") or RFC 3339 or a Unix timestamp. Defaults to now-1h."`
	// End bounds the range.
	End string `json:"end,omitempty" jsonschema:"Range end, same forms as start. Defaults to now."`
	// Step is the resolution.
	Step string `json:"step,omitempty" jsonschema:"Resolution, e.g. \"1m\". Omit to let the hub choose: it snaps to {15s,30s,1m,5m,15m,1h,6h,1d}, never goes below the cluster's scrape interval, and always reports what it applied in downsampled."`
	// MaxPoints is the point budget that drives step selection.
	MaxPoints int `json:"maxPoints,omitempty" jsonschema:"Maximum samples per series. Drives automatic step selection."`
	// MaxSeries caps how many series survive truncation.
	MaxSeries int `json:"maxSeries,omitempty" jsonschema:"Maximum series to return. Series are ranked by their maximum value; the selection strategy is named in truncated.selection."`
	// Timeout bounds the evaluation.
	Timeout string `json:"timeout,omitempty" jsonschema:"Upstream evaluation timeout, e.g. \"60s\". Maximum 120s."`
	// Format selects the encoding.
	Format string `json:"format,omitempty" jsonschema:"Output encoding. compact is columnar and is what you want; json is the raw Prometheus shape and costs ten to fifty times more tokens."`
}

// QueryRangeOut is the result of query_range. It is columnar: timestamps
// appear once as start and stepSeconds rather than once per sample per series.
type QueryRangeOut struct {
	Envelope
	// Start is the timestamp of index 0 in every values array, Unix seconds.
	Start int64 `json:"start,omitempty"`
	// StepSeconds is the spacing between adjacent indices.
	StepSeconds float64 `json:"stepSeconds,omitempty"`
	// Points is the length of every values array.
	Points int `json:"points,omitempty"`
	// SharedLabels are the labels every series has in common.
	SharedLabels map[string]string `json:"sharedLabels,omitempty"`
	// Series are the returned series, ranked by descending maximum.
	Series []render.RangeSeries `json:"series,omitempty"`
	// SeriesTotal is how many series matched before truncation.
	SeriesTotal int `json:"seriesTotal,omitempty"`
	// Truncated is set when series were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
	// Downsampled always reports the step that was applied and why.
	Downsampled *render.Downsampled `json:"downsampled,omitempty"`
	// Warnings are the query engine's own non-fatal notes.
	Warnings []string `json:"warnings,omitempty"`
	// ExecMillis is the round-trip time, hub to cluster and back.
	ExecMillis float64 `json:"execMillis,omitempty"`
	// Raw is the unmodified Prometheus payload, set only for format "json".
	Raw any `json:"raw,omitempty"`
}

// queryRange evaluates PromQL over a range, choosing the step itself unless
// told otherwise and reporting what it chose.
func (t *Tools) queryRange(
	ctx context.Context, p *fleet.Principal, in QueryRangeIn,
) (*QueryRangeOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	format, terr := parseFormat(in.Format, true)
	if terr != nil {
		return nil, terr
	}
	if terr := validateExpr(in.Query, in.Cluster); terr != nil {
		return nil, terr
	}

	now := t.now()
	start, end, terr := t.resolveRange(p, in.Start, in.End, now, map[string]any{
		"cluster": in.Cluster,
		"query":   render.ClipRunes(in.Query, 512),
		"start":   in.Start,
		"end":     in.End,
		"step":    in.Step,
	})
	if terr != nil {
		return nil, terr
	}
	userStep, err := ParseDuration(in.Step)
	if err != nil {
		return nil, invalidTime("step", in.Step, in.Cluster, err)
	}
	timeout, err := ParseDuration(in.Timeout)
	if err != nil {
		return nil, invalidTime("timeout", in.Timeout, in.Cluster, err)
	}
	timeout = effectiveTimeout(timeout, DefaultRangeTimeout)

	maxPoints := clampInt(in.MaxPoints, render.DefaultMaxPoints, 10, 500)
	maxSeries := clampInt(in.MaxSeries, render.DefaultMaxSeries, 1, 200)
	if l := p.Scope.Limits; l.MaxPoints > 0 {
		maxPoints = min(maxPoints, l.MaxPoints)
	}
	if l := p.Scope.Limits; l.MaxSeries > 0 {
		maxSeries = min(maxSeries, l.MaxSeries)
	}

	scrape, _ := render.ParsePromDuration(c.Prometheus.ScrapeInterval)
	step, down := render.SelectStep(render.StepRequest{
		Start:          start,
		End:            end,
		UserStep:       userStep,
		ScrapeInterval: scrape,
		MaxPoints:      maxPoints,
	})

	form := url.Values{}
	form.Set("query", in.Query)
	form.Set("start", formatUpstreamTime(start))
	form.Set("end", formatUpstreamTime(end))
	form.Set("step", render.FormatDuration(step))
	form.Set("timeout", render.FormatDuration(timeout))

	env, res, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointQueryRange,
		Form:      form,
		Timeout:   timeout,
	}, kindQuery)
	if terr != nil {
		return nil, terr
	}

	out := &QueryRangeOut{Envelope: untrusted(), Downsampled: &down}
	if res != nil {
		out.ExecMillis = round2(float64(res.Latency.Microseconds()) / 1000)
	}
	if format == render.FormatJSON {
		est := render.EstimateTokensOfBytes(len(env.Data))
		if t.tokenCeiling > 0 && est > t.tokenCeiling {
			out.Truncated = tokenCeilingTruncation(est, t.tokenCeiling)
			return out, nil
		}
		out.Raw = env.Data
		out.Warnings = slices.Concat(env.Warnings, env.Infos)
		return out, nil
	}

	data, derr := render.DecodeQueryData(env.Data)
	if derr != nil {
		return nil, malformed(c.ID, derr)
	}
	if data.ResultType != "matrix" {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("that expression returns a %s, not a range; use query instead",
				render.ClipRunes(data.ResultType, 32)), false).
			WithInput(map[string]any{
				"cluster": c.ID, "query": render.ClipRunes(in.Query, 512)}).
			WithHint("Call query with the same expression.")
	}
	matrix, err := render.DecodeMatrix(data.Result)
	if err != nil {
		return nil, malformed(c.ID, err)
	}

	enc := render.EncodeRange(render.RangeInput{
		Matrix:      matrix,
		Start:       start,
		End:         end,
		Step:        step,
		Downsampled: down,
		Warnings:    append(env.Warnings, env.Infos...),
	}, render.Options{
		MaxSeries:    maxSeries,
		MaxPoints:    maxPoints,
		TokenCeiling: t.tokenCeiling,
	})
	out.Start = enc.Start
	out.StepSeconds = enc.StepSeconds
	out.Points = enc.Points
	out.SharedLabels = enc.SharedLabels
	out.Series = enc.Series
	out.SeriesTotal = enc.SeriesTotal
	out.Truncated = enc.Truncated
	out.Downsampled = &enc.Downsampled
	out.Warnings = enc.Warnings
	return out, nil
}

// resolveRange parses and bounds a start/end pair.
//
// The lookback ceiling is enforced here rather than upstream because a
// too-large range is exactly the case where the agent needs a corrected
// argument object it can copy, and Prometheus would simply answer with far too
// much data instead of refusing.
// defaultRangeSpan is the window a range query covers when the caller gives
// neither a start nor an end.
const defaultRangeSpan = time.Hour

func (t *Tools) resolveRange(
	p *fleet.Principal, startArg, endArg string, now time.Time, echo map[string]any,
) (time.Time, time.Time, *ToolError) {
	defaultSpan := defaultRangeSpan
	end, err := ParseTime(endArg, now)
	if err != nil {
		return time.Time{}, time.Time{}, invalidTime("end", endArg, str(echo["cluster"]), err)
	}
	if end.IsZero() {
		end = now
	}
	start, err := ParseTime(startArg, now)
	if err != nil {
		return time.Time{}, time.Time{}, invalidTime("start", startArg, str(echo["cluster"]), err)
	}
	if start.IsZero() {
		start = end.Add(-defaultSpan)
	}
	if !end.After(start) {
		return time.Time{}, time.Time{}, newError(CodeInvalidArgument,
			"end must be after start", false).WithInput(echo).
			WithHint("Relative times are the reliable form: start \"now-6h\", end \"now\".")
	}

	limit := t.lookbackLimit(p)
	if span := end.Sub(start); span > limit {
		corrected := maps(echo)
		corrected["start"] = "now-" + render.FormatDuration(limit)
		corrected["end"] = "now"
		e := newError(CodeRangeTooLarge,
			fmt.Sprintf("the requested range spans %s, above this hub's %s limit",
				span.Truncate(time.Minute), render.FormatDuration(limit)), false).
			WithInput(echo).
			WithHint("Use the corrected arguments, or query a narrower window and repeat.")
		e.Corrected = corrected
		return time.Time{}, time.Time{}, e
	}
	if age := now.Sub(start); age > limit {
		corrected := maps(echo)
		corrected["start"] = "now-" + render.FormatDuration(limit)
		e := newError(CodeRangeTooLarge,
			fmt.Sprintf("start is %s in the past, beyond this hub's %s lookback limit",
				age.Truncate(time.Minute), render.FormatDuration(limit)), false).
			WithInput(echo).
			WithHint("Use the corrected arguments. Data older than the cluster's retention " +
				"does not exist regardless of the limit; check retention with describe_cluster.")
		e.Corrected = corrected
		return time.Time{}, time.Time{}, e
	}
	return start, end, nil
}

// checkLookback refuses an instant query reaching further back than the hub or
// the principal permits.
func (t *Tools) checkLookback(
	p *fleet.Principal, at time.Time, cluster string, echo map[string]any,
) *ToolError {
	limit := t.lookbackLimit(p)
	age := t.now().Sub(at)
	if age <= limit {
		return nil
	}
	corrected := maps(echo)
	corrected["time"] = "now-" + render.FormatDuration(limit)
	e := newError(CodeRangeTooLarge,
		fmt.Sprintf("time is %s in the past, beyond this hub's %s lookback limit",
			age.Truncate(time.Minute), render.FormatDuration(limit)), false).
		WithInput(echo).
		WithHint("Use the corrected arguments.")
	e.Corrected = corrected
	_ = cluster
	return e
}

// lookbackLimit is the hub's ceiling, tightened by the principal's own.
func (t *Tools) lookbackLimit(p *fleet.Principal) time.Duration {
	limit := t.maxLookback
	if p != nil && p.Scope != nil {
		if l := time.Duration(p.Scope.Limits.MaxLookback); l > 0 {
			limit = min(limit, l)
		}
	}
	return limit
}

// validateExpr applies the cheap structural checks that do not need a parser.
func validateExpr(q, cluster string) *ToolError {
	if q == "" {
		return newError(CodeInvalidArgument, "query is required", false).
			WithInput(map[string]any{"cluster": cluster}).
			WithHint("Call search_metrics to find a metric name, then query it.")
	}
	if len(q) > MaxPromQLBytes {
		return newError(CodeInvalidArgument,
			fmt.Sprintf("query is %d bytes, above the %d byte limit", len(q), MaxPromQLBytes),
			false).WithInput(map[string]any{"cluster": cluster})
	}
	return nil
}

// invalidTime builds the error for an unparseable time or duration argument.
func invalidTime(field, value, cluster string, err error) *ToolError {
	return newError(CodeInvalidTime, err.Error(), false).
		WithInput(map[string]any{"cluster": cluster, field: render.ClipRunes(value, 128)}).
		WithHint("Relative times are the reliable form: \"now-6h\", \"-15m\", \"now\". " +
			"Durations use the Prometheus grammar: \"30s\", \"5m\", \"1h30m\", \"1d\".")
}

// malformed builds the error for a payload this hub could not read.
func malformed(cluster string, err error) *ToolError {
	return newError(CodeMalformedUpstream,
		fmt.Sprintf("cluster %q returned a payload this hub could not read: %v", cluster, err),
		false).WithInput(map[string]any{"cluster": cluster})
}

// maps returns a shallow copy of m.
func maps(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// str renders an echoed argument as a string.
func str(v any) string {
	s, _ := v.(string)
	return s
}

// round2 rounds to two decimal places, which is all the precision a latency in
// milliseconds carries any meaning at.
//
// strconv.ParseFloat cannot fail on strconv.FormatFloat's own output: every
// finite value, +Inf, -Inf and NaN all round-trip through the 'f' format
// without error, so there is deliberately no fallback branch for a parse
// failure here.
func round2(v float64) float64 {
	out, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	return out
}

// labelsText renders a label map compactly for a table cell.
func labelsText(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

// valueText renders a numeric cell.
func valueText(v any) string {
	switch x := v.(type) {
	case *float64:
		if x == nil {
			return ""
		}
		return strconv.FormatFloat(*x, 'g', -1, 64)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case string:
		return x
	default:
		return fmt.Sprint(v)
	}
}
