// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Fan-out modes.
const (
	// FanoutInstant evaluates the expression at one instant per cluster.
	FanoutInstant = "instant"
	// FanoutRange evaluates it over a range, on a step common to every
	// cluster so the rows are comparable.
	FanoutRange = "range"
)

// Fan-out failure policies.
const (
	// OnErrorPartial returns what completed and reports the gap. It is the
	// default because a fleet of a hundred clusters always has one that is
	// down, and failing the whole call for it is useless.
	OnErrorPartial = "partial"
	// OnErrorFail refuses to return a partial answer. It exists for
	// all-or-nothing automation.
	OnErrorFail = "fail"
)

// ClusterLabel is the label injected into every fanned-out series so an agent
// can tell the clusters apart.
const ClusterLabel = "cluster"

// ClusterOriginalLabel preserves a series' own cluster label when one already
// existed. Overwriting it would silently rewrite source data — a federated
// setup legitimately carries a cluster label of its own, and an agent
// comparing "cluster" across a fan-out would be comparing two different
// things without ever being told.
const ClusterOriginalLabel = "cluster_original"

// FanoutQueryIn is the argument object of fanout_query.
type FanoutQueryIn struct {
	// Query is the PromQL expression, validated once at the hub before
	// dispatch so a syntax error costs one round trip and not a hundred.
	Query string `json:"query" jsonschema:"PromQL expression to run on every selected cluster. It is validated once at the hub before dispatch."`
	// Clusters names the targets explicitly.
	Clusters []string `json:"clusters,omitempty" jsonschema:"Explicit cluster names. Omit to select by labelSelector."`
	// LabelSelector selects targets by label.
	LabelSelector map[string]string `json:"labelSelector,omitempty" jsonschema:"Select clusters whose labels all match, e.g. {\"env\":\"prod\"}. One of clusters or labelSelector is required unless the fleet is small."`
	// Mode selects instant or range evaluation.
	Mode string `json:"mode,omitempty" jsonschema:"Evaluation mode."`
	// Time is the instant for mode "instant".
	Time string `json:"time,omitempty" jsonschema:"Evaluation instant for mode \"instant\". Relative (\"now-15m\") or RFC 3339. Defaults to now."`
	// Start, End and Step bound mode "range".
	Start string `json:"start,omitempty" jsonschema:"Range start for mode \"range\". Relative (\"now-6h\") or RFC 3339. Defaults to now-1h."`
	End   string `json:"end,omitempty" jsonschema:"Range end for mode \"range\". Defaults to now."`
	Step  string `json:"step,omitempty" jsonschema:"Resolution for mode \"range\". Omit to let the hub choose one step common to every cluster; the applied step is reported in downsampled."`
	// MaxClusters bounds the fan-out.
	MaxClusters int `json:"maxClusters,omitempty" jsonschema:"Maximum clusters to query."`
	// MaxSeriesPerCluster bounds each cluster's contribution.
	MaxSeriesPerCluster int `json:"maxSeriesPerCluster,omitempty" jsonschema:"Maximum series to keep from each cluster. Deliberately small: 100 clusters times 20 series would defeat every other budget here. Aggregate in the expression instead."`
	// Concurrency bounds simultaneous cluster queries.
	Concurrency int `json:"concurrency,omitempty" jsonschema:"How many clusters to query at once."`
	// Deadline bounds the whole fan-out.
	Deadline string `json:"deadline,omitempty" jsonschema:"Overall budget for the whole fan-out, e.g. \"60s\". On expiry the clusters that finished are returned; the rest are reported as timed out."`
	// OnError selects the failure policy.
	OnError string `json:"onError,omitempty" jsonschema:"What to do when some clusters fail."`
}

// ClusterFailure is one cluster's failure inside a fan-out.
type ClusterFailure struct {
	// Cluster is the cluster that failed.
	Cluster string `json:"cluster,omitempty"`
	// Code is one of the Code constants in this package.
	Code string `json:"code,omitempty"`
	// Message is the clipped explanation.
	Message string `json:"message,omitempty"`
	// Retryable states whether repeating the call could succeed.
	Retryable bool `json:"retryable,omitempty"`
}

// Coverage is the accounting that stops a model reporting a partial fan-out as
// a complete one.
//
// An LLM asked for the minimum across a fleet, given 37 of 42 clusters and no
// statement that 5 are missing, will report a minimum and will be wrong. This
// object, and the preamble beside it, exist entirely to prevent that.
type Coverage struct {
	// Requested is how many clusters were selected.
	Requested int `json:"requested,omitempty"`
	// OK is how many answered.
	OK int `json:"ok,omitempty"`
	// Failed is how many returned an error.
	Failed int `json:"failed,omitempty"`
	// TimedOut is how many did not answer within the deadline.
	TimedOut int `json:"timedOut,omitempty"`
	// Complete is true only when every selected cluster answered.
	Complete bool `json:"complete"`
}

// PerCluster names which clusters landed in each bucket.
type PerCluster struct {
	// OK are the clusters that answered, sorted.
	OK []string `json:"ok,omitempty"`
	// Failed are the failures, sorted by cluster.
	Failed []ClusterFailure `json:"failed,omitempty"`
	// TimedOut are the clusters that did not answer in time, sorted.
	TimedOut []string `json:"timedOut,omitempty"`
}

// FanoutSeries is one series of a range-mode fan-out.
type FanoutSeries struct {
	// Cluster is the cluster the series came from.
	Cluster string `json:"cluster,omitempty"`
	// Labels are the series' own labels, including cluster_original when the
	// series already carried a cluster label.
	Labels map[string]string `json:"labels,omitempty"`
	// Values holds one entry per step, nil where there is no sample.
	Values []*float64 `json:"values,omitempty"`
	// Max is the largest finite value in the series.
	Max *float64 `json:"max,omitempty"`
}

// FanoutQueryOut is the result of fanout_query.
type FanoutQueryOut struct {
	Envelope
	// Mode echoes the evaluation mode.
	Mode string `json:"mode,omitempty"`
	// Preamble states the coverage in words. It is the first thing a model
	// reads and it is deliberately not a field it can skip past.
	Preamble string `json:"preamble,omitempty"`
	// Coverage is the machine-readable accounting.
	Coverage Coverage `json:"coverage,omitzero"`
	// PerCluster names the clusters in each bucket.
	PerCluster PerCluster `json:"perCluster,omitzero"`
	// Columns names the members of each instant-mode row.
	Columns []string `json:"columns,omitempty"`
	// Rows are the instant-mode samples: cluster, metric, labels, value.
	Rows []render.Row `json:"rows,omitempty"`
	// Start is the timestamp of index 0 of every range-mode values array.
	Start int64 `json:"start,omitempty"`
	// StepSeconds is the common step every cluster was queried at.
	StepSeconds float64 `json:"stepSeconds,omitempty"`
	// Points is the length of every range-mode values array.
	Points int `json:"points,omitempty"`
	// Series are the range-mode series.
	Series []FanoutSeries `json:"series,omitempty"`
	// Total is how many rows or series were produced before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when rows or series were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
	// Downsampled reports the common step and why it was chosen.
	Downsampled *render.Downsampled `json:"downsampled,omitempty"`
	// Warnings are the hub's and the query engines' non-fatal notes, including
	// every cluster-label collision.
	Warnings []string `json:"warnings,omitempty"`
}

// FanoutColumns are the fixed columns of an instant-mode fan-out.
var FanoutColumns = []string{ClusterLabel, "__name__", "labels", "value"}

// fanoutResult is one cluster's contribution.
type fanoutResult struct {
	cluster  string
	vector   render.Vector
	matrix   render.Matrix
	warnings []string
	err      *ToolError
	timedOut bool
}

// fanoutQuery runs one expression across many clusters and merges the answers.
func (t *Tools) fanoutQuery(
	ctx context.Context, p *fleet.Principal, in FanoutQueryIn,
) (*FanoutQueryOut, *ToolError) {
	mode := in.Mode
	if mode == "" {
		mode = FanoutInstant
	}
	if !includes([]string{FanoutInstant, FanoutRange}, mode) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("mode %q is not one of instant, range", render.ClipRunes(mode, 32)),
			false).WithInput(map[string]any{"mode": render.ClipRunes(mode, 32)})
	}
	onError := in.OnError
	if onError == "" {
		onError = OnErrorPartial
	}
	if !includes([]string{OnErrorPartial, OnErrorFail}, onError) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("onError %q is not one of partial, fail", render.ClipRunes(onError, 32)),
			false).WithInput(map[string]any{"onError": render.ClipRunes(onError, 32)})
	}
	if terr := validateExpr(in.Query, ""); terr != nil {
		return nil, terr
	}
	// Validate once, centrally. A syntax error across a hundred clusters costs
	// one hundred round trips and a hundred identical error messages if it is
	// left to the spokes to notice.
	if a := analyzePromQL(in.Query); !a.Valid {
		e := newError(CodePromQLParse, a.Message, false).
			WithInput(map[string]any{"query": render.ClipRunes(in.Query, 1024)}).
			WithHint("The expression was rejected at the hub before any cluster was contacted. " +
				"Call explain_promql to see the full analysis.")
		if a.Position > 0 {
			col := min(a.Position, len(in.Query)+1)
			e.Caret = strings.Repeat(" ", col-1) + "^"
		}
		return nil, e
	}

	maxClusters := clampInt(in.MaxClusters, DefaultMaxClusters, 1, MaxClustersCeiling)
	targets, failures, terr := t.selectClusters(p, in, maxClusters)
	if terr != nil {
		return nil, terr
	}

	concurrency := clampInt(in.Concurrency, t.fanoutConcurrency, 1, MaxFanoutConcurrency)
	deadline, err := ParseDuration(in.Deadline)
	if err != nil {
		return nil, invalidTime("deadline", in.Deadline, "", err)
	}
	if deadline <= 0 {
		deadline = DefaultFanoutDeadline
	}
	deadline = min(deadline, MaxFanoutDeadline)

	now := t.now()
	out := &FanoutQueryOut{Envelope: untrusted(), Mode: mode}
	var form url.Values
	var endpoint promapi.Endpoint
	var start, end time.Time
	var step time.Duration

	if mode == FanoutInstant {
		at, err := ParseTime(in.Time, now)
		if err != nil {
			return nil, invalidTime("time", in.Time, "", err)
		}
		if at.IsZero() {
			at = now
		}
		endpoint = promapi.EndpointQuery
		form = url.Values{}
		form.Set("query", in.Query)
		form.Set("time", formatUpstreamTime(at))
	} else {
		start, end, terr = t.resolveRange(in.Start, in.End, now, map[string]any{
			"query": render.ClipRunes(in.Query, 512),
			"start": in.Start, "end": in.End, "step": in.Step,
		})
		if terr != nil {
			return nil, terr
		}
		userStep, err := ParseDuration(in.Step)
		if err != nil {
			return nil, invalidTime("step", in.Step, "", err)
		}
		var down render.Downsampled
		step, down = t.commonStep(targets, start, end, userStep)
		// One aligned start for every cluster, so index i means the same
		// wall-clock instant in every series and the rows are comparable.
		start = time.Unix(start.Unix()-start.Unix()%int64(step.Seconds()), 0).UTC()
		out.Downsampled = &down
		endpoint = promapi.EndpointQueryRange
		form = url.Values{}
		form.Set("query", in.Query)
		form.Set("start", formatUpstreamTime(start))
		form.Set("end", formatUpstreamTime(end))
		form.Set("step", render.FormatDuration(step))
	}

	// One overall budget, plus a per-cluster sub-deadline of half of it: a
	// single slow cluster must not consume the whole fan-out's time.
	fctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	perCluster := max(deadline/2, time.Second)

	results := t.dispatch(fctx, p, targets, endpoint, form, concurrency, perCluster)

	maxSeries := clampInt(in.MaxSeriesPerCluster, 5, 1, 50)
	if mode == FanoutInstant {
		t.mergeInstant(out, results, maxSeries)
	} else {
		t.mergeRange(out, results, start, end, step, maxSeries)
	}

	for _, f := range failures {
		results = append(results, fanoutResult{cluster: f.Cluster, err: &ToolError{
			Code: f.Code, Message: f.Message,
		}})
	}
	t.accountCoverage(out, targets, results, failures)

	if !out.Coverage.Complete && onError == OnErrorFail {
		e := newError(CodeAllClustersFailed,
			fmt.Sprintf("onError is \"fail\" and %d of %d clusters did not answer",
				out.Coverage.Failed+out.Coverage.TimedOut, out.Coverage.Requested), true).
			WithInput(map[string]any{"query": render.ClipRunes(in.Query, 512), "onError": onError}).
			WithHint("Re-run with onError \"partial\" to get the clusters that did answer, " +
				"together with an explicit coverage report.")
		return nil, e
	}
	if out.Coverage.OK == 0 && out.Coverage.Requested > 0 {
		e := newError(CodeAllClustersFailed,
			fmt.Sprintf("all %d selected clusters failed", out.Coverage.Requested), true).
			WithInput(map[string]any{"query": render.ClipRunes(in.Query, 512)}).
			WithHint("Call list_clusters to see which clusters are connected.")
		return nil, e
	}
	return out, nil
}

// selectClusters resolves the fan-out's targets, refusing the untargeted case.
func (t *Tools) selectClusters(
	p *fleet.Principal, in FanoutQueryIn, maxClusters int,
) ([]fleet.Cluster, []ClusterFailure, *ToolError) {
	visible := t.clusters.Visible(p)
	byID := make(map[string]fleet.Cluster, len(visible))
	for _, c := range visible {
		byID[c.ID] = c
	}

	var targets []fleet.Cluster
	var failures []ClusterFailure

	switch {
	case len(in.Clusters) > 0:
		for _, name := range dedupe(in.Clusters) {
			c, ok := byID[name]
			if !ok {
				failures = append(failures, ClusterFailure{
					Cluster:   render.ClipRunes(name, 128),
					Code:      CodeUnknownCluster,
					Message:   "no such cluster is reachable by this credential",
					Retryable: false,
				})
				continue
			}
			targets = append(targets, c)
		}
	case len(in.LabelSelector) > 0:
		for _, c := range visible {
			if matchesSelector(c.Labels, in.LabelSelector) {
				targets = append(targets, c)
			}
		}
	default:
		if len(visible) > maxClusters {
			e := newError(CodeNoSelectorTooBroad,
				fmt.Sprintf("no clusters or labelSelector was given and the fleet has %d "+
					"clusters, above maxClusters %d", len(visible), maxClusters), false).
				WithInput(map[string]any{
					"query":       render.ClipRunes(in.Query, 512),
					"maxClusters": maxClusters,
				}).
				WithHint("Add labelSelector (for example {\"env\":\"prod\"}) or an explicit " +
					"clusters list. An untargeted fan-out across the whole fleet should be " +
					"deliberate, not accidental.")
			return nil, nil, e
		}
		targets = visible
	}

	if len(targets) == 0 {
		e := newError(CodeNoClustersMatched, "no cluster matched the selection", false).
			WithInput(map[string]any{
				"clusters": clipAll(in.Clusters, 128), "labelSelector": in.LabelSelector}).
			WithHint("Call list_clusters to see the clusters this credential can reach and " +
				"the labels they carry.")
		if len(in.Clusters) > 0 {
			e.DidYouMean = t.didYouMean(p, in.Clusters[0])
		}
		return nil, nil, e
	}
	// Deterministic order, so repeated calls are diffable and a truncation
	// keeps the same clusters.
	slices.SortFunc(targets, func(a, b fleet.Cluster) int { return strings.Compare(a.ID, b.ID) })
	if len(targets) > maxClusters {
		for _, c := range targets[maxClusters:] {
			failures = append(failures, ClusterFailure{
				Cluster: c.ID,
				Code:    CodeInvalidArgument,
				Message: fmt.Sprintf("not queried: maxClusters is %d", maxClusters),
			})
		}
		targets = targets[:maxClusters]
	}
	return targets, failures, nil
}

// commonStep picks one step for every cluster: the largest of the per-cluster
// automatic steps. A shared step is what makes the merged rows comparable, and
// taking the largest keeps every cluster at or above its own scrape interval.
func (t *Tools) commonStep(
	targets []fleet.Cluster, start, end time.Time, userStep time.Duration,
) (time.Duration, render.Downsampled) {
	var best time.Duration
	var chosen render.Downsampled
	for _, c := range targets {
		scrape, _ := render.ParsePromDuration(c.Prometheus.ScrapeInterval)
		step, down := render.SelectStep(render.StepRequest{
			Start:          start,
			End:            end,
			UserStep:       userStep,
			ScrapeInterval: scrape,
			MaxPoints:      render.DefaultMaxPoints,
		})
		if step > best {
			best, chosen = step, down
		}
	}
	if best <= 0 {
		best, chosen = render.SelectStep(render.StepRequest{
			Start: start, End: end, UserStep: userStep, MaxPoints: render.DefaultMaxPoints,
		})
	}
	chosen.AppliedStep = render.FormatDuration(best)
	if len(targets) > 1 {
		chosen.Reason = chosen.Reason + "; common step across " +
			fmt.Sprint(len(targets)) + " clusters"
	}
	return best, chosen
}

// dispatch queries every target under a bounded concurrency.
func (t *Tools) dispatch(
	ctx context.Context, p *fleet.Principal, targets []fleet.Cluster,
	endpoint promapi.Endpoint, form url.Values, concurrency int, perCluster time.Duration,
) []fanoutResult {
	results := make([]fanoutResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, c := range targets {
		wg.Add(1)
		go func(i int, c fleet.Cluster) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = fanoutResult{cluster: c.ID, timedOut: true}
				return
			}
			results[i] = t.queryOne(ctx, p, c, endpoint, form, perCluster)
		}(i, c)
	}
	wg.Wait()
	return results
}

// queryOne runs the fan-out's expression against one cluster.
func (t *Tools) queryOne(
	ctx context.Context, p *fleet.Principal, c fleet.Cluster,
	endpoint promapi.Endpoint, form url.Values, perCluster time.Duration,
) fanoutResult {
	cctx, cancel := context.WithTimeout(ctx, perCluster)
	defer cancel()

	env, _, terr := t.fetch(cctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  endpoint,
		Form:      form,
		Timeout:   perCluster,
	}, kindQuery)
	if terr != nil {
		return fanoutResult{
			cluster:  c.ID,
			err:      terr,
			timedOut: terr.Code == CodeQueryTimeout || terr.Code == CodeCanceled,
		}
	}
	data, derr := render.DecodeQueryData(env.Data)
	if derr != nil {
		return fanoutResult{cluster: c.ID, err: malformed(c.ID, derr)}
	}
	res := fanoutResult{cluster: c.ID, warnings: append(env.Warnings, env.Infos...)}
	if data.ResultType == "matrix" {
		m, err := render.DecodeMatrix(data.Result)
		if err != nil {
			return fanoutResult{cluster: c.ID, err: malformed(c.ID, err)}
		}
		res.matrix = m
		return res
	}
	v, err := render.DecodeVector(data.Result)
	if err != nil {
		return fanoutResult{cluster: c.ID, err: malformed(c.ID, err)}
	}
	res.vector = v
	return res
}

// mergeInstant folds every cluster's vector into one columnar table.
func (t *Tools) mergeInstant(out *FanoutQueryOut, results []fanoutResult, maxSeries int) {
	out.Columns = FanoutColumns
	rows := make([]render.Row, 0, len(results)*maxSeries)
	total := 0
	for _, r := range results {
		if r.err != nil {
			continue
		}
		enc := render.EncodeInstant(render.InstantInput{
			Vector: r.vector, ResultType: "vector", Warnings: r.warnings,
		}, render.Options{MaxItems: maxSeries, TokenCeiling: -1})
		total += enc.Total
		for _, row := range enc.Rows {
			if len(row) < 3 {
				continue
			}
			labels, _ := row[1].(map[string]string)
			labels, warn := injectCluster(labels, r.cluster, enc.SharedLabels)
			if warn != "" {
				out.Warnings = append(out.Warnings, warn)
			}
			// The cluster is already its own column; repeating it in the label
			// map would be paid for once per row.
			delete(labels, ClusterLabel)
			rows = append(rows, render.Row{r.cluster, row[0], labels, row[2]})
		}
		out.Warnings = append(out.Warnings, prefixWarnings(r.cluster, enc.Warnings)...)
	}
	out.Total = total
	fitted, hit := render.FitTokens(rows, t.tokenCeiling, func(s []render.Row) any {
		return &FanoutQueryOut{Rows: s}
	})
	if hit {
		out.Truncated = (&render.Truncation{}).Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of "+
				"limit. Aggregate the expression, or lower maxClusters.", t.tokenCeiling))
		out.Truncated.Total = len(rows)
	} else if total > len(rows) {
		out.Truncated = &render.Truncation{
			Returned:  len(rows),
			Total:     total,
			Reason:    render.ReasonMaxSeries,
			Selection: render.SelectionTopNByMax(maxSeries),
			Hint: fmt.Sprintf("Each cluster contributed at most %d series. Aggregate in the "+
				"expression, for example sum by(job) (...), rather than raising "+
				"maxSeriesPerCluster.", maxSeries),
		}
	}
	out.Rows = fitted
	out.Warnings = dedupe(out.Warnings)
}

// mergeRange folds every cluster's matrix onto the common step grid.
func (t *Tools) mergeRange(
	out *FanoutQueryOut, results []fanoutResult,
	start, end time.Time, step time.Duration, maxSeries int,
) {
	points := 0
	if span := end.Sub(start); span >= 0 && step > 0 {
		points = int(span/step) + 1
	}
	out.Start = start.Unix()
	out.StepSeconds = step.Seconds()
	out.Points = points

	series := make([]FanoutSeries, 0, len(results)*maxSeries)
	total := 0
	for _, r := range results {
		if r.err != nil {
			continue
		}
		enc := render.EncodeRange(render.RangeInput{
			Matrix: r.matrix, Start: start, End: end, Step: step, Warnings: r.warnings,
		}, render.Options{MaxSeries: maxSeries, TokenCeiling: -1})
		total += enc.SeriesTotal
		for _, s := range enc.Series {
			labels, warn := injectCluster(s.Labels, r.cluster, enc.SharedLabels)
			if warn != "" {
				out.Warnings = append(out.Warnings, warn)
			}
			delete(labels, ClusterLabel)
			series = append(series, FanoutSeries{
				Cluster: r.cluster,
				Labels:  labels,
				Values:  s.Values,
				Max:     s.Max,
			})
		}
		out.Warnings = append(out.Warnings, prefixWarnings(r.cluster, enc.Warnings)...)
	}
	out.Total = total
	fitted, hit := render.FitTokens(series, t.tokenCeiling, func(s []FanoutSeries) any {
		return &FanoutQueryOut{Series: s}
	})
	if hit {
		out.Truncated = (&render.Truncation{}).Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of "+
				"limit. Shorten the range, aggregate, or lower maxClusters.", t.tokenCeiling))
		out.Truncated.Total = len(series)
	} else if total > len(series) {
		out.Truncated = &render.Truncation{
			Returned:  len(series),
			Total:     total,
			Reason:    render.ReasonMaxSeries,
			Selection: render.SelectionTopNByMax(maxSeries),
			Hint: fmt.Sprintf("Each cluster contributed at most %d series. Aggregate in the "+
				"expression rather than raising maxSeriesPerCluster.", maxSeries),
		}
	}
	out.Series = fitted
	out.Warnings = dedupe(out.Warnings)
}

// injectCluster adds the cluster label to a series' labels, preserving any
// cluster label the series already carried.
//
// The shared labels of the per-cluster encoding are folded back in first: a
// label common to every series within one cluster is not necessarily common
// across clusters, and dropping it here would merge two different series into
// one row.
func injectCluster(
	labels map[string]string, cluster string, shared map[string]string,
) (map[string]string, string) {
	out := make(map[string]string, len(labels)+len(shared)+1)
	for k, v := range shared {
		out[k] = v
	}
	for k, v := range labels {
		out[k] = v
	}
	warn := ""
	if existing, ok := out[ClusterLabel]; ok && existing != cluster {
		out[ClusterOriginalLabel] = existing
		warn = fmt.Sprintf(
			"cluster %q returned series already carrying a %q label (%q); the original was "+
				"preserved as %q rather than overwritten",
			cluster, ClusterLabel, render.LabelValue(existing), ClusterOriginalLabel)
	}
	out[ClusterLabel] = cluster
	return out, warn
}

// prefixWarnings attributes a cluster's warnings to it.
func prefixWarnings(cluster string, in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, w := range in {
		out = append(out, cluster+": "+w)
	}
	return out
}

// accountCoverage fills the coverage report and the preamble.
func (t *Tools) accountCoverage(
	out *FanoutQueryOut, targets []fleet.Cluster, results []fanoutResult,
	preFailures []ClusterFailure,
) {
	cov := Coverage{Requested: len(targets) + len(preFailures)}
	pc := PerCluster{}
	for _, r := range results {
		switch {
		case r.timedOut:
			cov.TimedOut++
			pc.TimedOut = append(pc.TimedOut, r.cluster)
		case r.err != nil:
			cov.Failed++
			retryable := r.err.Retryable != nil && *r.err.Retryable
			pc.Failed = append(pc.Failed, ClusterFailure{
				Cluster:   r.cluster,
				Code:      r.err.Code,
				Message:   render.ClipRunes(r.err.Message, 200),
				Retryable: retryable,
			})
		default:
			cov.OK++
			pc.OK = append(pc.OK, r.cluster)
		}
	}
	slices.Sort(pc.OK)
	slices.Sort(pc.TimedOut)
	slices.SortFunc(pc.Failed, func(a, b ClusterFailure) int {
		return strings.Compare(a.Cluster, b.Cluster)
	})
	cov.Complete = cov.OK == cov.Requested && cov.Requested > 0
	out.Coverage = cov
	out.PerCluster = pc

	if cov.Complete {
		out.Preamble = fmt.Sprintf("Complete result: all %d clusters answered.", cov.OK)
		return
	}
	out.Preamble = fmt.Sprintf(
		"Partial result: %d of %d clusters. Conclusions may be incomplete; %d failed and "+
			"%d timed out. Do not report a fleet-wide minimum, maximum or ranking as "+
			"complete without saying which clusters are missing.",
		cov.OK, cov.Requested, cov.Failed, cov.TimedOut)
}
