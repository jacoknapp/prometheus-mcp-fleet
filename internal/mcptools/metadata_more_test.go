// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// TestSearchMetricsArgumentValidation covers the three ways search_metrics
// can be misused before any upstream call is made.
func TestSearchMetricsArgumentValidation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.searchMetrics(ctx(t), h.p, SearchMetricsIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("empty pattern terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: strings.Repeat("x", 201)})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("oversized pattern terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: "up", Mode: "fuzzy"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("invalid mode terr = %v, want INVALID_ARGUMENT", terr)
	}
	if len(h.prom.calls) != 0 {
		t.Error("an invalid argument still reached the upstream")
	}
}

// TestSearchMetricsPropagatesNameListFailure proves the metric-name lookup
// search_metrics depends on is not the same best-effort enrichment as
// withMetadata: if the hub cannot list names at all, the search fails rather
// than silently reporting zero matches.
func TestSearchMetricsPropagatesNameListFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointLabelValues)+"/__name__", fakeResponse{
		err: errors.New("boom"),
	})
	_, terr := h.tools.searchMetrics(ctx(t), h.p, SearchMetricsIn{Cluster: okCluster, Pattern: "up"})
	if terr == nil || terr.Code != CodeUpstreamError {
		t.Fatalf("terr = %v, want UPSTREAM_ERROR", terr)
	}
}

// syntheticNameList builds an /api/v1/label/__name__/values payload with n
// long metric names, all matching a shared prefix, so a search against them
// can be pushed past a small token ceiling.
func syntheticNameList(t *testing.T, n int) []byte {
	t.Helper()
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, fmt.Sprintf(
			"synthetic_metric_with_a_long_name_to_inflate_tokens_%04d_total", i))
	}
	body, err := json.Marshal(map[string]any{"status": "success", "data": names})
	if err != nil {
		t.Fatalf("marshal synthetic name list: %v", err)
	}
	return body
}

// TestSearchMetricsTokenCeiling proves the hub's token budget beats a match
// count that already fits under limit.
func TestSearchMetricsTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointLabelValues)+"/__name__", fakeResponse{
		body: syntheticNameList(t, 200),
	})
	out, terr := h.tools.searchMetrics(ctx(t), h.p,
		SearchMetricsIn{Cluster: okCluster, Pattern: "synthetic", Limit: 500})
	if terr != nil {
		t.Fatalf("searchMetrics: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}

// TestMetricMetadataInvalidName covers the metric-name grammar check.
func TestMetricMetadataInvalidName(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.metricMetadata(ctx(t), h.p,
		MetricMetadataIn{Cluster: okCluster, Metric: "1_leading_digit"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
	if !strings.Contains(terr.Hint, "search_metrics") {
		t.Errorf("hint does not name a discovery call: %q", terr.Hint)
	}
}

// TestMetricMetadataFiltersByName proves a single metric name is sent
// upstream as the filter Prometheus itself applies; this hub does not
// second-guess the upstream by re-filtering the response.
func TestMetricMetadataFiltersByName(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.metricMetadata(ctx(t), h.p,
		MetricMetadataIn{Cluster: okCluster, Metric: "up"})
	if terr != nil {
		t.Fatalf("metricMetadata: %v", terr)
	}
	if form := h.prom.lastForm(promapi.EndpointMetadata); form["metric"] == nil ||
		form["metric"][0] != "up" {
		t.Errorf("form = %v, want metric=up sent upstream", form)
	}
}

// TestMetricMetadataUpstreamFailure proves a failure inside the shared
// metadataOf helper (here, a body that is not the metadata shape) propagates
// out of metricMetadata rather than being swallowed the way search_metrics'
// best-effort enrichment swallows it.
func TestMetricMetadataUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointMetadata), fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-object"}`),
	})
	_, terr := h.tools.metricMetadata(ctx(t), h.p, MetricMetadataIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestMetricMetadataSkipsMalformedUpstreamNames proves a metric name outside
// the Prometheus grammar is dropped rather than surfaced, because it cannot
// have come from a well-formed exposition and would become an attacker
// controlled map key otherwise.
func TestMetricMetadataSkipsMalformedUpstreamNames(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointMetadata), fakeResponse{
		body: []byte(`{"status":"success","data":{
			"up": [{"type":"gauge","help":"ok","unit":""}],
			"not a valid name!": [{"type":"gauge","help":"bad","unit":""}]
		}}`),
	})
	out, terr := h.tools.metricMetadata(ctx(t), h.p, MetricMetadataIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("metricMetadata: %v", terr)
	}
	if len(out.Metadata) != 1 || out.Metadata[0].Name != "up" {
		t.Fatalf("metadata = %+v, want the malformed name dropped", out.Metadata)
	}
}

// syntheticMetadata builds an /api/v1/metadata payload with n long entries.
func syntheticMetadata(t *testing.T, n int) []byte {
	t.Helper()
	data := make(map[string]any, n)
	for i := range n {
		data[fmt.Sprintf("synthetic_metric_%04d_total", i)] = []any{
			map[string]any{
				"type": "counter", "unit": "seconds",
				"help": "padding help text so the payload is large enough to exceed a small ceiling",
			},
		}
	}
	body, err := json.Marshal(map[string]any{"status": "success", "data": data})
	if err != nil {
		t.Fatalf("marshal synthetic metadata: %v", err)
	}
	return body
}

// TestMetricMetadataTokenCeiling mirrors the search_metrics equivalent.
func TestMetricMetadataTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointMetadata), fakeResponse{body: syntheticMetadata(t, 200)})
	out, terr := h.tools.metricMetadata(ctx(t), h.p, MetricMetadataIn{Cluster: okCluster, Limit: 1000})
	if terr != nil {
		t.Fatalf("metricMetadata: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}

// TestSeriesInvalidFormatAndRange covers series' own argument-validation
// errors: an unsupported format, and a range the time parser rejects.
func TestSeriesInvalidFormatAndRange(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}, Format: "yaml"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("format terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}, Start: "not-a-time"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("range terr = %v, want INVALID_TIME", terr)
	}
}

// TestSeriesMalformedUpstream covers the decode-data failure path.
func TestSeriesMalformedUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointSeries), fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-array"}`),
	})
	_, terr := h.tools.series(ctx(t), h.p, SeriesIn{Cluster: okCluster, Matchers: []string{"up"}})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// syntheticSeries builds an /api/v1/series payload with n distinct label sets.
func syntheticSeries(t *testing.T, n int) []byte {
	t.Helper()
	result := make([]any, 0, n)
	for i := range n {
		result = append(result, map[string]string{
			"__name__": "synthetic_series_metric_with_a_long_name",
			"job":      "synthetic",
			"pod":      fmt.Sprintf("workload-with-a-long-pod-name-%04d", i),
		})
	}
	body, err := json.Marshal(map[string]any{"status": "success", "data": result})
	if err != nil {
		t.Fatalf("marshal synthetic series: %v", err)
	}
	return body
}

// TestSeriesJSONFormatTokenCeiling proves format "json" is not a way around
// the token ceiling: an oversized raw payload is dropped and the truncation
// names the reason, rather than being passed through.
func TestSeriesJSONFormatTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 100
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointSeries), fakeResponse{body: syntheticSeries(t, 200)})
	out, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}, Format: "json"})
	if terr != nil {
		t.Fatalf("series: %v", terr)
	}
	if out.Raw != nil {
		t.Error("an oversized json payload was returned anyway")
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
}

// TestSeriesTokenCeiling covers the columnar (non-json) truncation escalation.
func TestSeriesTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointSeries), fakeResponse{body: syntheticSeries(t, 200)})
	out, terr := h.tools.series(ctx(t), h.p,
		SeriesIn{Cluster: okCluster, Matchers: []string{"up"}, Limit: 1000})
	if terr != nil {
		t.Fatalf("series: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}

// TestLabelNamesArgumentValidationAndFailures covers label_names' own matcher
// and range validation plus the upstream failure and decode paths.
func TestLabelNamesArgumentValidationAndFailures(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.labelNames(ctx(t), h.p,
		LabelNamesIn{Cluster: okCluster, Matchers: []string{`job="api"`}})
	if terr == nil || terr.Code != CodeBadMatcher {
		t.Fatalf("matcher terr = %v, want BAD_MATCHER", terr)
	}

	_, terr = h.tools.labelNames(ctx(t), h.p, LabelNamesIn{Cluster: okCluster, Start: "not-a-time"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("range terr = %v, want INVALID_TIME", terr)
	}

	if _, terr := h.tools.labelNames(ctx(t), h.p,
		LabelNamesIn{Cluster: okCluster, Matchers: []string{"up"}}); terr != nil {
		t.Fatalf("labelNames with a matcher: %v", terr)
	}
	if form := h.prom.lastForm(promapi.EndpointLabels); len(form["match[]"]) != 1 ||
		form["match[]"][0] != "up" {
		t.Errorf("form = %v, want the matcher sent upstream", form)
	}

	h.prom.set(string(promapi.EndpointLabels), fakeResponse{err: errors.New("boom")})
	_, terr = h.tools.labelNames(ctx(t), h.p, LabelNamesIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeUpstreamError {
		t.Fatalf("upstream terr = %v, want UPSTREAM_ERROR", terr)
	}

	h.prom.set(string(promapi.EndpointLabels), fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-array"}`),
	})
	_, terr = h.tools.labelNames(ctx(t), h.p, LabelNamesIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("decode terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestLabelValuesArgumentValidationAndFailures covers label_values' own
// matcher and range validation, and proves matchers actually reach the
// upstream form.
func TestLabelValuesArgumentValidationAndFailures(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "job", Matchers: []string{`job="api"`}})
	if terr == nil || terr.Code != CodeBadMatcher {
		t.Fatalf("matcher terr = %v, want BAD_MATCHER", terr)
	}

	_, terr = h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "job", Start: "not-a-time"})
	if terr == nil || terr.Code != CodeInvalidTime {
		t.Fatalf("range terr = %v, want INVALID_TIME", terr)
	}

	out, terr := h.tools.labelValues(ctx(t), h.p,
		LabelValuesIn{Cluster: okCluster, Label: "job", Matchers: []string{"up"}})
	if terr != nil {
		t.Fatalf("labelValues: %v", terr)
	}
	if len(out.Values) == 0 {
		t.Fatal("no values returned")
	}
	if form := h.prom.lastForm(promapi.EndpointLabelValues); len(form["match[]"]) != 1 ||
		form["match[]"][0] != "up" {
		t.Errorf("form = %v, want the matcher sent upstream", form)
	}

	h.prom.set(string(promapi.EndpointLabelValues)+"/job", fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-array"}`),
	})
	_, terr = h.tools.labelValues(ctx(t), h.p, LabelValuesIn{Cluster: okCluster, Label: "job"})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("decode terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestLabelValuesTokenCeiling covers the label_values truncation escalation.
func TestLabelValuesTokenCeiling(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	values := make([]string, 0, 200)
	for i := range 200 {
		values = append(values, fmt.Sprintf("value-with-a-long-name-to-inflate-tokens-%04d", i))
	}
	body, err := json.Marshal(map[string]any{"status": "success", "data": values})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	h.prom.set(string(promapi.EndpointLabelValues)+"/job", fakeResponse{body: body})

	out, terr := h.tools.labelValues(ctx(t), h.p, LabelValuesIn{Cluster: okCluster, Label: "job", Limit: 1000})
	if terr != nil {
		t.Fatalf("labelValues: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Total != 200 {
		t.Errorf("total = %d, want the honest 200", out.Truncated.Total)
	}
}

// TestValidateMatchersSkipsBlankAndRejectsOversized covers the two matcher
// edges TestValidateMatchersRejectsBareLabel does not: a blank entry (after
// trimming) is silently dropped rather than rejected, and a matcher above the
// upstream parameter size limit is refused before it ever reaches Do.
func TestValidateMatchersSkipsBlankAndRejectsOversized(t *testing.T) {
	t.Parallel()

	out, terr := validateMatchers([]string{"  ", "up"}, "c", false)
	if terr != nil {
		t.Fatalf("validateMatchers: %v", terr)
	}
	if len(out) != 1 || out[0] != "up" {
		t.Errorf("out = %v, want the blank entry dropped and \"up\" kept", out)
	}

	huge := `up{job="` + strings.Repeat("x", promapi.MaxParamBytes) + `"}`
	_, terr = validateMatchers([]string{huge}, "c", false)
	if terr == nil || terr.Code != CodeBadMatcher {
		t.Fatalf("terr = %v, want BAD_MATCHER for an oversized matcher", terr)
	}
}
