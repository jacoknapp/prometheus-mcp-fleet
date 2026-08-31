// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
)

func TestQueryFallbacksReturnEmptyResultsHonestly(t *testing.T) {
	t.Parallel()

	emptyVector := `{"status":"success","data":{"resultType":"vector","result":[]}}`
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{QueryResults: map[string]string{
		`prometheus_target_interval_length_seconds{quantile="0.99"}`: emptyVector,
		"prometheus_build_info": emptyVector,
	}})
	client, err := promclient.New(promclient.Config{BaseURL: fake.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("promclient.New: %v", err)
	}
	c := &Collector{client: client}

	interval, err := c.scrapeIntervalByQuery(context.Background())
	if err != nil {
		t.Fatalf("scrapeIntervalByQuery: %v", err)
	}
	if interval != "" {
		t.Fatalf("scrape interval = %q, want empty", interval)
	}

	labels, err := c.externalLabelsByQuery(context.Background())
	if err != nil {
		t.Fatalf("externalLabelsByQuery: %v", err)
	}
	if labels != nil {
		t.Fatalf("external labels = %v, want nil", labels)
	}
}

func TestDetectFlavor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		server  string
		version string
		flags   map[string]string
		want    string
	}{
		{
			name: "thanos from the server header",
			// Thanos Querier answers the Prometheus API but is not Prometheus;
			// telling an agent otherwise sends it looking for a local TSDB.
			server: "Thanos/0.39.2", want: "Thanos",
		},
		{name: "thanos from the version string", version: "thanos, version 0.39.2", want: "Thanos"},
		{name: "mimir", server: "Mimir/2.18.0", want: "Mimir"},
		{name: "cortex", version: "cortex, version 1.19.0", want: "Cortex"},
		{name: "victoriametrics", server: "VictoriaMetrics/1.108.0", want: "VictoriaMetrics"},
		{name: "vmselect", server: "vmselect/1.108.0", want: "VictoriaMetrics"},
		{name: "vmsingle", server: "vmsingle/1.108.0", want: "VictoriaMetrics"},
		{name: "hyphenated victoria metrics", version: "victoria-metrics-1.108.0", want: "VictoriaMetrics"},
		{name: "prometheus from the header", server: "Prometheus/3.6.0", want: "Prometheus"},
		{
			name: "prometheus inferred from tsdb flags",
			// No product name anywhere, but only a real Prometheus reports
			// storage.tsdb.path on /api/v1/status/flags.
			version: "3.6.0", flags: map[string]string{"storage.tsdb.path": "/prometheus"},
			want: "Prometheus",
		},
		{
			name: "tsdb flags without a version is not enough",
			// A proxy could echo the flags; without a version we admit ignorance.
			flags: map[string]string{"storage.tsdb.path": "/prometheus"},
			want:  FlavorUnknown,
		},
		{name: "nothing to go on", want: FlavorUnknown},
		{name: "unrecognised product", server: "nginx/1.27.0", version: "9.9.9", want: FlavorUnknown},
		{
			name: "thanos wins over an incidental prometheus mention",
			// Thanos' own version banner mentions Prometheus; order matters.
			server: "Thanos/0.39.2", version: "prometheus-compatible", want: "Thanos",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := detectFlavor(tc.server, tc.version, tc.flags); got != tc.want {
				t.Fatalf("detectFlavor(%q, %q, %v) = %q, want %q", tc.server, tc.version, tc.flags, got, tc.want)
			}
		})
	}
}

func TestMetricPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, in, want string }{
		{"two segments", "kube_pod", "kube_pod"},
		{"more than two segments", "kube_pod_container_status_restarts_total", "kube_pod"},
		{"single segment", "up", "up"},
		{"leading underscores are stripped", "__name__", "name"},
		{"trailing underscore", "go_", "go"},
		{"only underscores", "___", ""},
		{"empty", "", ""},
		// Recording-rule names use ':' as their separator, so a name with one
		// underscore is already only two '_'-segments long and survives whole.
		{"colon in a recording rule name", "instance:node_cpu:rate5m", "instance:node_cpu:rate5m"},
		{"recording rule with two underscores", "instance:node_cpu_seconds:rate5m", "instance:node_cpu"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := metricPrefix(tc.in); got != tc.want {
				t.Fatalf("metricPrefix(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestTopPrefixesRanksByCount is the regression test for the ranking bug: the
// cap must select the most populous prefixes, not the alphabetically first
// ones, or the field stops carrying the signal it exists to carry.
func TestTopPrefixesRanksByCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		names []string
		topN  int
		want  []string
	}{
		{
			name: "ranked by count, ties broken alphabetically",
			names: []string{
				"kube_pod_info", "kube_pod_status_phase", "kube_pod_container_status_restarts_total",
				"istio_requests_total", "istio_requests_bytes",
				"go_goroutines", "apiserver_request_total",
			},
			topN: 25,
			want: []string{"kube_pod", "istio_requests", "apiserver_request", "go_goroutines"},
		},
		{
			name: "cap keeps the most populous, not the alphabetically first",
			names: []string{
				"zzz_metric_one", "zzz_metric_two", "zzz_metric_three",
				"aaa_metric_one",
				"bbb_metric_one",
			},
			topN: 1,
			want: []string{"zzz_metric"},
		},
		{
			name:  "topN zero means uncapped",
			names: []string{"a_one", "b_one", "c_one"},
			topN:  0,
			want:  []string{"a_one", "b_one", "c_one"},
		},
		{name: "no names", names: nil, topN: 25, want: nil},
		{name: "names that yield no prefix", names: []string{"___", ""}, topN: 25, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, topPrefixes(tc.names, tc.topN)); diff != "" {
				t.Fatalf("topPrefixes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTopPrefixesIsStableAcrossInputOrder proves the ranking does not depend on
// map iteration order, which would make the fingerprint churn between refreshes
// of an unchanged cluster.
func TestTopPrefixesIsStableAcrossInputOrder(t *testing.T) {
	t.Parallel()

	names := []string{
		"kube_pod_info", "kube_pod_status_phase", "istio_requests_total",
		"istio_requests_bytes", "node_cpu_seconds_total", "go_goroutines",
	}
	want := topPrefixes(names, 25)
	for range 50 {
		reversed := make([]string, len(names))
		for i, n := range names {
			reversed[len(names)-1-i] = n
		}
		if diff := cmp.Diff(want, topPrefixes(reversed, 25)); diff != "" {
			t.Fatalf("topPrefixes is order dependent (-first +reversed):\n%s", diff)
		}
	}
}

func TestCapList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		topN int
		want []string
	}{
		{"sorts and dedupes", []string{"b", "a", "b", "c"}, 25, []string{"a", "b", "c"}},
		{"caps", []string{"e", "d", "c", "b", "a"}, 2, []string{"a", "b"}},
		{"uncapped when topN is zero", []string{"b", "a"}, 0, []string{"a", "b"}},
		{"empty", nil, 25, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, capList(tc.in, tc.topN)); diff != "" {
				t.Fatalf("capList mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCapListDoesNotMutateItsInput(t *testing.T) {
	t.Parallel()
	in := []string{"c", "a", "b"}
	capList(in, 25)
	if diff := cmp.Diff([]string{"c", "a", "b"}, in); diff != "" {
		t.Fatalf("capList mutated its argument (-want +got):\n%s", diff)
	}
}

func TestParseGlobalSection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		doc          string
		wantLabels   map[string]string
		wantInterval string
	}{
		{
			name: "block form",
			doc: "global:\n  scrape_interval: 30s\n  evaluation_interval: 30s\n" +
				"  external_labels:\n    cluster: prod-us-east-1\n    region: us-east-1\n" +
				"scrape_configs:\n- job_name: kubelet\n",
			wantLabels:   map[string]string{"cluster": "prod-us-east-1", "region": "us-east-1"},
			wantInterval: "30s",
		},
		{
			name:         "inline flow map",
			doc:          "global:\n  scrape_interval: \"15s\"\n  external_labels: {cluster: eu, replica: 'a'}\n",
			wantLabels:   map[string]string{"cluster": "eu", "replica": "a"},
			wantInterval: "15s",
		},
		{
			name: "external labels outside the global block are ignored",
			// A scrape_config may carry an external_labels-looking key; only the
			// global block is authoritative.
			doc:          "scrape_configs:\n- job_name: x\n  external_labels:\n    cluster: wrong\n",
			wantLabels:   nil,
			wantInterval: "",
		},
		{
			name:         "comments and blank lines",
			doc:          "# a comment\n\nglobal:\n  # another\n  scrape_interval: 1m\n",
			wantInterval: "1m",
		},
		{
			name:         "dedent ends the external labels block",
			doc:          "global:\n  external_labels:\n    cluster: eu\n  scrape_interval: 45s\n",
			wantLabels:   map[string]string{"cluster": "eu"},
			wantInterval: "45s",
		},
		{name: "empty document"},
		{name: "not yaml at all", doc: "<html><body>login</body></html>"},
		{
			name:       "value-less lines are skipped",
			doc:        "global:\n  external_labels:\n    justakey\n    cluster: eu\n",
			wantLabels: map[string]string{"cluster": "eu"},
		},
		{
			name:         "value-less global line is skipped",
			doc:          "global:\n  justakey\n  scrape_interval: 20s\n",
			wantInterval: "20s",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			labels, interval := parseGlobalSection(tc.doc)
			if diff := cmp.Diff(tc.wantLabels, labels); diff != "" {
				t.Fatalf("labels mismatch (-want +got):\n%s", diff)
			}
			if interval != tc.wantInterval {
				t.Fatalf("scrape interval = %q, want %q", interval, tc.wantInterval)
			}
		})
	}
}

func TestParseInlineMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"pairs", "{a: b, c: d}", map[string]string{"a": "b", "c": "d"}},
		{"quoted", `{"a": "b"}`, map[string]string{"a": "b"}},
		{"not a flow map", "a: b", nil},
		{"empty braces", "{}", nil},
		{"pair without a colon", "{ab}", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, parseInlineMap(tc.in)); diff != "" {
				t.Fatalf("parseInlineMap mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnquote(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, in, want string }{
		{"double quotes", `"a"`, "a"},
		{"single quotes", `'a'`, "a"},
		{"unquoted", "a", "a"},
		{"one character", `"`, `"`},
		{"mismatched", `"a'`, `"a'`},
		// Exactly two characters is the smallest input the quote check can
		// ever match against: nothing else here proves the length guard
		// admits two runes rather than requiring three or more.
		{"empty double-quoted", `""`, ""},
		{"empty single-quoted", `''`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := unquote(tc.in); got != tc.want {
				t.Fatalf("unquote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"first wins", []string{"a", "b"}, "a"},
		{"skips empties", []string{"", "", "b"}, "b"},
		{"all empty", []string{"", ""}, ""},
		{"none", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := firstNonEmpty(tc.in...); got != tc.want {
				t.Fatalf("firstNonEmpty(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTruncateReason(t *testing.T) {
	t.Parallel()

	short := "prometheus refused the connection"
	if got := truncateReason(short); got != short {
		t.Fatalf("truncateReason clipped a short reason: %q", got)
	}
	long := strings.Repeat("x", 1000)
	got := truncateReason(long)
	if !strings.HasSuffix(got, "...[clipped]") {
		t.Fatalf("truncateReason(long) = %q, want a clipped marker", got)
	}
	if len(got) != 300+len("...[clipped]") {
		t.Fatalf("truncateReason(long) length = %d", len(got))
	}

	// Exactly at the cap: nothing else here distinguishes <= from <, so a
	// reason landing precisely on the limit must survive untouched.
	exact := strings.Repeat("y", 300)
	if got := truncateReason(exact); got != exact {
		t.Fatalf("truncateReason clipped a reason exactly at the cap: %q", got)
	}
}

func TestLabelKeyIsCanonical(t *testing.T) {
	t.Parallel()
	a := labelKey(map[string]string{"b": "2", "a": "1"})
	b := labelKey(map[string]string{"a": "1", "b": "2"})
	if a != b {
		t.Fatalf("labelKey is order dependent: %q vs %q", a, b)
	}
	if a != "a=1,b=2," {
		t.Fatalf("labelKey = %q", a)
	}
}

func TestHalveAndAppendNote(t *testing.T) {
	t.Parallel()

	if got := halve([]string{"a", "b", "c", "d"}); len(got) != 2 {
		t.Fatalf("halve returned %v", got)
	}
	if got := halve([]string{"a"}); got != nil {
		t.Fatalf("halve of a single element = %v, want nil", got)
	}
	if got := appendNote("", "note"); got != "note" {
		t.Fatalf("appendNote onto an empty description = %q", got)
	}
	if got := appendNote("desc", "note"); got != "desc note" {
		t.Fatalf("appendNote = %q", got)
	}
}

// TestCapSizeAcceptsAPayloadExactlyAtTheCap proves the size check is
// inclusive: a payload landing exactly on MaxFactsBytes must survive
// untouched. Every other capSize test here is comfortably over or under the
// cap, so nothing else distinguishes <= from <.
func TestCapSizeAcceptsAPayloadExactlyAtTheCap(t *testing.T) {
	t.Parallel()

	cluster := fleet.Cluster{
		ID:         "prod",
		Prometheus: fleet.PrometheusInfo{Jobs: []string{"a", "b"}},
	}
	b, err := json.Marshal(cluster)
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{maxFactsBytes: len(b)}
	c.capSize(&cluster)

	if diff := cmp.Diff([]string{"a", "b"}, cluster.Prometheus.Jobs); diff != "" {
		t.Fatalf("a payload exactly at the cap was truncated (-want +got):\n%s", diff)
	}
	if cluster.Description != "" {
		t.Fatalf("description = %q, want no truncation note", cluster.Description)
	}
}

// TestShrinkSampledSkipsFieldsAlreadyEmpty proves the precedence chain moves
// past a field with nothing left in it rather than mistaking "empty" for
// "worth shrinking": each len(...) > 0 guard has to be strict, or the chain
// gets stuck on an already-empty field and the ones behind it -- which may
// still have something to give -- are never reached.
func TestShrinkSampledSkipsFieldsAlreadyEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cluster fleet.Cluster
		want    fleet.Cluster
		wantOK  bool
	}{
		{
			name:    "namespaces present: they are the first to shrink",
			cluster: fleet.Cluster{Prometheus: fleet.PrometheusInfo{Namespaces: []string{"a", "b", "c", "d"}}},
			want:    fleet.Cluster{Prometheus: fleet.PrometheusInfo{Namespaces: []string{"a", "b"}}},
			wantOK:  true,
		},
		{
			name:    "namespaces empty, jobs present: jobs shrink",
			cluster: fleet.Cluster{Prometheus: fleet.PrometheusInfo{Jobs: []string{"a", "b", "c", "d"}}},
			want:    fleet.Cluster{Prometheus: fleet.PrometheusInfo{Jobs: []string{"a", "b"}}},
			wantOK:  true,
		},
		{
			name:    "namespaces and jobs empty, metric prefixes present: prefixes shrink",
			cluster: fleet.Cluster{Prometheus: fleet.PrometheusInfo{MetricPrefixes: []string{"a", "b", "c", "d"}}},
			want:    fleet.Cluster{Prometheus: fleet.PrometheusInfo{MetricPrefixes: []string{"a", "b"}}},
			wantOK:  true,
		},
		{
			name: "only external labels present: they are cleared",
			cluster: fleet.Cluster{Prometheus: fleet.PrometheusInfo{
				ExternalLabels: map[string]string{"cluster": "prod"},
			}},
			want:   fleet.Cluster{Prometheus: fleet.PrometheusInfo{ExternalLabels: nil}},
			wantOK: true,
		},
		{
			name:    "nothing sampled is left",
			cluster: fleet.Cluster{},
			want:    fleet.Cluster{},
			wantOK:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := tc.cluster
			ok := shrinkSampled(&c)
			if ok != tc.wantOK {
				t.Fatalf("shrinkSampled() ok = %v, want %v", ok, tc.wantOK)
			}
			if diff := cmp.Diff(tc.want, c); diff != "" {
				t.Fatalf("shrinkSampled mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTSDBStatusMetricNamesSentinelSurvivesAMissingEntry proves the
// metricNames sentinel is only overwritten when
// labelValueCountByLabelName actually reports the __name__ entry. Unlike
// activeSeries, which every response path assigns unconditionally, metricNames
// is only set inside a loop that may never find its target -- a
// Prometheus-compatible server that omits it must still report the honest
// "unknown" sentinel rather than a value that happens to look like zero.
func TestTSDBStatusMetricNamesSentinelSurvivesAMissingEntry(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"headStats":{"numSeries":42},` +
			`"labelValueCountByLabelName":[{"name":"job","value":7}]}}`))
	}))
	defer srv.Close()

	client, err := promclient.New(promclient.Config{BaseURL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{client: client}
	got, err := c.tsdbStatus(context.Background())
	if err != nil {
		t.Fatalf("tsdbStatus: %v", err)
	}
	if got.activeSeries != 42 {
		t.Fatalf("activeSeries = %d, want 42", got.activeSeries)
	}
	if got.metricNames != -1 {
		t.Fatalf("metricNames = %d, want the -1 sentinel when __name__ is absent from the response", got.metricNames)
	}
}

// TestHasAlertmanagerRequiresAtLeastOneActivePeer proves the check is a
// genuine emptiness test: a response that decodes cleanly but lists zero
// active Alertmanagers must report false, not "decoded without error
// therefore true".
func TestHasAlertmanagerRequiresAtLeastOneActivePeer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"activeAlertmanagers":[]}}`))
	}))
	defer srv.Close()

	client, err := promclient.New(promclient.Config{BaseURL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{client: client}
	got, err := c.hasAlertmanager(context.Background())
	if err != nil {
		t.Fatalf("hasAlertmanager: %v", err)
	}
	if got {
		t.Fatal("hasAlertmanager() = true with zero active peers")
	}
}

// TestSortedSamplesIsStableForEqualLabelSets proves the ordering function is a
// strict less-than. sort.SliceStable's guarantee for genuinely tied elements
// -- that they keep their original relative order -- depends on that: a
// comparator that also reports "less" when two keys are equal makes every tied
// pair look reorderable, and Go's stable sort resolves that by walking a tied
// element past everything before it, reversing the run.
func TestSortedSamplesIsStableForEqualLabelSets(t *testing.T) {
	t.Parallel()

	in := make(promclient.Vector, 6)
	for i := range in {
		// Every sample renders the same label key; Value is the only way to
		// tell them apart afterwards.
		in[i] = promclient.Sample{Labels: map[string]string{"job": "x"}, Value: float64(i)}
	}
	got := sortedSamples(in)
	for i, s := range got {
		if s.Value != float64(i) {
			t.Fatalf("sortedSamples reordered equal-key samples: got order %v, want 0..%d unchanged",
				valuesOf(got), len(in)-1)
		}
	}
}

// valuesOf collects a vector's values in order, for a readable failure
// message.
func valuesOf(v promclient.Vector) []float64 {
	out := make([]float64, len(v))
	for i, s := range v {
		out[i] = s.Value
	}
	return out
}
