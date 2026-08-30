// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
