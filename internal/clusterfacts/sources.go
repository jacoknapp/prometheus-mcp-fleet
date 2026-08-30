// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
)

// Reasons recorded on facts that could not be collected. They are stable
// strings so the hub can render them without interpreting an error message.
const (
	// reasonNoKubernetesAccess is the default Kubernetes unavailability
	// reason: the spoke has no RBAC by design.
	reasonNoKubernetesAccess = "spoke has no Kubernetes API access by design; set PMF_CLUSTER_K8S_* or expose kubernetes_build_info to Prometheus"
	// reasonNoTSDBStatus explains a missing series count.
	reasonNoTSDBStatus = "/api/v1/status/tsdb unavailable"
)

// FlavorUnknown is the flavor reported when detection has nothing to go on.
// It is deliberately not a guess: a wrong flavor would send an agent looking
// for Thanos-only endpoints on a plain Prometheus.
const FlavorUnknown = "unknown"

// Refresh recomputes the expensive facts and publishes them atomically.
//
// Every source is independent: a failure records a reason on the affected
// field and leaves the others intact. The returned error is the join of the
// sources that failed and exists for logging and for the
// promfleet_spoke_facts_refresh_total{result} metric. The published snapshot
// is updated whether or not it is nil.
//
// When the Prometheus ping fails the collector marks the cluster unreachable
// and carries the previously collected detail forward rather than blanking it,
// so a Prometheus restart does not erase what an agent knows about a cluster.
func (c *Collector) Refresh(ctx context.Context) error {
	cluster := c.base()
	cluster.LastSeen = c.now()

	if err := c.client.Ping(ctx); err != nil {
		prev := c.previous().Prometheus
		prev.Reachable = false
		prev.UnreachableReason = truncateReason(err.Error())
		cluster.Prometheus = prev
		cluster.Kubernetes = c.previous().Kubernetes
		c.applyOperatorKubernetes(&cluster.Kubernetes)
		c.capSize(&cluster)
		c.publish(cluster, c.now())
		return fmt.Errorf("ping prometheus: %w", err)
	}

	var problems []error
	fail := func(source string, err error) {
		if err == nil {
			return
		}
		problems = append(problems, fmt.Errorf("%s: %w", source, err))
		c.log.LogAttrs(ctx, slog.LevelDebug, "cluster fact source failed",
			slog.String("source", source), slog.String("error", err.Error()))
	}

	prom := fleet.PrometheusInfo{Reachable: true, ActiveSeries: -1, MetricNames: -1}

	serverHeader, version, err := c.buildInfo(ctx)
	fail("buildinfo", err)
	prom.Version = version

	flags, err := c.flags(ctx)
	fail("flags", err)
	prom.Retention = firstNonEmpty(flags["storage.tsdb.retention.time"], flags["storage.tsdb.retention"], flags["storage.tsdb.retention.size"])
	prom.LookbackDelta = flags["query.lookback-delta"]
	// The global scrape interval is not a Prometheus command-line flag; some
	// compatible servers do expose it as one, so it is worth a look before
	// falling back to the config endpoint and then to a probe query.
	prom.ScrapeInterval = firstNonEmpty(flags["scrape.interval"], flags["promscrape.scrapeInterval"])
	prom.Flavor = detectFlavor(serverHeader, version, flags)

	// External labels: the config endpoint is authoritative but gated off by
	// default because scrape configs embed credentials. A gated endpoint is an
	// expected outcome, not a failure.
	externalLabels, configScrapeInterval, err := c.fromStatusConfig(ctx)
	if err != nil && !errors.Is(err, promapi.ErrEndpointGated) {
		fail("status/config", err)
	}
	prom.ExternalLabels = externalLabels
	if prom.ScrapeInterval == "" {
		prom.ScrapeInterval = configScrapeInterval
	}
	if len(prom.ExternalLabels) == 0 {
		labels, err := c.externalLabelsByQuery(ctx)
		if err != nil {
			fail("external labels probe", err)
		}
		prom.ExternalLabels = labels
	}
	if prom.ScrapeInterval == "" {
		interval, err := c.scrapeIntervalByQuery(ctx)
		if err != nil {
			fail("scrape interval probe", err)
		}
		prom.ScrapeInterval = interval
	}

	tsdb, tsdbErr := c.tsdbStatus(ctx)
	fail("status/tsdb", tsdbErr)
	prom.ActiveSeries = tsdb.activeSeries

	// The metric-name list is fetched for its own sake: the prefixes derived
	// from it are the highest-value fact this package publishes. Its length is
	// therefore an exact metric-name count that costs nothing extra, and the
	// tsdb figure is only needed when that call is the one that failed.
	names, err := c.client.LabelValues(ctx, "__name__")
	if err != nil {
		fail("label_values(__name__)", err)
		prom.MetricNames = tsdb.metricNames
	} else {
		prom.MetricNames = int64(len(names))
		prom.MetricPrefixes = topPrefixes(names, c.topN)
	}

	jobs, err := c.client.LabelValues(ctx, "job")
	fail("label_values(job)", err)
	prom.Jobs = capList(jobs, c.topN)

	namespaces, err := c.client.LabelValues(ctx, "namespace")
	fail("label_values(namespace)", err)
	prom.Namespaces = capList(namespaces, c.topN)

	groups, alerting, err := c.ruleCounts(ctx)
	fail("rules", err)
	prom.RuleGroups, prom.AlertingRules = groups, alerting

	firing, err := c.firingAlerts(ctx)
	fail("alerts", err)
	prom.FiringAlerts = firing

	hasAM, err := c.hasAlertmanager(ctx)
	fail("alertmanagers", err)
	prom.HasAlertmanager = hasAM

	cluster.Prometheus = prom
	cluster.Kubernetes = c.kubernetes(ctx, fail)

	c.capSize(&cluster)
	c.publish(cluster, c.now())
	return errors.Join(problems...)
}

// buildInfo returns the Server response header and the reported version.
func (c *Collector) buildInfo(ctx context.Context) (serverHeader, version string, err error) {
	var env struct {
		Data struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	header, err := c.client.GetJSONHeaders(ctx, promapi.EndpointBuildInfo, nil, &env)
	if header != nil {
		serverHeader = header.Get("Server")
	}
	if err != nil {
		return serverHeader, "", err
	}
	return serverHeader, env.Data.Version, nil
}

// flags returns the upstream command-line flags.
func (c *Collector) flags(ctx context.Context) (map[string]string, error) {
	var env struct {
		Data map[string]string `json:"data"`
	}
	if err := c.client.GetJSON(ctx, promapi.EndpointFlags, nil, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// tsdbCounts holds the two cardinality numbers /api/v1/status/tsdb reports
// that the facts care about. Both are -1 when unknown.
type tsdbCounts struct {
	activeSeries int64
	metricNames  int64
}

// tsdbStatus returns the head-block series count and the number of distinct
// metric names from /api/v1/status/tsdb.
//
// There is deliberately no PromQL fallback here. count({__name__=~".+"}) would
// answer the same question, but on a large cluster it walks the whole index and
// can take a Prometheus down; a facts refresh must never be the most expensive
// query a cluster serves. When tsdb status is unavailable both counts stay -1
// and [reasonNoTSDBStatus] is recorded on the returned error, which the caller
// joins into the refresh error and logs.
func (c *Collector) tsdbStatus(ctx context.Context) (tsdbCounts, error) {
	var env struct {
		Data struct {
			HeadStats struct {
				NumSeries int64 `json:"numSeries"`
			} `json:"headStats"`
			LabelValueCounts []struct {
				Name  string `json:"name"`
				Value int64  `json:"value"`
			} `json:"labelValueCountByLabelName"`
		} `json:"data"`
	}
	out := tsdbCounts{activeSeries: -1, metricNames: -1}
	if err := c.client.GetJSON(ctx, promapi.EndpointTSDBStatus, nil, &env); err != nil {
		return out, fmt.Errorf("%s: %w", reasonNoTSDBStatus, err)
	}
	out.activeSeries = env.Data.HeadStats.NumSeries
	for _, lv := range env.Data.LabelValueCounts {
		if lv.Name == "__name__" {
			out.metricNames = lv.Value
			break
		}
	}
	return out, nil
}

// ruleCounts returns the number of rule groups and of alerting rules.
// exclude_alerts trims the response: the alert instances themselves are
// counted from /api/v1/alerts instead, and on a busy cluster they dominate the
// payload.
func (c *Collector) ruleCounts(ctx context.Context) (groups, alerting int32, err error) {
	var env struct {
		Data struct {
			Groups []struct {
				Rules []struct {
					Type string `json:"type"`
				} `json:"rules"`
			} `json:"groups"`
		} `json:"data"`
	}
	form := url.Values{"exclude_alerts": []string{"true"}}
	if err := c.client.GetJSON(ctx, promapi.EndpointRules, form, &env); err != nil {
		return 0, 0, err
	}
	// The rules response is read through promclient, which caps it at
	// MaxResponseBytes; a group costs tens of bytes of JSON, so the count
	// cannot approach 2^31.
	groups = int32(len(env.Data.Groups)) //nolint:gosec // G115: bounded by the client's response byte budget.
	for _, g := range env.Data.Groups {
		for _, r := range g.Rules {
			if r.Type == "alerting" {
				alerting++
			}
		}
	}
	return groups, alerting, nil
}

// firingAlerts counts the alerts currently in the firing state. Pending alerts
// are excluded: an agent asking "what is broken" means firing.
func (c *Collector) firingAlerts(ctx context.Context) (int32, error) {
	var env struct {
		Data struct {
			Alerts []struct {
				State string `json:"state"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if err := c.client.GetJSON(ctx, promapi.EndpointAlerts, nil, &env); err != nil {
		return 0, err
	}
	var n int32
	for _, a := range env.Data.Alerts {
		if a.State == "firing" {
			n++
		}
	}
	return n, nil
}

// hasAlertmanager reports whether any Alertmanager peer is active.
func (c *Collector) hasAlertmanager(ctx context.Context) (bool, error) {
	var env struct {
		Data struct {
			Active []struct {
				URL string `json:"url"`
			} `json:"activeAlertmanagers"`
		} `json:"data"`
	}
	if err := c.client.GetJSON(ctx, promapi.EndpointAlertmanagers, nil, &env); err != nil {
		return false, err
	}
	return len(env.Data.Active) > 0, nil
}

// kubernetes assembles the Kubernetes facts. Availability is false with a
// reason by default; operator configuration wins, and PromQL is a
// failure-tolerant last resort.
func (c *Collector) kubernetes(ctx context.Context, fail func(string, error)) fleet.KubernetesInfo {
	info := fleet.KubernetesInfo{Available: false, UnavailableReason: reasonNoKubernetesAccess}

	if v, err := c.kubernetesVersionByQuery(ctx); err != nil {
		fail("kubernetes_build_info", err)
	} else if v != "" {
		info.Version = v
	}
	if n, err := c.nodeCountByQuery(ctx); err != nil {
		fail("count(kube_node_info)", err)
	} else if n > 0 {
		info.NodeCount = n
	}
	if info.Version != "" || info.NodeCount > 0 {
		info.Available = true
		info.UnavailableReason = ""
	}
	c.applyOperatorKubernetes(&info)
	return info
}

// applyOperatorKubernetes overlays the operator-supplied Kubernetes values.
func (c *Collector) applyOperatorKubernetes(info *fleet.KubernetesInfo) {
	if c.k8sVersion != "" {
		info.Version = c.k8sVersion
	}
	if c.k8sUID != "" {
		info.ClusterUID = c.k8sUID
	}
	if c.k8sNodeCount > 0 {
		info.NodeCount = c.k8sNodeCount
	}
	if info.Version != "" || info.ClusterUID != "" || info.NodeCount > 0 {
		info.Available = true
		info.UnavailableReason = ""
	}
}

// kubernetesVersionByQuery reads the Kubernetes version off the
// kubernetes_build_info metric, which both the apiserver and kube-state-metrics
// export. The label is git_version on most builds and gitVersion on some.
func (c *Collector) kubernetesVersionByQuery(ctx context.Context) (string, error) {
	v, err := c.client.InstantQuery(ctx, "kubernetes_build_info")
	if err != nil {
		return "", err
	}
	for _, s := range sortedSamples(v) {
		for _, key := range []string{"git_version", "gitVersion", "version"} {
			if val := s.Labels[key]; val != "" {
				return val, nil
			}
		}
	}
	return "", nil
}

// nodeCountByQuery counts nodes via kube-state-metrics.
func (c *Collector) nodeCountByQuery(ctx context.Context) (int32, error) {
	v, err := c.client.InstantQuery(ctx, "count(kube_node_info)")
	if err != nil {
		return 0, err
	}
	if len(v) == 0 {
		return 0, nil
	}
	n := v[0].Value
	if n < 0 || n > float64(1<<31-1) {
		return 0, nil
	}
	return int32(n), nil //nolint:gosec // G115: n is range-checked against [0, 2^31-1] immediately above.
}

// scrapeIntervalByQuery derives the global scrape interval from the interval
// label of prometheus_target_interval_length_seconds, which Prometheus sets to
// the configured interval string. It is the only cheap way to learn the value
// when /api/v1/status/config is gated off, since the interval is not a
// command-line flag.
func (c *Collector) scrapeIntervalByQuery(ctx context.Context) (string, error) {
	v, err := c.client.InstantQuery(ctx, `prometheus_target_interval_length_seconds{quantile="0.99"}`)
	if err != nil {
		return "", err
	}
	for _, s := range sortedSamples(v) {
		if iv := s.Labels["interval"]; iv != "" {
			return iv, nil
		}
	}
	return "", nil
}

// nonExternalLabels are the label names that appear on prometheus_build_info
// for reasons other than external labels: the metric's own labels and the
// labels Kubernetes service discovery attaches.
var nonExternalLabels = map[string]bool{
	"__name__": true, "instance": true, "job": true, "version": true,
	"revision": true, "branch": true, "goversion": true, "goarch": true,
	"goos": true, "tags": true, "container": true, "endpoint": true,
	"namespace": true, "pod": true, "service": true, "node": true,
	"pod_template_hash": true,
}

// externalLabelsByQuery derives the external labels without reading the scrape
// config.
//
// The heuristic: query prometheus_build_info and treat every label that is not
// one of the metric's own labels or a service-discovery label as an external
// label. On Thanos, Mimir, Cortex and any federated setup the external labels
// are stamped onto every series, so this returns exactly cluster/region/replica
// and friends. On a standalone Prometheus, which does not add external labels
// to its own query results, it correctly returns nothing.
//
// It is best-effort by construction: an empty result is not an error.
func (c *Collector) externalLabelsByQuery(ctx context.Context) (map[string]string, error) {
	v, err := c.client.InstantQuery(ctx, "prometheus_build_info")
	if err != nil {
		return nil, err
	}
	for _, s := range sortedSamples(v) {
		out := map[string]string{}
		for k, val := range s.Labels {
			if !nonExternalLabels[k] && val != "" {
				out[k] = val
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, nil
}

// sortedSamples orders a vector deterministically by its rendered label set,
// so that a multi-series result does not make the facts churn between
// refreshes.
func sortedSamples(v promclient.Vector) promclient.Vector {
	out := slices.Clone(v)
	sort.SliceStable(out, func(i, j int) bool {
		return labelKey(out[i].Labels) < labelKey(out[j].Labels)
	})
	return out
}

// labelKey renders a label set canonically.
func labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(',')
	}
	return b.String()
}

// fromStatusConfig reads the external labels and global scrape interval from
// /api/v1/status/config. It returns promapi.ErrEndpointGated (wrapped) when
// the operator has not enabled the endpoint, which the caller treats as an
// expected outcome rather than a failure.
func (c *Collector) fromStatusConfig(ctx context.Context) (map[string]string, string, error) {
	var env struct {
		Data struct {
			YAML string `json:"yaml"`
		} `json:"data"`
	}
	if err := c.client.GetJSON(ctx, promapi.EndpointConfig, nil, &env); err != nil {
		return nil, "", err
	}
	labels, interval := parseGlobalSection(env.Data.YAML)
	return labels, interval, nil
}

// parseGlobalSection extracts scrape_interval and external_labels from the
// global block of a Prometheus configuration.
//
// This is a deliberate 40-line scanner rather than a YAML dependency: the
// dependency budget in BUILD_SPEC section 2 is a closed set, and the two
// values wanted here live at a fixed, simple place in the document. Anything
// it does not understand yields empty values, never an error.
func parseGlobalSection(doc string) (labels map[string]string, scrapeInterval string) {
	inGlobal := false
	inExternal := false
	externalIndent := 0
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			inGlobal = strings.HasPrefix(line, "global:")
			inExternal = false
			continue
		}
		if !inGlobal {
			continue
		}
		if inExternal {
			if indent > externalIndent {
				if k, v, ok := strings.Cut(trimmed, ":"); ok {
					if key, val := strings.TrimSpace(k), unquote(strings.TrimSpace(v)); key != "" && val != "" {
						if labels == nil {
							labels = map[string]string{}
						}
						labels[key] = val
					}
				}
				continue
			}
			inExternal = false
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "scrape_interval":
			scrapeInterval = unquote(val)
		case "external_labels":
			if val == "" {
				inExternal, externalIndent = true, indent
				continue
			}
			for k, v := range parseInlineMap(val) {
				if labels == nil {
					labels = map[string]string{}
				}
				labels[k] = v
			}
		}
	}
	return labels, scrapeInterval
}

// parseInlineMap handles the YAML flow form, external_labels: {a: b, c: d}.
func parseInlineMap(s string) map[string]string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s[1:len(s)-1], ",") {
		k, v, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		if key, val := unquote(strings.TrimSpace(k)), unquote(strings.TrimSpace(v)); key != "" && val != "" {
			out[key] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// unquote strips one layer of YAML quoting.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// detectFlavor identifies the Prometheus-compatible server.
//
// What it keys on, in order:
//  1. The Server response header, which Thanos, Mimir, Cortex and
//     VictoriaMetrics all set to their own product name.
//  2. The buildinfo version string, which the Cortex-derived projects prefix
//     with the product name.
//  3. The presence of storage.tsdb.* command-line flags, which only an actual
//     Prometheus reports on /api/v1/status/flags.
//
// Anything else is [FlavorUnknown]. Guessing would be worse than admitting
// ignorance: an agent told a plain Prometheus is Thanos will reach for
// endpoints that are not there.
func detectFlavor(serverHeader, version string, flags map[string]string) string {
	haystack := strings.ToLower(serverHeader + " " + version)
	switch {
	case strings.Contains(haystack, "thanos"):
		return "Thanos"
	case strings.Contains(haystack, "mimir"):
		return "Mimir"
	case strings.Contains(haystack, "cortex"):
		return "Cortex"
	case strings.Contains(haystack, "victoriametrics"), strings.Contains(haystack, "vmselect"),
		strings.Contains(haystack, "vmsingle"), strings.Contains(haystack, "victoria-metrics"):
		return "VictoriaMetrics"
	case strings.Contains(haystack, "prometheus"):
		return "Prometheus"
	}
	if flags["storage.tsdb.path"] != "" && version != "" {
		return "Prometheus"
	}
	return FlavorUnknown
}

// topPrefixes ranks metric-name prefixes by how many metric names share them.
//
// A prefix is the first two underscore-separated segments of a metric name, so
// kube_pod_info and kube_pod_status_phase both count towards "kube_pod". This
// is the single highest-value fact the spoke publishes: it tells a model in
// one glance whether a cluster is kube_-shaped, istio_-shaped or jvm_-shaped,
// without the model spending a query to find out.
//
// Ties break alphabetically so the list is stable across refreshes and the
// fingerprint does not churn.
func topPrefixes(names []string, topN int) []string {
	counts := map[string]int{}
	for _, name := range names {
		if p := metricPrefix(name); p != "" {
			counts[p]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	prefixes := make([]string, 0, len(counts))
	for p := range counts {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if counts[prefixes[i]] != counts[prefixes[j]] {
			return counts[prefixes[i]] > counts[prefixes[j]]
		}
		return prefixes[i] < prefixes[j]
	})
	// Truncate in rank order rather than through capList, which sorts
	// alphabetically. Sorting here would select the alphabetically first topN
	// prefixes instead of the most populous ones, which is precisely the
	// opposite of what makes this field worth publishing: an agent shown
	// "apiserver_request, cadvisor_..., container_cpu" learns far less than one
	// shown "kube_pod, istio_request, jvm_memory". The fingerprint is unaffected
	// because it sorts every slice into a copy before hashing.
	if topN > 0 && len(prefixes) > topN {
		prefixes = prefixes[:topN]
	}
	return prefixes
}

// metricPrefix returns the first two underscore-separated segments of a metric
// name, or the whole name when it has fewer than two.
func metricPrefix(name string) string {
	name = strings.TrimLeft(name, "_")
	if name == "" {
		return ""
	}
	first, rest, ok := strings.Cut(name, "_")
	if !ok {
		return first
	}
	second, _, _ := strings.Cut(rest, "_")
	if second == "" {
		return first
	}
	return first + "_" + second
}

// capList sorts and truncates a sampled list. Sorting makes the sample stable
// between refreshes, which keeps the fingerprint stable.
func capList(in []string, topN int) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	out = slices.Compact(out)
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncateReason bounds an unreachability reason so a verbose upstream error
// cannot dominate the facts payload.
func truncateReason(s string) string {
	const max = 300
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[clipped]"
}
