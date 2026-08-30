// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// canonicalFacts is the exact set of fields that participate in a fingerprint,
// listed positively rather than by exclusion so that a new field added to
// fleet.Cluster cannot silently start churning every spoke's fingerprint.
//
// Everything time-varying is absent by design. collectedAt in particular must
// never be included: if it were, every refresh would produce a new fingerprint
// even when nothing about the cluster had changed, the hub would re-fetch the
// full facts document from every spoke on every poll, and the optimisation the
// fingerprint exists to provide would be exactly inverted. The same reasoning
// excludes LastSeen, ConnectedSince, State and CertNotAfter, all of which the
// hub owns anyway.
type canonicalFacts struct {
	ID              string            `json:"id"`
	DisplayName     string            `json:"displayName"`
	Description     string            `json:"description"`
	Labels          map[string]string `json:"labels"`
	AgentVersion    string            `json:"agentVersion"`
	ProtocolVersion string            `json:"protocolVersion"`

	KubernetesAvailable  bool   `json:"k8sAvailable"`
	KubernetesReason     string `json:"k8sReason"`
	KubernetesVersion    string `json:"k8sVersion"`
	KubernetesClusterUID string `json:"k8sClusterUid"`
	KubernetesNodeCount  int32  `json:"k8sNodeCount"`

	PromReachable       bool              `json:"promReachable"`
	PromUnreachable     string            `json:"promUnreachableReason"`
	PromFlavor          string            `json:"promFlavor"`
	PromVersion         string            `json:"promVersion"`
	PromRetention       string            `json:"promRetention"`
	PromScrapeInterval  string            `json:"promScrapeInterval"`
	PromLookbackDelta   string            `json:"promLookbackDelta"`
	PromExternalLabels  map[string]string `json:"promExternalLabels"`
	PromActiveSeries    int64             `json:"promActiveSeries"`
	PromMetricNames     int64             `json:"promMetricNames"`
	PromJobs            []string          `json:"promJobs"`
	PromNamespaces      []string          `json:"promNamespaces"`
	PromMetricPrefixes  []string          `json:"promMetricPrefixes"`
	PromRuleGroups      int32             `json:"promRuleGroups"`
	PromAlertingRules   int32             `json:"promAlertingRules"`
	PromFiringAlerts    int32             `json:"promFiringAlerts"`
	PromHasAlertmanager bool              `json:"promHasAlertmanager"`
}

// Fingerprint returns the SHA-256, hex-encoded fingerprint of a fact set.
//
// The encoding is canonical and process-independent: struct fields are emitted
// in declaration order, encoding/json emits map keys in sorted order, and
// every slice is sorted into a copy before hashing. Two processes given the
// same facts therefore produce the same fingerprint, and reordering a job list
// upstream does not invalidate a hub's cache.
func Fingerprint(c fleet.Cluster) string {
	cf := canonicalFacts{
		ID:              c.ID,
		DisplayName:     c.DisplayName,
		Description:     c.Description,
		Labels:          c.Labels,
		AgentVersion:    c.AgentVersion,
		ProtocolVersion: c.ProtocolVersion,

		KubernetesAvailable:  c.Kubernetes.Available,
		KubernetesReason:     c.Kubernetes.UnavailableReason,
		KubernetesVersion:    c.Kubernetes.Version,
		KubernetesClusterUID: c.Kubernetes.ClusterUID,
		KubernetesNodeCount:  c.Kubernetes.NodeCount,

		PromReachable:       c.Prometheus.Reachable,
		PromUnreachable:     c.Prometheus.UnreachableReason,
		PromFlavor:          c.Prometheus.Flavor,
		PromVersion:         c.Prometheus.Version,
		PromRetention:       c.Prometheus.Retention,
		PromScrapeInterval:  c.Prometheus.ScrapeInterval,
		PromLookbackDelta:   c.Prometheus.LookbackDelta,
		PromExternalLabels:  c.Prometheus.ExternalLabels,
		PromActiveSeries:    c.Prometheus.ActiveSeries,
		PromMetricNames:     c.Prometheus.MetricNames,
		PromJobs:            sortedCopy(c.Prometheus.Jobs),
		PromNamespaces:      sortedCopy(c.Prometheus.Namespaces),
		PromMetricPrefixes:  sortedCopy(c.Prometheus.MetricPrefixes),
		PromRuleGroups:      c.Prometheus.RuleGroups,
		PromAlertingRules:   c.Prometheus.AlertingRules,
		PromFiringAlerts:    c.Prometheus.FiringAlerts,
		PromHasAlertmanager: c.Prometheus.HasAlertmanager,
	}
	// canonicalFacts contains only strings, numbers, bools, []string and
	// map[string]string -- no floats, no channels, no custom marshaler -- so
	// encoding/json has no failure mode here. A fingerprint that quietly fell
	// back to a hash of nothing would make every spoke look unchanged forever,
	// which is worse than stopping; and this branch can only be reached by
	// adding an unmarshalable field to the struct above, in this package.
	// canonicalFacts is deliberately restricted to JSON's infallible scalar,
	// map and slice types. Keep the ignored error beside that invariant instead
	// of carrying an unreachable panic branch that can never be tested honestly.
	b, _ := json.Marshal(cf)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sortedCopy returns a sorted copy, leaving the caller's slice untouched.
func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}
