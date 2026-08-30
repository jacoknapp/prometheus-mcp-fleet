// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/clusterfacts"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// sampleCluster is a fully populated fact set. Tests mutate a copy of it to
// prove exactly which fields the fingerprint is sensitive to.
func sampleCluster() fleet.Cluster {
	return fleet.Cluster{
		ID:              "prod-us-east-1",
		DisplayName:     "Production US East",
		Description:     "customer-facing API tier",
		Labels:          map[string]string{"env": "prod", "region": "us-east-1", "tier": "api"},
		AgentVersion:    "1.4.0",
		ProtocolVersion: "2026-07-28",
		Kubernetes: fleet.KubernetesInfo{
			Available: true, Version: "v1.32.4", ClusterUID: "9f2c", NodeCount: 12,
		},
		Prometheus: fleet.PrometheusInfo{
			Reachable:      true,
			Flavor:         "Prometheus",
			Version:        "3.6.0",
			Retention:      "15d",
			ScrapeInterval: "30s",
			LookbackDelta:  "5m",
			ExternalLabels: map[string]string{"cluster": "prod-us-east-1", "region": "us-east-1"},
			ActiveSeries:   482913,
			MetricNames:    2211,
			Jobs:           []string{"apiserver", "kubelet", "node-exporter"},
			Namespaces:     []string{"default", "kube-system", "monitoring"},
			MetricPrefixes: []string{"kube_pod", "container_cpu", "node_cpu"},
			RuleGroups:     2, AlertingRules: 3, FiringAlerts: 2, HasAlertmanager: true,
		},
	}
}

func TestFingerprintIsHexSHA256(t *testing.T) {
	t.Parallel()
	fp := clusterfacts.Fingerprint(sampleCluster())
	if len(fp) != 64 {
		t.Fatalf("fingerprint %q is %d chars, want 64", fp, len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Fatalf("fingerprint is not hex: %v", err)
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	t.Parallel()
	want := clusterfacts.Fingerprint(sampleCluster())
	// A fresh map each iteration gives Go's randomised map iteration a genuine
	// chance to change the encoding order if anything depended on it.
	for range 200 {
		if got := clusterfacts.Fingerprint(sampleCluster()); got != want {
			t.Fatalf("fingerprint is not deterministic: %q != %q", got, want)
		}
	}
}

// TestFingerprintIgnoresMapOrderAndSliceOrder is the property the hub's
// Describe cache depends on: the same facts arriving in a different order must
// hash the same, or every poll would look like a change.
func TestFingerprintIgnoresMapOrderAndSliceOrder(t *testing.T) {
	t.Parallel()

	want := clusterfacts.Fingerprint(sampleCluster())

	tests := []struct {
		name   string
		mutate func(*fleet.Cluster)
	}{
		{
			name: "labels rebuilt in the opposite order",
			mutate: func(c *fleet.Cluster) {
				c.Labels = map[string]string{"tier": "api", "region": "us-east-1", "env": "prod"}
			},
		},
		{
			name: "external labels rebuilt in the opposite order",
			mutate: func(c *fleet.Cluster) {
				c.Prometheus.ExternalLabels = map[string]string{"region": "us-east-1", "cluster": "prod-us-east-1"}
			},
		},
		{
			name: "jobs reversed",
			mutate: func(c *fleet.Cluster) {
				c.Prometheus.Jobs = []string{"node-exporter", "kubelet", "apiserver"}
			},
		},
		{
			name: "namespaces reversed",
			mutate: func(c *fleet.Cluster) {
				c.Prometheus.Namespaces = []string{"monitoring", "kube-system", "default"}
			},
		},
		{
			name: "metric prefixes reordered",
			mutate: func(c *fleet.Cluster) {
				c.Prometheus.MetricPrefixes = []string{"node_cpu", "kube_pod", "container_cpu"}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := sampleCluster()
			tc.mutate(&c)
			if got := clusterfacts.Fingerprint(c); got != want {
				t.Fatalf("reordering changed the fingerprint: %q != %q", got, want)
			}
		})
	}
}

// TestFingerprintExcludesTimeVaryingFields is the reason the whole optimisation
// works. If collectedAt or any of the hub-owned timestamps contributed, every
// refresh of an unchanged cluster would produce a new hash, the hub would
// re-fetch the full document from every spoke on every poll, and the
// fingerprint would cost bandwidth instead of saving it.
func TestFingerprintExcludesTimeVaryingFields(t *testing.T) {
	t.Parallel()

	want := clusterfacts.Fingerprint(sampleCluster())
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		mutate func(*fleet.Cluster)
	}{
		{"lastSeen", func(c *fleet.Cluster) { c.LastSeen = now }},
		{"connectedSince", func(c *fleet.Cluster) { c.ConnectedSince = now.Add(-time.Hour) }},
		{"certNotAfter", func(c *fleet.Cluster) { c.CertNotAfter = now.Add(336 * time.Hour) }},
		{"state", func(c *fleet.Cluster) { c.State = fleet.StateDegraded }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := sampleCluster()
			tc.mutate(&c)
			if got := clusterfacts.Fingerprint(c); got != want {
				t.Fatalf("%s contributed to the fingerprint: %q != %q", tc.name, got, want)
			}
		})
	}
}

// TestFingerprintIsSensitiveToEveryPublishedFact walks every field that an
// agent can act on and proves a change to it is visible. Without this, the
// exclusion test above could be satisfied by a fingerprint that ignores
// everything.
func TestFingerprintIsSensitiveToEveryPublishedFact(t *testing.T) {
	t.Parallel()

	want := clusterfacts.Fingerprint(sampleCluster())

	tests := []struct {
		name   string
		mutate func(*fleet.Cluster)
	}{
		{"id", func(c *fleet.Cluster) { c.ID = "other" }},
		{"displayName", func(c *fleet.Cluster) { c.DisplayName = "other" }},
		{"description", func(c *fleet.Cluster) { c.Description = "other" }},
		{"labels value", func(c *fleet.Cluster) { c.Labels["env"] = "staging" }},
		{"labels key added", func(c *fleet.Cluster) { c.Labels["new"] = "1" }},
		{"labels key removed", func(c *fleet.Cluster) { delete(c.Labels, "env") }},
		{"agentVersion", func(c *fleet.Cluster) { c.AgentVersion = "1.5.0" }},
		{"protocolVersion", func(c *fleet.Cluster) { c.ProtocolVersion = "2027-01-01" }},
		{"k8s available", func(c *fleet.Cluster) { c.Kubernetes.Available = false }},
		{"k8s reason", func(c *fleet.Cluster) { c.Kubernetes.UnavailableReason = "no rbac" }},
		{"k8s version", func(c *fleet.Cluster) { c.Kubernetes.Version = "v1.33.0" }},
		{"k8s uid", func(c *fleet.Cluster) { c.Kubernetes.ClusterUID = "other" }},
		{"k8s node count", func(c *fleet.Cluster) { c.Kubernetes.NodeCount = 13 }},
		{"prom reachable", func(c *fleet.Cluster) { c.Prometheus.Reachable = false }},
		{"prom unreachable reason", func(c *fleet.Cluster) { c.Prometheus.UnreachableReason = "refused" }},
		{"prom flavor", func(c *fleet.Cluster) { c.Prometheus.Flavor = "Thanos" }},
		{"prom version", func(c *fleet.Cluster) { c.Prometheus.Version = "3.7.0" }},
		{"prom retention", func(c *fleet.Cluster) { c.Prometheus.Retention = "30d" }},
		{"prom scrape interval", func(c *fleet.Cluster) { c.Prometheus.ScrapeInterval = "15s" }},
		{"prom lookback delta", func(c *fleet.Cluster) { c.Prometheus.LookbackDelta = "1m" }},
		{"prom external labels", func(c *fleet.Cluster) { c.Prometheus.ExternalLabels["cluster"] = "other" }},
		{"prom active series", func(c *fleet.Cluster) { c.Prometheus.ActiveSeries = 1 }},
		{"prom metric names", func(c *fleet.Cluster) { c.Prometheus.MetricNames = 1 }},
		{"prom jobs", func(c *fleet.Cluster) { c.Prometheus.Jobs = append(c.Prometheus.Jobs, "extra") }},
		{"prom namespaces", func(c *fleet.Cluster) { c.Prometheus.Namespaces = append(c.Prometheus.Namespaces, "extra") }},
		{"prom metric prefixes", func(c *fleet.Cluster) { c.Prometheus.MetricPrefixes = append(c.Prometheus.MetricPrefixes, "extra") }},
		{"prom rule groups", func(c *fleet.Cluster) { c.Prometheus.RuleGroups = 9 }},
		{"prom alerting rules", func(c *fleet.Cluster) { c.Prometheus.AlertingRules = 9 }},
		{"prom firing alerts", func(c *fleet.Cluster) { c.Prometheus.FiringAlerts = 9 }},
		{"prom has alertmanager", func(c *fleet.Cluster) { c.Prometheus.HasAlertmanager = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := sampleCluster()
			tc.mutate(&c)
			if got := clusterfacts.Fingerprint(c); got == want {
				t.Fatalf("changing %s did not change the fingerprint", tc.name)
			}
		})
	}
}

func TestFingerprintDoesNotMutateItsArgument(t *testing.T) {
	t.Parallel()
	c := sampleCluster()
	c.Prometheus.Jobs = []string{"zulu", "alpha"}
	clusterfacts.Fingerprint(c)
	if c.Prometheus.Jobs[0] != "zulu" {
		t.Fatalf("Fingerprint sorted the caller's slice in place: %v", c.Prometheus.Jobs)
	}
}

func TestFingerprintOfZeroCluster(t *testing.T) {
	t.Parallel()
	// The zero value must hash rather than panic: New publishes a placeholder
	// snapshot before any collection has happened.
	if fp := clusterfacts.Fingerprint(fleet.Cluster{}); len(fp) != 64 {
		t.Fatalf("Fingerprint(zero) = %q", fp)
	}
}
