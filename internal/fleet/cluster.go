// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package fleet

import "time"

// ClusterState is the hub's view of a spoke's availability.
type ClusterState string

const (
	// StateConnected means a live tunnel is attached and queries will be served.
	StateConnected ClusterState = "connected"
	// StateDisconnected means the cluster is enrolled but has no live tunnel.
	StateDisconnected ClusterState = "disconnected"
	// StateDegraded means the tunnel is up but the spoke reports its local
	// Prometheus as unreachable.
	StateDegraded ClusterState = "degraded"
)

// Cluster is the hub's registry entry for one spoke. It is the unit an AI
// agent selects when routing a query, so every field here is chosen to help an
// agent pick the right cluster without issuing a query first.
type Cluster struct {
	// ID is the authoritative identity, taken from the spoke's client
	// certificate and never from anything the spoke reports at runtime.
	ID string `json:"id"`
	// DisplayName is the human-facing name, e.g. "prod-us-east-1".
	DisplayName string `json:"displayName,omitempty"`
	// Description orients an agent, e.g. "customer-facing API tier".
	Description string `json:"description,omitempty"`
	// Labels are operator-supplied selectors such as {env: prod}.
	Labels map[string]string `json:"labels,omitempty"`

	State ClusterState `json:"state"`
	// LastSeen is when the hub last had contact with the spoke.
	LastSeen time.Time `json:"lastSeen,omitempty"`
	// ConnectedSince is when the current tunnel was attached.
	ConnectedSince time.Time `json:"connectedSince,omitempty"`
	// AgentVersion and ProtocolVersion come from the spoke's Describe reply.
	AgentVersion    string `json:"agentVersion,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	// CertNotAfter is the expiry of the spoke's current client certificate.
	CertNotAfter time.Time `json:"certNotAfter,omitempty"`

	Kubernetes KubernetesInfo `json:"kubernetes,omitzero"`
	Prometheus PrometheusInfo `json:"prometheus,omitzero"`
}

// KubernetesInfo is the optional Kubernetes context a spoke reports. The spoke
// ships with no RBAC by default, so Available is false unless an operator opts
// in.
type KubernetesInfo struct {
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailableReason,omitempty"`
	Version           string `json:"version,omitempty"`
	ClusterUID        string `json:"clusterUid,omitempty"`
	NodeCount         int32  `json:"nodeCount,omitempty"`
}

// PrometheusInfo describes the Prometheus-compatible server behind a spoke.
// The lists are capped samples, not exhaustive inventories: they exist so an
// agent can narrow 100 clusters to one or two before spending a query.
type PrometheusInfo struct {
	Reachable         bool              `json:"reachable"`
	UnreachableReason string            `json:"unreachableReason,omitempty"`
	Flavor            string            `json:"flavor,omitempty"`
	Version           string            `json:"version,omitempty"`
	Retention         string            `json:"retention,omitempty"`
	ScrapeInterval    string            `json:"scrapeInterval,omitempty"`
	LookbackDelta     string            `json:"lookbackDelta,omitempty"`
	ExternalLabels    map[string]string `json:"externalLabels,omitempty"`
	// ActiveSeries and MetricNames are -1 when the spoke could not collect them.
	ActiveSeries int64 `json:"activeSeries,omitempty"`
	MetricNames  int64 `json:"metricNames,omitempty"`

	Jobs            []string `json:"jobs,omitempty"`
	Namespaces      []string `json:"namespaces,omitempty"`
	MetricPrefixes  []string `json:"metricPrefixes,omitempty"`
	RuleGroups      int32    `json:"ruleGroups,omitempty"`
	AlertingRules   int32    `json:"alertingRules,omitempty"`
	FiringAlerts    int32    `json:"firingAlerts,omitempty"`
	HasAlertmanager bool     `json:"hasAlertmanager,omitempty"`
}

// Healthy reports whether the cluster can currently serve queries.
func (c *Cluster) Healthy() bool { return c.State == StateConnected }
