// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// validateRequest rejects requests this transport will not put on the wire.
// The spoke re-validates the path against its own allow-list; this is only the
// structural check that keeps malformed requests off the socket.
func validateRequest(req *tunnel.Request) error {
	switch {
	case req == nil:
		return fmt.Errorf("%w: nil request", ErrInvalidRequest)
	case req.Method != http.MethodGet && req.Method != http.MethodPost:
		return fmt.Errorf("%w: method %q is not GET or POST", ErrInvalidRequest, req.Method)
	case !strings.HasPrefix(req.Path, "/"):
		return fmt.Errorf("%w: path %q is not absolute", ErrInvalidRequest, req.Path)
	case req.MaxResponseBytes <= 0:
		return fmt.Errorf("%w: MaxResponseBytes must be > 0, got %d", ErrInvalidRequest, req.MaxResponseBytes)
	default:
		return nil
	}
}

// requestToProto converts a tunnel request into its wire form.
func requestToProto(req *tunnel.Request) *fleetv1.ProxyRequest {
	return &fleetv1.ProxyRequest{
		Method:           req.Method,
		Path:             req.Path,
		Body:             req.Form,
		MaxResponseBytes: uint64(req.MaxResponseBytes), //nolint:gosec // G115: validateRequest rejects MaxResponseBytes <= 0 before any request is sent.
		AcceptGzip:       req.AcceptGzip,
		RequestId:        req.RequestID,
	}
}

// requestFromProto converts a wire request into its tunnel form. It is used on
// the spoke, which must treat every field as untrusted input.
func requestFromProto(in *fleetv1.ProxyRequest) (*tunnel.Request, error) {
	// Range-check before converting, not after: the wire field is a uint64 and
	// anything above 2^63 would wrap to a negative budget.
	if in.GetMaxResponseBytes() > 1<<62 {
		return nil, fmt.Errorf("%w: max_response_bytes %d overflows int64", ErrInvalidRequest, in.GetMaxResponseBytes())
	}
	req := &tunnel.Request{
		Method:           in.GetMethod(),
		Path:             in.GetPath(),
		Form:             in.GetBody(),
		AcceptGzip:       in.GetAcceptGzip(),
		RequestID:        in.GetRequestId(),
		MaxResponseBytes: int64(in.GetMaxResponseBytes()), //nolint:gosec // G115: bounded by the 1<<62 check immediately above.
	}
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	return req, nil
}

// factsToProto renders a Describe reply for the wire. generation overrides
// whatever the handler reported: the spoke's process start time is owned by the
// dialer, not by the facts collector.
func factsToProto(f tunnel.Facts, generation int64) *fleetv1.DescribeResponse {
	out := &fleetv1.DescribeResponse{
		Fingerprint: f.Fingerprint,
		Unchanged:   !f.Changed,
	}
	if !f.Changed {
		return out
	}
	c := f.Cluster
	out.Facts = &fleetv1.ClusterFacts{
		ClusterId:         c.ID,
		DisplayName:       c.DisplayName,
		Labels:            maps.Clone(c.Labels),
		Description:       c.Description,
		AgentVersion:      c.AgentVersion,
		ProtocolVersion:   c.ProtocolVersion,
		StartedAtUnixNano: generation,
		Kubernetes: &fleetv1.KubernetesFacts{
			Available:         c.Kubernetes.Available,
			UnavailableReason: c.Kubernetes.UnavailableReason,
			Version:           c.Kubernetes.Version,
			ClusterUid:        c.Kubernetes.ClusterUID,
			NodeCount:         c.Kubernetes.NodeCount,
		},
		Prometheus: &fleetv1.PrometheusFacts{
			Reachable:              c.Prometheus.Reachable,
			UnreachableReason:      c.Prometheus.UnreachableReason,
			Flavor:                 c.Prometheus.Flavor,
			Version:                c.Prometheus.Version,
			Retention:              c.Prometheus.Retention,
			ScrapeInterval:         c.Prometheus.ScrapeInterval,
			LookbackDelta:          c.Prometheus.LookbackDelta,
			ExternalLabels:         maps.Clone(c.Prometheus.ExternalLabels),
			ActiveSeries:           c.Prometheus.ActiveSeries,
			MetricNameCount:        c.Prometheus.MetricNames,
			Jobs:                   c.Prometheus.Jobs,
			Namespaces:             c.Prometheus.Namespaces,
			MetricPrefixes:         c.Prometheus.MetricPrefixes,
			RuleGroupCount:         c.Prometheus.RuleGroups,
			AlertingRuleCount:      c.Prometheus.AlertingRules,
			FiringAlertCount:       c.Prometheus.FiringAlerts,
			AlertmanagerConfigured: c.Prometheus.HasAlertmanager,
		},
	}
	return out
}

// factsFromProto converts a Describe reply into its tunnel form. The hub
// overwrites Cluster.ID with the certificate-derived identity afterwards; the
// value carried here is advisory, exactly as the proto says.
func factsFromProto(in *fleetv1.DescribeResponse) tunnel.Facts {
	f := tunnel.Facts{
		Fingerprint: in.GetFingerprint(),
		Changed:     !in.GetUnchanged(),
	}
	pf := in.GetFacts()
	if pf == nil {
		// An unchanged reply carries no payload, and therefore no generation.
		f.Changed = false
		return f
	}
	f.Generation = pf.GetStartedAtUnixNano()
	k := pf.GetKubernetes()
	p := pf.GetPrometheus()
	f.Cluster = fleet.Cluster{
		ID:              pf.GetClusterId(),
		DisplayName:     pf.GetDisplayName(),
		Description:     pf.GetDescription(),
		Labels:          maps.Clone(pf.GetLabels()),
		AgentVersion:    pf.GetAgentVersion(),
		ProtocolVersion: pf.GetProtocolVersion(),
		Kubernetes: fleet.KubernetesInfo{
			Available:         k.GetAvailable(),
			UnavailableReason: k.GetUnavailableReason(),
			Version:           k.GetVersion(),
			ClusterUID:        k.GetClusterUid(),
			NodeCount:         k.GetNodeCount(),
		},
		Prometheus: fleet.PrometheusInfo{
			Reachable:         p.GetReachable(),
			UnreachableReason: p.GetUnreachableReason(),
			Flavor:            p.GetFlavor(),
			Version:           p.GetVersion(),
			Retention:         p.GetRetention(),
			ScrapeInterval:    p.GetScrapeInterval(),
			LookbackDelta:     p.GetLookbackDelta(),
			ExternalLabels:    maps.Clone(p.GetExternalLabels()),
			ActiveSeries:      p.GetActiveSeries(),
			MetricNames:       p.GetMetricNameCount(),
			Jobs:              p.GetJobs(),
			Namespaces:        p.GetNamespaces(),
			MetricPrefixes:    p.GetMetricPrefixes(),
			RuleGroups:        p.GetRuleGroupCount(),
			AlertingRules:     p.GetAlertingRuleCount(),
			FiringAlerts:      p.GetFiringAlertCount(),
			HasAlertmanager:   p.GetAlertmanagerConfigured(),
		},
	}
	return f
}
