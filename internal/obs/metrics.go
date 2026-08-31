// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"net/http"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// Namespace prefixes every metric this project exports.
const Namespace = "promfleet"

// Subsystems, which are also the binary names accepted by [NewRegistry].
const (
	// SubsystemHub prefixes hub metrics.
	SubsystemHub = "hub"
	// SubsystemSpoke prefixes spoke metrics.
	SubsystemSpoke = "spoke"
)

// durationBuckets span a fast in-cluster query to a range query that is about
// to hit the hub's 120s ceiling.
var durationBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120}

// byteBuckets span 1 KiB to 256 MiB, covering the default 32 MiB per-response
// cap and the 256 MiB global budget.
var byteBuckets = prometheus.ExponentialBuckets(1024, 4, 10)

// binaryRE constrains the binary name that becomes a metric subsystem.
var binaryRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// HubMetrics is the hub's metric set. Every field corresponds to one metric in
// the build specification, and the label sets are exactly those it permits:
// cluster is bounded at roughly 100, endpoint, tool, code, result, reason and
// op are closed enums. Never pass PromQL text, matchers, label values, request
// IDs, key identifiers or spoke addresses as a label value.
//
// All fields are safe for concurrent use.
type HubMetrics struct {
	// SpokeConnected is 1 while a cluster has a live tunnel.
	SpokeConnected *prometheus.GaugeVec
	// SpokesConnected is the number of live tunnels.
	SpokesConnected prometheus.Gauge
	// SecurityEventsTotal counts credential mints, revocations, enrollment
	// burns and replay attempts by event kind. It is separate from
	// EnrollmentsTotal because these are audit-grade events an operator alerts
	// on, not request outcomes.
	SecurityEventsTotal *prometheus.CounterVec
	// StateBytes is the encoded size of the credential state document. A
	// Kubernetes Secret caps at 1 MiB and the store refuses writes well before
	// that, so this must be alertable long before it bites.
	StateBytes prometheus.Gauge
	// EnrollmentsTotal counts enrollment attempts by outcome.
	EnrollmentsTotal *prometheus.CounterVec
	// ProxyRequestsTotal counts proxied Prometheus calls.
	ProxyRequestsTotal *prometheus.CounterVec
	// ProxyDuration measures end-to-end proxied call latency.
	ProxyDuration *prometheus.HistogramVec
	// ProxyInflight is the number of proxied calls currently running.
	ProxyInflight *prometheus.GaugeVec
	// ProxyResponseBytes measures upstream response sizes.
	ProxyResponseBytes prometheus.Histogram
	// MCPToolCallsTotal counts MCP tool invocations by outcome.
	MCPToolCallsTotal *prometheus.CounterVec
	// MCPToolDuration measures MCP tool latency.
	MCPToolDuration *prometheus.HistogramVec
	// AuthnFailuresTotal counts rejected credentials by reason.
	AuthnFailuresTotal *prometheus.CounterVec
	// SpokeCertExpiry is seconds until each spoke certificate expires.
	SpokeCertExpiry *prometheus.GaugeVec
	// CACertExpiry is seconds until the internal CA certificate expires.
	CACertExpiry prometheus.Gauge
	// StoreOpDuration measures credential-store operations by op and outcome.
	StoreOpDuration *prometheus.HistogramVec
}

// NewHubMetrics registers the hub metric set on r and returns it. It panics if
// the same metrics are already registered on r, which can only happen if it is
// called twice with one registry.
func NewHubMetrics(r prometheus.Registerer) *HubMetrics {
	f := promauto.With(r)
	return &HubMetrics{
		SpokeConnected: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "spoke_connected",
			Help: "1 while the cluster has a live tunnel to this hub, 0 otherwise.",
		}, []string{"cluster"}),
		SpokesConnected: f.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "spokes_connected",
			Help: "Number of spokes with a live tunnel to this hub.",
		}),
		StateBytes: f.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "state_bytes",
			Help: "Encoded size of the credential state document in bytes.",
		}),
		EnrollmentsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "enrollments_total",
			Help: "Spoke enrollment attempts by result.",
		}, []string{"result"}),
		SecurityEventsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "security_events_total",
			Help: "Credential mints, revocations, enrollment burns and replay attempts by event kind.",
		}, []string{"event"}),
		ProxyRequestsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "proxy_requests_total",
			Help: "Prometheus API calls proxied to a spoke, by cluster, endpoint and status code.",
		}, []string{"cluster", "endpoint", "code"}),
		ProxyDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "proxy_duration_seconds",
			Help: "End-to-end latency of a proxied Prometheus API call.", Buckets: durationBuckets,
		}, []string{"cluster", "endpoint"}),
		ProxyInflight: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "proxy_inflight",
			Help: "Proxied Prometheus API calls currently in flight.",
		}, []string{"cluster"}),
		ProxyResponseBytes: f.NewHistogram(prometheus.HistogramOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "proxy_response_bytes",
			Help: "Size in bytes of upstream Prometheus responses.", Buckets: byteBuckets,
		}),
		MCPToolCallsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "mcp_tool_calls_total",
			Help: "MCP tool invocations by tool and result.",
		}, []string{"tool", "result"}),
		MCPToolDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "mcp_tool_duration_seconds",
			Help: "MCP tool invocation latency.", Buckets: durationBuckets,
		}, []string{"tool"}),
		AuthnFailuresTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "authn_failures_total",
			Help: "Rejected credentials by reason.",
		}, []string{"reason"}),
		SpokeCertExpiry: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "spoke_cert_expiry_seconds",
			Help: "Seconds until each spoke client certificate expires.",
		}, []string{"cluster"}),
		CACertExpiry: f.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "ca_cert_expiry_seconds",
			Help: "Seconds until the internal CA certificate expires.",
		}),
		StoreOpDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace, Subsystem: SubsystemHub, Name: "store_op_duration_seconds",
			Help: "Credential store operation latency by operation and result.", Buckets: durationBuckets,
		}, []string{"op", "result"}),
	}
}

// SpokeMetrics is the spoke's metric set. endpoint is the closed promapi
// endpoint enum for Prometheus calls and the configured hub endpoint for
// tunnel state; both are bounded.
//
// All fields are safe for concurrent use.
type SpokeMetrics struct {
	// HubReplicas is how many hub replicas the hub behind an endpoint says are
	// running, as learned on the last handshake. Zero means the hub does not
	// know, and the spoke then keeps a single tunnel to that endpoint.
	//
	// Cardinality: one series per configured hub endpoint, typically one.
	HubReplicas *prometheus.GaugeVec
	// TunnelsCovered is how many DISTINCT hub replicas behind an endpoint this
	// spoke currently holds a tunnel to.
	//
	// Alert on TunnelsCovered < HubReplicas. A tunnel terminates on exactly one
	// replica and the hub does not forward between replicas, so a spoke short
	// of full coverage has a proportional share of its tool calls answered
	// "cluster not connected" -- an intermittent failure that is painful to
	// diagnose after the fact and trivial to see here.
	//
	// Cardinality: one series per configured hub endpoint, typically one.
	TunnelsCovered *prometheus.GaugeVec
	// TunnelUp is 1 while the tunnel to a hub endpoint is established.
	TunnelUp *prometheus.GaugeVec
	// TunnelReconnectsTotal counts reconnects by reason.
	TunnelReconnectsTotal *prometheus.CounterVec
	// PromRequestsTotal counts local Prometheus calls.
	PromRequestsTotal *prometheus.CounterVec
	// PromDuration measures local Prometheus latency.
	PromDuration *prometheus.HistogramVec
	// PromUp is 1 while the local Prometheus answered its last probe.
	PromUp prometheus.Gauge
	// FactsRefreshTotal counts cluster-facts refreshes by result.
	FactsRefreshTotal *prometheus.CounterVec
	// ClientCertExpiry is seconds until this spoke's certificate expires.
	ClientCertExpiry prometheus.Gauge
	// InflightRequests is the number of Prometheus calls currently running.
	InflightRequests prometheus.Gauge
}

// NewSpokeMetrics registers the spoke metric set on r and returns it. It
// panics if the same metrics are already registered on r.
func NewSpokeMetrics(r prometheus.Registerer) *SpokeMetrics {
	f := promauto.With(r)
	return &SpokeMetrics{
		HubReplicas: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "hub_replicas",
			Help: "Hub replicas the hub behind this endpoint reports, or 0 if unknown.",
		}, []string{"endpoint"}),
		TunnelsCovered: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "tunnels_covered",
			Help: "Distinct hub replicas behind this endpoint that this spoke holds a tunnel to.",
		}, []string{"endpoint"}),
		TunnelUp: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "tunnel_up",
			Help: "1 while the tunnel to the hub endpoint is established, 0 otherwise.",
		}, []string{"endpoint"}),
		TunnelReconnectsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "tunnel_reconnects_total",
			Help: "Tunnel reconnect attempts by reason.",
		}, []string{"reason"}),
		PromRequestsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "prom_requests_total",
			Help: "Requests to the local Prometheus by endpoint and status code.",
		}, []string{"endpoint", "code"}),
		PromDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "prom_duration_seconds",
			Help: "Latency of requests to the local Prometheus.", Buckets: durationBuckets,
		}, []string{"endpoint"}),
		PromUp: f.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "prom_up",
			Help: "1 while the local Prometheus answered its most recent probe.",
		}),
		FactsRefreshTotal: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "facts_refresh_total",
			Help: "Cluster facts refreshes by result.",
		}, []string{"result"}),
		ClientCertExpiry: f.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "client_cert_expiry_seconds",
			Help: "Seconds until this spoke's client certificate expires.",
		}),
		InflightRequests: f.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace, Subsystem: SubsystemSpoke, Name: "inflight_requests",
			Help: "Prometheus requests currently in flight on this spoke.",
		}),
	}
}

// NewRegistry returns a registry holding the Go runtime collector, the process
// collector and a promfleet_<binary>_build_info gauge carrying the build
// stamps.
//
// binary names the subsystem and must match ^[a-z][a-z0-9_]*$; it is normally
// [SubsystemHub] or [SubsystemSpoke]. It panics on any other value, because an
// invalid metric name is a programming error that must not reach production.
func NewRegistry(b version.Build, binary string) *prometheus.Registry {
	if !binaryRE.MatchString(binary) {
		panic("obs: NewRegistry: binary name " + binary + " must match " + binaryRE.String())
	}
	r := prometheus.NewRegistry()
	r.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace, Subsystem: binary, Name: "build_info",
		Help: "Build stamps of the running binary, always 1.",
	}, []string{"version", "commit", "goversion"})
	buildInfo.WithLabelValues(b.Version, b.Commit, b.GoVersion).Set(1)
	r.MustRegister(buildInfo)
	return r
}

// MetricsHandler serves r in the Prometheus text and OpenMetrics formats. It
// does not compress: the admin listener is scraped from inside the cluster and
// compression would add CPU to every scrape for no useful saving.
func MetricsHandler(r *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(r, promhttp.HandlerOpts{
		ErrorHandling:     promhttp.HTTPErrorOnError,
		EnableOpenMetrics: true,
		Registry:          r,
	})
}
