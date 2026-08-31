// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"log/slog"
	"strings"
	"time"
)

// Spoke defaults.
const (
	// DefaultSpokeAdminAddr exposes metrics and health inside the cluster, so
	// unlike the hub's admin listener it is not loopback-only.
	DefaultSpokeAdminAddr = ":9090"
	// DefaultPrometheusURL is the in-cluster service the Prometheus Operator
	// creates.
	DefaultPrometheusURL = "http://prometheus-operated.monitoring.svc:9090"
	// DefaultIdentitySecretName is the Secret the spoke writes its issued key
	// and certificate to, so a restart does not need a fresh enrollment token.
	DefaultIdentitySecretName = "prometheus-mcp-fleet-identity"
	// IdentityBackendSecret persists the spoke identity in a Kubernetes Secret.
	// It requires get/create/update on exactly that one Secret by name.
	IdentityBackendSecret = "secret"
	// IdentityBackendFile persists it on local disk, for development.
	IdentityBackendFile = "file"
	// IdentityBackendMemory keeps the key only in memory. It needs no RBAC at
	// all, at the cost of re-enrolling on every restart, which in turn needs a
	// multi-use enrollment token.
	IdentityBackendMemory = "memory"
	// IdentityBackendAuto selects secret in a cluster and file otherwise.
	IdentityBackendAuto = "auto"
)

// Spoke is the fully resolved configuration of the spoke binary. Every field
// maps to one --flag and one PMF_ variable; see [EnvKey].
type Spoke struct {
	// HubEndpoints are the hub tunnel endpoints to dial, comma separated, as
	// URLs such as wss://hub.example.com/tunnel. A bare host:port from before
	// ADR-0014 is still accepted and read as wss://<host:port>/tunnel. The
	// spoke holds one tunnel per endpoint, which is how hub HA works: there is
	// no hub-to-hub forwarding.
	HubEndpoints []string
	// HubAPIURL is the https base URL of the hub's enrollment listener.
	HubAPIURL string
	// HubCAFile is the trust bundle used to verify the hub's server
	// certificate, which behind an Ingress is the Ingress's certificate. When
	// empty the bundle returned by enrollment and cached in DataDir is used.
	HubCAFile string
	// HubTLSInsecure disables verification of the hub's server certificate.
	// It exists only for bootstrapping a lab and is refused by Validate
	// unless AllowInsecure is also set, because it turns the tunnel's mutual
	// authentication into one-way authentication.
	HubTLSInsecure bool
	// AllowInsecure (PMF_ALLOW_INSECURE=1) is the second key that must be
	// turned for any insecure option to take effect. Requiring two independent
	// settings makes an insecure spoke impossible to reach by a single typo.
	AllowInsecure bool
	// EnrollmentTokenFile holds the single-use pmf_enr_ token.
	EnrollmentTokenFile string

	// ClusterID is the immutable cluster identity. It must match
	// ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ and is the value the hub binds into
	// the spoke's client certificate URI SAN.
	ClusterID string
	// ClusterDisplayName is the human-facing name shown to an agent.
	ClusterDisplayName string
	// ClusterDescription orients an agent choosing between clusters.
	ClusterDescription string
	// ClusterSDLC is the cluster's lifecycle stage: dev, staging, prod or
	// whatever taxonomy this fleet uses. It is REQUIRED.
	//
	// It is a field of its own rather than one more entry in ClusterLabels
	// because it is the selector everything else is built on. Agent key scopes
	// choose clusters by label and fanout_query takes a label selector, so a
	// cluster that reached production without a lifecycle label is a cluster no
	// scoped credential can reach and no fleet-wide query will target -- and
	// nothing would have told the operator. Requiring it makes that failure
	// impossible at install rather than mysterious at query time.
	//
	// The value is a free-form slug by deliberate choice: no fixed taxonomy
	// survives contact with every organisation. The cost is that prod and
	// production can coexist across a fleet, and nothing here prevents it.
	ClusterSDLC string
	// ClusterLabels are operator-supplied selectors, parsed from "k=v,k=v".
	// ClusterSDLC is merged in as "sdlc" and wins over any entry of that name,
	// so selectors need no special case for it.
	ClusterLabels map[string]string

	// DataDir holds the client key, the issued certificate and the cached hub
	// trust bundle.
	DataDir string
	// IdentityBackend selects where the issued client key and certificate are
	// persisted: "secret", "file", "memory" or "auto".
	IdentityBackend string
	// IdentitySecretName is the Secret used when IdentityBackend resolves to
	// "secret".
	IdentitySecretName string
	// Namespace overrides the namespace of the identity Secret. Empty uses the
	// namespace projected into the pod.
	Namespace string

	// PrometheusURL is the local Prometheus-compatible server.
	PrometheusURL string
	// PrometheusTimeout bounds one upstream request. It is deliberately below
	// the hub's query timeout so the spoke fails first and returns a useful
	// error instead of the hub timing out blind.
	PrometheusTimeout time.Duration
	// PrometheusBearerTokenFile authenticates to Prometheus when it is behind
	// an authenticating proxy.
	PrometheusBearerTokenFile string
	// PrometheusTLSCAFile is the trust bundle for an https Prometheus.
	PrometheusTLSCAFile string
	// PrometheusTLSSkipVerify disables verification of the Prometheus server
	// certificate. Validate refuses it unless AllowInsecure is also set.
	PrometheusTLSSkipVerify bool
	// PrometheusMaxResponseBytes caps one upstream response body.
	PrometheusMaxResponseBytes int64

	// FactsRefreshInterval is how often the spoke recollects cluster facts.
	FactsRefreshInterval time.Duration
	// ReconnectMinBackoff is the initial tunnel reconnect delay.
	ReconnectMinBackoff time.Duration
	// ReconnectMaxBackoff caps the tunnel reconnect delay.
	ReconnectMaxBackoff time.Duration

	// AdminAddr carries /metrics, /healthz and /readyz.
	AdminAddr string
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// LogFormat is json or text.
	LogFormat string
	// PprofEnabled exposes /debug/pprof on the admin listener.
	PprofEnabled bool
	// OTLPEndpoint enables OTLP/gRPC trace export. Empty disables tracing.
	OTLPEndpoint string
	// TraceSampleRatio is the head sampling ratio in [0,1].
	TraceSampleRatio float64
	// ShutdownDrainDelay is how long /readyz reports 503 before tunnels close.
	ShutdownDrainDelay time.Duration
	// ShutdownGrace bounds draining in-flight Prometheus requests.
	ShutdownGrace time.Duration
}

// LoadSpoke parses the spoke configuration from args (which must not include
// the program name) and getenv. A nil getenv uses the process environment.
//
// It returns a *HelpError matching [ErrHelp] when -h or --help was passed,
// [ErrUsage] for an unknown flag or a stray argument, and [ErrEnv] for a
// variable that cannot be parsed. The result is not validated; call
// [Spoke.Validate].
func LoadSpoke(args []string, getenv func(string) string) (*Spoke, error) {
	l := newLoader("spoke", getenv)
	c := &Spoke{}

	l.list(&c.HubEndpoints, "hub-endpoints", nil, "comma-separated hub tunnel URLs, e.g. wss://hub.example.com/tunnel")
	l.str(&c.HubAPIURL, "hub-api-url", "", "https base URL of the hub's enrollment listener")
	l.str(&c.HubCAFile, "hub-ca-file", "", "trust bundle for the hub; empty uses the bundle cached in <data-dir>")
	l.boolean(&c.HubTLSInsecure, "hub-tls-insecure", false, "skip verification of the hub certificate; requires --allow-insecure")
	l.boolean(&c.AllowInsecure, "allow-insecure", false, "permit the insecure options; never set this in production")
	l.str(&c.EnrollmentTokenFile, "enrollment-token-file", "", "file holding the single-use enrollment token")

	l.str(&c.ClusterID, "cluster-id", "", "immutable cluster identity (required)")
	l.str(&c.ClusterSDLC, "cluster-sdlc", "", "lifecycle stage such as dev, staging or prod (required)")
	l.str(&c.ClusterDisplayName, "cluster-display-name", "", "human-facing cluster name")
	l.str(&c.ClusterDescription, "cluster-description", "", "one line describing what this cluster runs")
	l.labels(&c.ClusterLabels, "cluster-labels", "operator-supplied selectors as k=v,k=v")

	l.str(&c.IdentityBackend, "identity-backend", IdentityBackendAuto, "where the client key and certificate live: secret, file, memory or auto")
	l.str(&c.IdentitySecretName, "identity-secret-name", DefaultIdentitySecretName, "Secret holding the spoke identity")
	l.str(&c.Namespace, "namespace", "", "namespace of the identity Secret; empty uses the projected namespace")
	l.str(&c.DataDir, "data-dir", DefaultDataDir, "directory holding the client key, certificate and hub trust bundle")

	l.str(&c.PrometheusURL, "prometheus-url", DefaultPrometheusURL, "URL of the local Prometheus-compatible server")
	l.duration(&c.PrometheusTimeout, "prometheus-timeout", 25*time.Second, "timeout for one upstream Prometheus request")
	l.str(&c.PrometheusBearerTokenFile, "prometheus-bearer-token-file", "", "file holding a bearer token for Prometheus")
	l.str(&c.PrometheusTLSCAFile, "prometheus-tls-ca-file", "", "trust bundle for an https Prometheus")
	l.boolean(&c.PrometheusTLSSkipVerify, "prometheus-tls-skip-verify", false, "skip verification of the Prometheus certificate; requires --allow-insecure")
	l.bytesize(&c.PrometheusMaxResponseBytes, "prometheus-max-response-bytes", 33554432, "maximum bytes accepted from one Prometheus response")

	l.duration(&c.FactsRefreshInterval, "facts-refresh-interval", 10*time.Minute, "how often cluster facts are recollected")
	l.duration(&c.ReconnectMinBackoff, "reconnect-min-backoff", 500*time.Millisecond, "initial tunnel reconnect delay")
	l.duration(&c.ReconnectMaxBackoff, "reconnect-max-backoff", 30*time.Second, "maximum tunnel reconnect delay")

	l.str(&c.AdminAddr, "admin-addr", DefaultSpokeAdminAddr, "listen address of metrics, health and pprof")
	l.str(&c.LogLevel, "log-level", DefaultLogLevel, "log level: debug, info, warn or error")
	l.str(&c.LogFormat, "log-format", DefaultLogFormat, "log format: json or text")
	l.boolean(&c.PprofEnabled, "pprof-enabled", false, "expose /debug/pprof on the admin listener")
	l.str(&c.OTLPEndpoint, "otel-exporter-otlp-endpoint", otelEndpointDefault(l), "OTLP/gRPC endpoint for traces; empty disables tracing")
	l.ratio(&c.TraceSampleRatio, "trace-sample-ratio", DefaultTraceSampleRatio, "head trace sampling ratio between 0 and 1")
	l.duration(&c.ShutdownDrainDelay, "shutdown-drain-delay", 5*time.Second, "time /readyz reports 503 before tunnels close")
	l.duration(&c.ShutdownGrace, "shutdown-grace", 30*time.Second, "graceful shutdown budget")

	if err := l.parse(args); err != nil {
		return nil, err
	}
	// Normalise before validating, so that "PROD", " Prod " and "Pre Prod" are
	// accepted and become "prod" and "pre-prod" rather than being refused for
	// their spelling. The value is a label an agent key scope selects on, so
	// what matters is that a hundred clusters agree on one form -- refusing an
	// operator's capitalisation achieves that by making them retype it, which
	// is worse than just fixing it here.
	c.ClusterSDLC = NormaliseSDLC(c.ClusterSDLC)
	return c, nil
}

// NormaliseSDLC canonicalises a lifecycle stage: trimmed, lowercased, with
// runs of whitespace and underscores folded to a single hyphen.
//
// It deliberately does not reject anything -- Validate does that against the
// normalised value, so an operator is told their input is unusable only when it
// still is after the obvious repairs.
func NormaliseSDLC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	b.Grow(len(s))
	lastHyphen := false
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t' || r == '_' || r == '-':
			// Collapse separators rather than emitting "pre--prod", and never
			// start with one.
			if b.Len() > 0 && !lastHyphen {
				b.WriteByte('-')
				lastHyphen = true
			}
		default:
			b.WriteRune(r)
			lastHyphen = false
		}
	}
	// A trailing separator would fail the slug pattern for a value the operator
	// clearly meant, so drop it.
	return strings.TrimSuffix(b.String(), "-")
}

// identityBackends is the closed set accepted by --identity-backend.
var identityBackends = []string{
	IdentityBackendSecret, IdentityBackendFile,
	IdentityBackendMemory, IdentityBackendAuto,
}

// Validate reports every problem with the configuration at once, joined with
// errors.Join. Each problem wraps [ErrInvalid] and names the flag and the
// environment variable it came from.
func (c *Spoke) Validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(c.HubEndpoints) == 0 {
		add(problem("hub-endpoints", "is required (comma-separated URLs, e.g. wss://hub.example.com/tunnel)"))
	}
	seen := make(map[string]struct{}, len(c.HubEndpoints))
	for _, e := range c.HubEndpoints {
		add(checkHubEndpoint("hub-endpoints", e))
		if _, dup := seen[e]; dup {
			add(problem("hub-endpoints", "%q appears twice", e))
		}
		seen[e] = struct{}{}
	}

	if c.HubAPIURL == "" {
		add(problem("hub-api-url", "is required for enrollment"))
	} else {
		add(checkURL("hub-api-url", c.HubAPIURL))
	}

	if c.HubTLSInsecure && !c.AllowInsecure {
		add(problem("hub-tls-insecure",
			"disables verification of the hub certificate, which lets anything on the "+
				"network impersonate the hub and collect this cluster's metrics; set %s=1 as well "+
				"to acknowledge that", EnvKey("allow-insecure")))
	}
	if c.PrometheusTLSSkipVerify && !c.AllowInsecure {
		add(problem("prometheus-tls-skip-verify",
			"disables verification of the Prometheus certificate; set %s=1 as well to acknowledge that",
			EnvKey("allow-insecure")))
	}

	switch {
	case c.ClusterID == "":
		add(problem("cluster-id", "is required"))
	case !clusterIDRE.MatchString(c.ClusterID):
		add(problem("cluster-id", "%q must match %s", c.ClusterID, clusterIDRE))
	}
	switch {
	case c.ClusterSDLC == "":
		add(problem("cluster-sdlc", "is required (for example dev, staging or prod)"))
	case !clusterSDLCRE.MatchString(c.ClusterSDLC):
		add(problem("cluster-sdlc", "%q must match %s", c.ClusterSDLC, clusterSDLCRE))
	}
	if err := validateClusterLabels(c.ClusterLabels); err != nil {
		add(problem("cluster-labels", "%s", err))
	}
	if i := indexControl(c.ClusterDisplayName); i >= 0 {
		add(problem("cluster-display-name", "has a control character at byte %d", i))
	}
	if i := indexControl(c.ClusterDescription); i >= 0 {
		add(problem("cluster-description", "has a control character at byte %d", i))
	}

	if c.DataDir == "" {
		add(problem("data-dir", "is required"))
	}

	if c.PrometheusURL == "" {
		add(problem("prometheus-url", "is required"))
	} else {
		add(checkURL("prometheus-url", c.PrometheusURL))
	}
	add(checkPositive("prometheus-timeout", c.PrometheusTimeout))
	add(checkPositiveBytes("prometheus-max-response-bytes", c.PrometheusMaxResponseBytes))

	add(checkPositive("facts-refresh-interval", c.FactsRefreshInterval))
	add(checkPositive("reconnect-min-backoff", c.ReconnectMinBackoff))
	add(checkPositive("reconnect-max-backoff", c.ReconnectMaxBackoff))
	if c.ReconnectMinBackoff > 0 && c.ReconnectMaxBackoff > 0 && c.ReconnectMaxBackoff < c.ReconnectMinBackoff {
		add(problem("reconnect-max-backoff", "%s is below --reconnect-min-backoff (%s)",
			c.ReconnectMaxBackoff, c.ReconnectMinBackoff))
	}

	add(checkAddr("admin-addr", c.AdminAddr))
	add(checkEnum("identity-backend", c.IdentityBackend, identityBackends))
	if c.IdentityBackend == IdentityBackendSecret && c.IdentitySecretName == "" {
		add(problem("identity-secret-name", "is required when --identity-backend=secret"))
	}
	add(checkEnum("log-level", c.LogLevel, logLevels))
	add(checkEnum("log-format", c.LogFormat, logFormats))
	add(checkRatio("trace-sample-ratio", c.TraceSampleRatio))
	add(checkNonNegative("shutdown-drain-delay", c.ShutdownDrainDelay))
	add(checkPositive("shutdown-grace", c.ShutdownGrace))

	return errors.Join(errs...)
}

// indexControl returns the byte offset of the first control character in s, or
// -1. Cluster names reach an agent's context, so they are screened here as
// well as at the hub.
func indexControl(s string) int {
	for i, r := range s {
		if isControl(r) {
			return i
		}
	}
	return -1
}

// LogValue implements slog.LogValuer. URL userinfo is stripped; every other
// value is a path, an address or a bound and is safe to record.
func (c *Spoke) LogValue() slog.Value {
	if c == nil {
		return slog.StringValue("<nil>")
	}
	return slog.GroupValue(
		slog.Any("hub_endpoints", c.HubEndpoints),
		slog.String("hub_api_url", redactURL(c.HubAPIURL)),
		slog.String("hub_ca_file", c.HubCAFile),
		slog.Bool("hub_tls_insecure", c.HubTLSInsecure),
		slog.Bool("allow_insecure", c.AllowInsecure),
		slog.String("enrollment_token_file", c.EnrollmentTokenFile),
		slog.String("cluster_id", c.ClusterID),
		slog.String("cluster_display_name", c.ClusterDisplayName),
		slog.String("cluster_description", c.ClusterDescription),
		slog.String("cluster_labels", FormatClusterLabels(c.ClusterLabels)),
		slog.String("data_dir", c.DataDir),
		slog.String("prometheus_url", redactURL(c.PrometheusURL)),
		slog.Duration("prometheus_timeout", c.PrometheusTimeout),
		slog.String("prometheus_bearer_token_file", c.PrometheusBearerTokenFile),
		slog.String("prometheus_tls_ca_file", c.PrometheusTLSCAFile),
		slog.Bool("prometheus_tls_skip_verify", c.PrometheusTLSSkipVerify),
		slog.Int64("prometheus_max_response_bytes", c.PrometheusMaxResponseBytes),
		slog.Duration("facts_refresh_interval", c.FactsRefreshInterval),
		slog.Duration("reconnect_min_backoff", c.ReconnectMinBackoff),
		slog.Duration("reconnect_max_backoff", c.ReconnectMaxBackoff),
		slog.String("admin_addr", c.AdminAddr),
		slog.String("log_level", c.LogLevel),
		slog.String("log_format", c.LogFormat),
		slog.Bool("pprof_enabled", c.PprofEnabled),
		slog.String("otlp_endpoint", redactURL(c.OTLPEndpoint)),
		slog.Float64("trace_sample_ratio", c.TraceSampleRatio),
		slog.Duration("shutdown_drain_delay", c.ShutdownDrainDelay),
		slog.Duration("shutdown_grace", c.ShutdownGrace),
	)
}
