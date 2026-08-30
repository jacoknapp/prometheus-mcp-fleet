// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"log/slog"
	"net/url"
	"path/filepath"
	"regexp"
	"time"
)

// Hub defaults. They are exported so that operators reading generated
// documentation and tests asserting on drift both refer to one definition.
const (
	// DefaultMCPAddr is the listen address of the agent-facing MCP endpoint.
	DefaultMCPAddr = ":8080"
	// DefaultTunnelPath is the path on the MCP listener where spokes open the
	// tunnel WebSocket. It shares a listener with MCP so the whole product
	// needs exactly one Ingress rule; see ADR-0014.
	DefaultTunnelPath = "/tunnel"
	// DefaultHubAdminAddr is loopback-only: the admin listener carries key
	// administration, metrics, health and pprof.
	DefaultHubAdminAddr = "127.0.0.1:9090"
	// DefaultDataDir is scratch space for CA material and the pepper. It is an
	// emptyDir in the chart: nothing here is durable, because durable state
	// lives in a Kubernetes Secret (see ADR-0005).
	DefaultDataDir = "/var/lib/prometheus-mcp-fleet"
	// DefaultTrustDomain is the SPIFFE-style trust domain in spoke certificate
	// URI SANs (pmf://<trust-domain>/spoke/<cluster-id>).
	DefaultTrustDomain = "fleet.local"
	// DefaultLogLevel is the default slog level.
	DefaultLogLevel = "info"
	// DefaultLogFormat is the default slog handler.
	DefaultLogFormat = "json"
	// DefaultTraceSampleRatio samples 5% of traces.
	DefaultTraceSampleRatio = 0.05
	// DefaultStateSecretName is the Secret holding the credential records.
	DefaultStateSecretName = "prometheus-mcp-fleet-state"
	// DefaultCASecretName is the Secret holding the CA certificate and key. It
	// is deliberately separate from the state Secret so the two have different
	// blast radii and can carry different RBAC.
	DefaultCASecretName = "prometheus-mcp-fleet-ca"
	// StateFileName is the file the file backend writes inside DataDir.
	StateFileName = "state.json"
	// StateBackendSecret persists credential records in a Kubernetes Secret.
	StateBackendSecret = "secret"
	// StateBackendFile persists them in a local JSON file, for development and
	// for running outside Kubernetes.
	StateBackendFile = "file"
	// StateBackendAuto selects secret when a projected service account token is
	// present and file otherwise.
	StateBackendAuto = "auto"

	// PepperFileName is the file the hub self-generates inside DataDir when
	// --pepper-file was not supplied.
	PepperFileName = "pepper.key"
	// CACertFileName and CAKeyFileName are the files the hub self-initialises
	// inside DataDir when no CA is supplied.
	CACertFileName = "ca.crt"
	CAKeyFileName  = "ca.key"
)

// stateBackends is the closed set accepted by --state-backend.
var stateBackends = []string{StateBackendSecret, StateBackendFile, StateBackendAuto}

// trustDomainRE is the accepted trust-domain grammar: a lowercase DNS name. It
// ends up inside every spoke certificate's URI SAN, so it is validated rather
// than trusted.
var trustDomainRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// Hub is the fully resolved configuration of the hub binary. Every field maps
// to one --flag and one PMF_ variable; see [EnvKey].
type Hub struct {
	// MCPAddr is where the agent-facing MCP (Streamable HTTP) endpoint listens.
	MCPAddr string
	// TunnelPath is the path on MCPAddr where spokes open the tunnel
	// WebSocket. There is no separate tunnel listener: an Ingress terminates
	// TLS and cannot pass a client certificate through, so the tunnel arrives
	// as ordinary HTTP and authenticates inside the connection (ADR-0014).
	TunnelPath string
	// AdminAddr carries the admin REST API, /metrics, health and pprof. It
	// defaults to loopback because it is the credential-issuing surface.
	AdminAddr string

	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// LogFormat is json or text.
	LogFormat string

	// DataDir is scratch space for CA material and the pepper. It need not be
	// durable; see StateBackend.
	DataDir string
	// StateBackend selects where credential records are persisted: "secret",
	// "file", or "auto" to choose by whether the process is running in a
	// cluster. There is no database; see ADR-0005.
	StateBackend string
	// StateSecretName is the Secret holding the credential records when
	// StateBackend resolves to "secret".
	StateSecretName string
	// CASecretName is the Secret holding the CA certificate and key. The hub
	// materialises it into DataDir at startup and writes back the material it
	// generates on first boot.
	CASecretName string
	// StateFile is the JSON file used when StateBackend resolves to "file".
	// Empty resolves to DataDir/state.json.
	StateFile string
	// Namespace overrides the namespace the Secrets live in. Empty uses the
	// namespace projected into the pod.
	Namespace string
	// PepperFile is the out-of-database HMAC pepper. When left empty it
	// resolves to DataDir/pepper.key; the hub generates it on first start if
	// the path is absent and writable.
	PepperFile string
	// CACertFile and CAKeyFile are the internal CA. When both are empty the
	// hub self-initialises a CA inside DataDir.
	CACertFile string
	// CAKeyFile is the private key matching CACertFile.
	CAKeyFile string
	// TrustDomain is the authority component of spoke certificate URI SANs.
	TrustDomain string

	// SpokeCertTTL is the lifetime of an issued spoke client certificate.
	SpokeCertTTL time.Duration
	// EnrollmentTokenTTL bounds how long a single-use enrollment token lives.
	EnrollmentTokenTTL time.Duration
	// AgentKeyTTL is the default lifetime of a newly minted agent key.
	AgentKeyTTL time.Duration
	// MaxSpokes caps how many clusters may be enrolled.
	MaxSpokes int

	// QueryTimeout bounds an instant query and every non-range endpoint.
	QueryTimeout time.Duration
	// RangeQueryTimeout bounds a range query, which is legitimately slower.
	RangeQueryTimeout time.Duration
	// MaxResponseBytes caps one upstream response body.
	MaxResponseBytes int64
	// MaxInflightPerCluster is the per-cluster concurrency semaphore.
	MaxInflightPerCluster int
	// MaxResponseBudgetBytes is the process-wide in-flight response budget.
	MaxResponseBudgetBytes int64
	// FactsPollInterval is how often the hub refreshes cluster facts.
	FactsPollInterval time.Duration

	// ShutdownDrainDelay is how long /readyz reports 503 before the hub stops
	// accepting work, giving a load balancer time to notice.
	ShutdownDrainDelay time.Duration
	// ShutdownGrace bounds the graceful shutdown of the HTTP servers.
	ShutdownGrace time.Duration

	// PprofEnabled exposes /debug/pprof on the admin listener.
	PprofEnabled bool
	// EnableStatusConfig ungates the /api/v1/status/config Prometheus
	// endpoint. It is false by default because scrape configurations routinely
	// embed bearer tokens and basic-auth credentials in plain text. Not named
	// in the spec's key list but required by the gate in internal/promapi.
	EnableStatusConfig bool

	// OTLPEndpoint enables OTLP/gRPC trace export. Empty disables tracing
	// entirely, with no network activity. It falls back to the standard
	// OTEL_EXPORTER_OTLP_ENDPOINT variable when PMF_ prefixed one is unset.
	OTLPEndpoint string
	// TraceSampleRatio is the head sampling ratio in [0,1].
	TraceSampleRatio float64

	// PublicURL is the canonical external URL of the MCP endpoint, published
	// in the OAuth protected-resource metadata document.
	PublicURL string
}

// LoadHub parses the hub configuration from args (which must not include the
// program name) and getenv. A nil getenv uses the process environment.
//
// It returns a *HelpError matching [ErrHelp] when -h or --help was passed,
// [ErrUsage] for an unknown flag or a stray argument, and [ErrEnv] for a
// variable that cannot be parsed. The result is not validated; call
// [Hub.Validate].
func LoadHub(args []string, getenv func(string) string) (*Hub, error) {
	l := newLoader("hub", getenv)
	c := &Hub{}

	l.str(&c.MCPAddr, "mcp-addr", DefaultMCPAddr, "listen address of the agent-facing MCP endpoint")
	l.str(&c.TunnelPath, "tunnel-path", DefaultTunnelPath, "path on --mcp-addr where spokes open the tunnel websocket")
	l.str(&c.AdminAddr, "admin-addr", DefaultHubAdminAddr, "listen address of the admin API, metrics, health and pprof")

	l.str(&c.LogLevel, "log-level", DefaultLogLevel, "log level: debug, info, warn or error")
	l.str(&c.LogFormat, "log-format", DefaultLogFormat, "log format: json or text")

	l.str(&c.DataDir, "data-dir", DefaultDataDir, "scratch directory for CA material and the pepper; need not be durable")
	l.str(&c.StateBackend, "state-backend", StateBackendAuto, "where credential records live: secret, file or auto")
	l.str(&c.StateSecretName, "state-secret-name", DefaultStateSecretName, "Secret holding the credential records")
	l.str(&c.CASecretName, "ca-secret-name", DefaultCASecretName, "Secret holding the CA certificate and key")
	l.str(&c.StateFile, "state-file", "", "JSON state file for the file backend; defaults to <data-dir>/"+StateFileName)
	l.str(&c.Namespace, "namespace", "", "namespace of the state and CA Secrets; empty uses the projected namespace")
	l.str(&c.PepperFile, "pepper-file", "", "HMAC pepper file; defaults to <data-dir>/"+PepperFileName)
	l.str(&c.CACertFile, "ca-cert-file", "", "internal CA certificate; empty self-initialises in <data-dir>")
	l.str(&c.CAKeyFile, "ca-key-file", "", "internal CA private key; empty self-initialises in <data-dir>")
	l.str(&c.TrustDomain, "trust-domain", DefaultTrustDomain, "trust domain in spoke certificate URI SANs")

	l.duration(&c.SpokeCertTTL, "spoke-cert-ttl", 336*time.Hour, "lifetime of an issued spoke client certificate")
	l.duration(&c.EnrollmentTokenTTL, "enrollment-token-ttl", 15*time.Minute, "lifetime of a single-use enrollment token")
	l.duration(&c.AgentKeyTTL, "agent-key-ttl", 720*time.Hour, "default lifetime of a minted agent key")
	l.integer(&c.MaxSpokes, "max-spokes", 256, "maximum number of enrolled clusters")

	l.duration(&c.QueryTimeout, "query-timeout", 30*time.Second, "timeout for instant and metadata queries")
	l.duration(&c.RangeQueryTimeout, "range-query-timeout", 120*time.Second, "timeout for range queries")
	l.bytesize(&c.MaxResponseBytes, "max-response-bytes", 33554432, "maximum bytes accepted from one upstream response")
	l.integer(&c.MaxInflightPerCluster, "max-inflight-per-cluster", 8, "per-cluster in-flight request limit")
	l.bytesize(&c.MaxResponseBudgetBytes, "max-response-budget-bytes", 268435456, "process-wide in-flight response byte budget")
	l.duration(&c.FactsPollInterval, "facts-poll-interval", 60*time.Second, "how often cluster facts are refreshed")

	l.duration(&c.ShutdownDrainDelay, "shutdown-drain-delay", 5*time.Second, "time /readyz reports 503 before work stops")
	l.duration(&c.ShutdownGrace, "shutdown-grace", 30*time.Second, "graceful shutdown budget")

	l.boolean(&c.PprofEnabled, "pprof-enabled", false, "expose /debug/pprof on the admin listener")
	l.boolean(&c.EnableStatusConfig, "enable-status-config", false, "ungate /api/v1/status/config, which can expose scrape credentials")

	l.str(&c.OTLPEndpoint, "otel-exporter-otlp-endpoint", otelEndpointDefault(l), "OTLP/gRPC endpoint for traces; empty disables tracing")
	l.ratio(&c.TraceSampleRatio, "trace-sample-ratio", DefaultTraceSampleRatio, "head trace sampling ratio between 0 and 1")

	l.str(&c.PublicURL, "public-url", "", "canonical external URL of the MCP endpoint")

	if err := l.parse(args); err != nil {
		return nil, err
	}
	if c.PepperFile == "" && c.DataDir != "" {
		c.PepperFile = filepath.Join(c.DataDir, PepperFileName)
	}
	if c.StateFile == "" && c.DataDir != "" {
		c.StateFile = filepath.Join(c.DataDir, StateFileName)
	}
	// The CA paths resolve together or not at all: a half-configured pair is
	// caught by Validate's checkPair, and leaving them empty here would hand
	// an empty path to the loader.
	if c.CACertFile == "" && c.CAKeyFile == "" && c.DataDir != "" {
		c.CACertFile = filepath.Join(c.DataDir, CACertFileName)
		c.CAKeyFile = filepath.Join(c.DataDir, CAKeyFileName)
	}
	return c, nil
}

// otelEndpointDefault honours the vendor-neutral OTEL_EXPORTER_OTLP_ENDPOINT
// variable, which operators and sidecar injectors already set, while still
// letting the PMF_ prefixed form and the flag override it.
func otelEndpointDefault(l *loader) string { return l.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") }

// Validate reports every problem with the configuration at once, joined with
// errors.Join. Each problem wraps [ErrInvalid] and names the flag and the
// environment variable it came from.
func (c *Hub) Validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	add(checkAddr("mcp-addr", c.MCPAddr))
	add(checkPath("tunnel-path", c.TunnelPath))
	add(checkAddr("admin-addr", c.AdminAddr))

	add(checkEnum("log-level", c.LogLevel, logLevels))
	add(checkEnum("log-format", c.LogFormat, logFormats))

	if c.DataDir == "" {
		add(problem("data-dir", "is required"))
	}
	if c.PepperFile == "" {
		add(problem("pepper-file", "is required when --data-dir is empty"))
	}
	add(checkEnum("state-backend", c.StateBackend, stateBackends))
	if c.StateBackend != StateBackendFile && c.StateSecretName == "" {
		add(problem("state-secret-name", "is required unless --state-backend=file"))
	}
	if c.StateBackend == StateBackendFile && c.StateFile == "" {
		add(problem("state-file", "is required when --state-backend=file and --data-dir is empty"))
	}
	add(checkPair("ca-cert-file", c.CACertFile, "ca-key-file", c.CAKeyFile))
	if c.PublicURL == "" {
		add(problem("public-url",
			"is required: it is the canonical external URL agents reach, and it "+
				"is the mandatory \"resource\" field of the RFC 9728 metadata "+
				"document the 401 challenge points at"))
	} else if u, uerr := url.Parse(c.PublicURL); uerr != nil ||
		(u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		add(problem("public-url", "%q must be an absolute http or https URL", c.PublicURL))
	}
	if !trustDomainRE.MatchString(c.TrustDomain) {
		add(problem("trust-domain", "%q must match %s", c.TrustDomain, trustDomainRE))
	}

	add(checkPositive("spoke-cert-ttl", c.SpokeCertTTL))
	add(checkPositive("enrollment-token-ttl", c.EnrollmentTokenTTL))
	add(checkPositive("agent-key-ttl", c.AgentKeyTTL))
	add(checkPositiveInt("max-spokes", c.MaxSpokes))

	add(checkPositive("query-timeout", c.QueryTimeout))
	add(checkPositive("range-query-timeout", c.RangeQueryTimeout))
	add(checkPositiveBytes("max-response-bytes", c.MaxResponseBytes))
	add(checkPositiveInt("max-inflight-per-cluster", c.MaxInflightPerCluster))
	add(checkPositiveBytes("max-response-budget-bytes", c.MaxResponseBudgetBytes))
	if c.MaxResponseBudgetBytes > 0 && c.MaxResponseBytes > 0 && c.MaxResponseBudgetBytes < c.MaxResponseBytes {
		add(problem("max-response-budget-bytes",
			"%d is below --max-response-bytes (%d), so no single response could ever complete",
			c.MaxResponseBudgetBytes, c.MaxResponseBytes))
	}
	add(checkPositive("facts-poll-interval", c.FactsPollInterval))

	add(checkNonNegative("shutdown-drain-delay", c.ShutdownDrainDelay))
	add(checkPositive("shutdown-grace", c.ShutdownGrace))

	add(checkRatio("trace-sample-ratio", c.TraceSampleRatio))
	if c.PublicURL != "" {
		add(checkURL("public-url", c.PublicURL))
	}

	return errors.Join(errs...)
}

// LogValue implements slog.LogValuer. URL userinfo is stripped; every other
// value is a path, an address or a bound and is safe to record.
func (c *Hub) LogValue() slog.Value {
	if c == nil {
		return slog.StringValue("<nil>")
	}
	return slog.GroupValue(
		slog.String("mcpAddr", c.MCPAddr),
		slog.String("tunnelPath", c.TunnelPath),
		slog.String("adminAddr", c.AdminAddr),
		slog.String("logLevel", c.LogLevel),
		slog.String("logFormat", c.LogFormat),
		slog.String("dataDir", c.DataDir),
		slog.String("pepperFile", c.PepperFile),
		slog.String("caCertFile", c.CACertFile),
		slog.String("caKeyFile", c.CAKeyFile),
		slog.String("trustDomain", c.TrustDomain),
		slog.Duration("spokeCertTTL", c.SpokeCertTTL),
		slog.Duration("enrollmentTokenTTL", c.EnrollmentTokenTTL),
		slog.Duration("agentKeyTTL", c.AgentKeyTTL),
		slog.Int("maxSpokes", c.MaxSpokes),
		slog.Duration("queryTimeout", c.QueryTimeout),
		slog.Duration("rangeQueryTimeout", c.RangeQueryTimeout),
		slog.Int64("maxResponseBytes", c.MaxResponseBytes),
		slog.Int("maxInflightPerCluster", c.MaxInflightPerCluster),
		slog.Int64("maxResponseBudgetBytes", c.MaxResponseBudgetBytes),
		slog.Duration("factsPollInterval", c.FactsPollInterval),
		slog.Duration("shutdownDrainDelay", c.ShutdownDrainDelay),
		slog.Duration("shutdownGrace", c.ShutdownGrace),
		slog.Bool("pprofEnabled", c.PprofEnabled),
		slog.Bool("enableStatusConfig", c.EnableStatusConfig),
		slog.String("otlpEndpoint", redactURL(c.OTLPEndpoint)),
		slog.Float64("traceSampleRatio", c.TraceSampleRatio),
		slog.String("publicURL", redactURL(c.PublicURL)),
	)
}
