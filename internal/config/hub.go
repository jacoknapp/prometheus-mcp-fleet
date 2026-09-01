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

	// DefaultCARotateAtRemainingFraction is the point in the signing root's
	// life at which the hub starts rotating it: the last fifth.
	//
	// A root lives ten years by default and a rotation takes about a month
	// (see Hub.CARotationPollInterval), so the last fifth is two years of
	// runway for a job that needs one thirtieth of it. That asymmetry is the
	// point. The cost of starting early is a second trusted root for a month
	// every eight years; the cost of starting late is a fleet-wide outage on a
	// deadline nobody can move. There is also a floor underneath this
	// fraction that no configuration can lower -- see
	// [Hub.CARotationRunway] -- so setting it small does not let the hub
	// begin a rotation it cannot finish.
	DefaultCARotateAtRemainingFraction = 0.2
	// DefaultCARotationPollInterval is how often each replica re-reads the CA
	// Secret to notice a rotation, its own or another replica's.
	DefaultCARotationPollInterval = 5 * time.Minute
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
	// CATrustBundleFile holds ADDITIONAL root certificates the hub will accept
	// on a spoke's chain, beyond the one it signs with. Empty is the steady
	// state and trusts only the signer.
	//
	// It exists so a CA can be rotated without re-enrolling a hundred clusters.
	// During a rotation both roots are trusted at once: the outgoing root keeps
	// verifying certificates already in the field while the incoming one starts
	// issuing, and the old root is dropped only when nothing chains to it any
	// more. Additive on purpose -- the signer is always trusted and cannot be
	// configured out, because a hub that refuses the certificates it just
	// issued fails silently until the next reconnect.
	//
	// See docs/adr/0015-ca-rotation.md for the procedure.
	CATrustBundleFile string
	// CARotationEnabled lets the hub rotate its own signing root: mint a
	// successor, publish it to the trust bundle, promote it to signer, and
	// retire the outgoing root, each step gated on evidence rather than on a
	// human running a runbook.
	//
	// It requires the secret state backend. The phase, the time it was
	// entered and the successor's key material all live in the CA Secret,
	// whose resourceVersion is the compare-and-swap that stops two replicas
	// advancing the same step twice; the file backend has no such primitive
	// and is a single-process development mode, so rotation is simply off
	// there. See docs/adr/0015-ca-rotation.md.
	CARotationEnabled bool
	// CARotateAtRemainingFraction is the fraction of the signing root's total
	// life at which rotation begins. 0.2 starts it once four fifths of the
	// root's life is gone. Zero leaves only the runway floor below.
	CARotateAtRemainingFraction float64
	// CARotationPollInterval is how often each replica re-reads the CA Secret.
	//
	// It bounds two things: how long a replica can keep serving a trust
	// bundle a rotation has already widened, and how long one can keep
	// signing with a root a rotation has already retired. Both are safe for
	// far longer than this -- the retired root stays trusted for a full
	// certificate lifetime afterwards, which is what makes the lag harmless
	// -- so the interval is set by politeness to the API server, not by
	// correctness. One GET per replica per interval.
	CARotationPollInterval time.Duration
	// TrustDomain is the authority component of spoke certificate URI SANs.
	TrustDomain string
	// PeerDiscoveryDomain is a headless Service FQDN that resolves to one
	// address per running hub replica.
	//
	// It exists so multi-replica HA works behind ONE Ingress hostname. A tunnel
	// terminates on exactly one replica and there is deliberately no
	// hub-to-hub forwarding, so a spoke must hold a tunnel to every replica or
	// a share of tool calls find no session. The hub counts the addresses here
	// and tells each spoke how many replicas to expect; the spoke then dials
	// the same hostname until it has seen them all. Empty disables discovery,
	// and a spoke keeps one tunnel per configured endpoint.
	PeerDiscoveryDomain string

	// SpokeCertTTL is the lifetime of an issued spoke client certificate.
	SpokeCertTTL time.Duration
	// RenewGrace is how long after a spoke certificate expires the hub will
	// still renew it, given proof the spoke still holds the private key.
	//
	// A spoke renews at half its certificate's life, so an expired certificate
	// means the cluster was unreachable for half a lifetime. Without a grace
	// period that spoke is locked out for good: /renew refuses the expired
	// certificate and its enrollment token was single-use and burned at
	// install. Re-enrolling by hand is not a step that exists in a GitOps
	// rollout, so the default is generous. Zero disables the grace entirely and
	// restores strict expiry.
	RenewGrace time.Duration
	// EnrollmentTokenTTL bounds how long a single-use enrollment token lives.
	EnrollmentTokenTTL time.Duration
	// AgentKeyTTL is the default lifetime of a newly minted agent key, and
	// the ceiling a create request may ask for. Nothing rotates agent keys
	// automatically: the holder is an AI agent's configuration, not a process
	// that can re-enrol itself, so expiry here is an outage on a timer. The
	// default is deliberately long for that reason, and a key may be minted
	// with no expiry at all (see hubapi.CreateKeyRequest.NoExpiry).
	AgentKeyTTL time.Duration
	// AdminKeyTTL is the default and maximum lifetime of a minted admin key,
	// including the bootstrap key printed on first start. It is a separate
	// knob from AgentKeyTTL because the two credentials deserve opposite
	// pressure: an agent key's expiry is an outage on a timer, while an admin
	// key mints other credentials and must not quietly inherit whatever the
	// agent policy was relaxed to.
	AdminKeyTTL time.Duration
	// MaxSpokes optionally caps concurrent spoke sessions on this replica.
	// Zero, the default, means no limit.
	//
	// It is off by default because a cap here refuses spokes rather than
	// shedding load: the limit is enforced before the WebSocket upgrade, so an
	// over-limit spoke gets a 503 and its cluster silently never joins the
	// fleet, which is invisible to anyone looking at the hub wondering where a
	// cluster went. It also counts sessions, not clusters -- a cluster running
	// several spoke pods holds one per pod -- so any number chosen for a
	// cluster count is wrong by that multiple. Set it only as a deliberate
	// resource guard, knowing what it does when reached.
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
	l.str(&c.CATrustBundleFile, "ca-trust-bundle-file", "",
		"additional root certificates to trust alongside the signer, for CA rotation; empty trusts only the signer")
	l.boolean(&c.CARotationEnabled, "ca-rotation-enabled", true,
		"let the hub rotate its own signing root; requires --state-backend=secret")
	l.ratio(&c.CARotateAtRemainingFraction, "ca-rotate-at-remaining-fraction", DefaultCARotateAtRemainingFraction,
		"fraction of the signing root's life remaining at which rotation begins")
	l.duration(&c.CARotationPollInterval, "ca-rotation-poll-interval", DefaultCARotationPollInterval,
		"how often each replica re-reads the CA Secret to notice a rotation")
	l.str(&c.TrustDomain, "trust-domain", DefaultTrustDomain, "trust domain in spoke certificate URI SANs")
	l.str(&c.PeerDiscoveryDomain, "peer-discovery-domain", "",
		"headless Service FQDN resolving to one address per hub replica; enables multi-replica HA behind one hostname")

	l.duration(&c.SpokeCertTTL, "spoke-cert-ttl", 336*time.Hour, "lifetime of an issued spoke client certificate")
	l.duration(&c.EnrollmentTokenTTL, "enrollment-token-ttl", 15*time.Minute, "lifetime of a single-use enrollment token")
	l.duration(&c.RenewGrace, "renew-grace", 30*24*time.Hour,
		"how long after expiry a spoke certificate may still be renewed; 0 to require an unexpired certificate")
	l.duration(&c.AgentKeyTTL, "agent-key-ttl", 2160*time.Hour, "default and maximum lifetime of a minted agent key (90d)")
	l.duration(&c.AdminKeyTTL, "admin-key-ttl", 2160*time.Hour, "default and maximum lifetime of a minted admin key, including the bootstrap key (90d)")
	l.integer(&c.MaxSpokes, "max-spokes", 0, "optional cap on concurrent spoke sessions on this replica; 0 means no limit")

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
	add(checkNonNegative("renew-grace", c.RenewGrace))
	add(checkPositive("agent-key-ttl", c.AgentKeyTTL))
	add(checkPositive("admin-key-ttl", c.AdminKeyTTL))
	add(checkNonNegativeInt("max-spokes", c.MaxSpokes))

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
	add(checkRatio("ca-rotate-at-remaining-fraction", c.CARotateAtRemainingFraction))
	add(checkPositive("ca-rotation-poll-interval", c.CARotationPollInterval))

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
		slog.String("mcp_addr", c.MCPAddr),
		slog.String("tunnel_path", c.TunnelPath),
		slog.String("admin_addr", c.AdminAddr),
		slog.String("log_level", c.LogLevel),
		slog.String("log_format", c.LogFormat),
		slog.String("data_dir", c.DataDir),
		slog.String("pepper_file", c.PepperFile),
		slog.String("ca_cert_file", c.CACertFile),
		slog.String("ca_key_file", c.CAKeyFile),
		slog.String("trust_domain", c.TrustDomain),
		slog.Duration("spoke_cert_ttl", c.SpokeCertTTL),
		slog.Duration("enrollment_token_ttl", c.EnrollmentTokenTTL),
		slog.Duration("agent_key_ttl", c.AgentKeyTTL),
		slog.Duration("admin_key_ttl", c.AdminKeyTTL),
		slog.Int("max_spokes", c.MaxSpokes),
		slog.Duration("query_timeout", c.QueryTimeout),
		slog.Duration("range_query_timeout", c.RangeQueryTimeout),
		slog.Int64("max_response_bytes", c.MaxResponseBytes),
		slog.Int("max_inflight_per_cluster", c.MaxInflightPerCluster),
		slog.Int64("max_response_budget_bytes", c.MaxResponseBudgetBytes),
		slog.Duration("facts_poll_interval", c.FactsPollInterval),
		slog.Bool("ca_rotation_enabled", c.CARotationEnabled),
		slog.Float64("ca_rotate_at_remaining_fraction", c.CARotateAtRemainingFraction),
		slog.Duration("ca_rotation_poll_interval", c.CARotationPollInterval),
		slog.Duration("shutdown_drain_delay", c.ShutdownDrainDelay),
		slog.Duration("shutdown_grace", c.ShutdownGrace),
		slog.Bool("pprof_enabled", c.PprofEnabled),
		slog.Bool("enable_status_config", c.EnableStatusConfig),
		slog.String("otlp_endpoint", redactURL(c.OTLPEndpoint)),
		slog.Float64("trace_sample_ratio", c.TraceSampleRatio),
		slog.String("public_url", redactURL(c.PublicURL)),
	)
}

// CARotationRunway is the shortest life a signing root must have left for a
// rotation started now to finish before it expires.
//
// A rotation is two waits, each of which the hub cannot shorten. The first --
// the new root trusted, the old root still signing -- runs a full certificate
// lifetime, because that is how long it takes for every spoke to have renewed
// at least once onto the two-root bundle. The second -- the new root signing,
// the old root still trusted -- runs a certificate lifetime plus the renewal
// grace, because until then a spoke that has been switched off can still come
// back with a certificate the outgoing root issued and expect to renew it.
//
// The outgoing root must stay VALID for both, not merely present: an expired
// root verifies nothing, so the certificates chained to it would fail on the
// day it lapsed regardless of whether the trust bundle still named it. This
// is therefore a hard floor under
// [Hub.CARotateAtRemainingFraction] -- a fraction that computes to less than
// this is raised to it -- because starting a rotation that cannot finish is
// strictly worse than starting one early.
func (c *Hub) CARotationRunway() time.Duration {
	// The poll-interval terms mirror the retirement gate's padding (a losing
	// replica keeps signing with the old root until its next poll) plus one
	// interval of transition overshoot per phase boundary.
	return 2*c.SpokeCertTTL + c.RenewGrace + 4*c.CARotationPollInterval
}
