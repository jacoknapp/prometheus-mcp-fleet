// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validHub returns a hub configuration that Validate accepts.
func validHub(t *testing.T) *Hub {
	t.Helper()
	c, err := LoadHub(nil, env(map[string]string{
		"PMF_PUBLIC_URL": "https://pmf.example.com/mcp",
	}))
	if err != nil {
		t.Fatalf("LoadHub() error = %v", err)
	}
	return c
}

// validSpoke returns a spoke configuration that Validate accepts.
func validSpoke(t *testing.T) *Spoke {
	t.Helper()
	c, err := LoadSpoke(nil, env(map[string]string{
		"PMF_HUB_ENDPOINTS": "wss://hub.example.com/tunnel",
		"PMF_HUB_API_URL":   "https://hub.example.com",
		"PMF_CLUSTER_ID":    "prod-us-east-1",
		"PMF_CLUSTER_SDLC":  "prod",
	}))
	if err != nil {
		t.Fatalf("LoadSpoke() error = %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("baseline spoke must be valid, got %v", err)
	}
	return c
}

func TestHubValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*Hub)
		contains string
	}{
		{"mcp addr empty", func(c *Hub) { c.MCPAddr = "" }, "--mcp-addr"},
		{"mcp addr not host:port", func(c *Hub) { c.MCPAddr = "8080" }, "--mcp-addr"},
		{"mcp addr bad port", func(c *Hub) { c.MCPAddr = ":notaport" }, "invalid port"},
		{"mcp addr port out of range", func(c *Hub) { c.MCPAddr = ":70000" }, "invalid port"},
		{"tunnel path relative", func(c *Hub) { c.TunnelPath = "tunnel" }, "--tunnel-path"},
		{"tunnel path root", func(c *Hub) { c.TunnelPath = "/" }, "--tunnel-path"},
		{"tunnel path empty", func(c *Hub) { c.TunnelPath = "" }, "--tunnel-path"},
		{"tunnel path with a query", func(c *Hub) { c.TunnelPath = "/tunnel?x=1" }, "--tunnel-path"},
		{"tunnel path with a mux wildcard", func(c *Hub) { c.TunnelPath = "/tunnel/{id}" }, "--tunnel-path"},
		{"admin addr", func(c *Hub) { c.AdminAddr = "nope" }, "--admin-addr"},
		{"admin addr host with space", func(c *Hub) { c.AdminAddr = "bad host:9090" }, "--admin-addr"},
		{"log level", func(c *Hub) { c.LogLevel = "verbose" }, "--log-level"},
		{"log format", func(c *Hub) { c.LogFormat = "xml" }, "--log-format"},
		{"data dir", func(c *Hub) { c.DataDir = "" }, "--data-dir"},
		{"pepper file", func(c *Hub) { c.PepperFile = "" }, "--pepper-file"},
		{"state secret required", func(c *Hub) { c.StateBackend, c.StateSecretName = StateBackendSecret, "" }, "--state-secret-name"},
		{"state file required", func(c *Hub) { c.StateBackend, c.StateFile = StateBackendFile, "" }, "--state-file"},
		{"ca cert without key", func(c *Hub) { c.CACertFile, c.CAKeyFile = "/ca.pem", "" }, "--ca-key-file"},
		{"ca key without cert", func(c *Hub) { c.CACertFile, c.CAKeyFile = "", "/ca.key" }, "--ca-cert-file"},
		{"trust domain empty", func(c *Hub) { c.TrustDomain = "" }, "--trust-domain"},
		{"trust domain uppercase", func(c *Hub) { c.TrustDomain = "Fleet.Local" }, "--trust-domain"},
		{"spoke cert ttl", func(c *Hub) { c.SpokeCertTTL = 0 }, "--spoke-cert-ttl"},
		{"enrollment token ttl", func(c *Hub) { c.EnrollmentTokenTTL = -time.Second }, "--enrollment-token-ttl"},
		{"renew grace negative", func(c *Hub) { c.RenewGrace = -time.Second }, "--renew-grace"},
		{"agent key ttl", func(c *Hub) { c.AgentKeyTTL = 0 }, "--agent-key-ttl"},
		{"max spokes negative", func(c *Hub) { c.MaxSpokes = -1 }, "--max-spokes"},
		{"query timeout", func(c *Hub) { c.QueryTimeout = 0 }, "--query-timeout"},
		{"range query timeout", func(c *Hub) { c.RangeQueryTimeout = 0 }, "--range-query-timeout"},
		{"max response bytes", func(c *Hub) { c.MaxResponseBytes = 0 }, "--max-response-bytes"},
		{"max inflight", func(c *Hub) { c.MaxInflightPerCluster = -1 }, "--max-inflight-per-cluster"},
		{"budget bytes", func(c *Hub) { c.MaxResponseBudgetBytes = 0 }, "--max-response-budget-bytes"},
		{
			"budget below single response",
			func(c *Hub) { c.MaxResponseBudgetBytes = 1024 },
			"below --max-response-bytes",
		},
		{"facts poll interval", func(c *Hub) { c.FactsPollInterval = 0 }, "--facts-poll-interval"},
		{"drain delay negative", func(c *Hub) { c.ShutdownDrainDelay = -time.Second }, "--shutdown-drain-delay"},
		{"shutdown grace", func(c *Hub) { c.ShutdownGrace = 0 }, "--shutdown-grace"},
		{"sample ratio high", func(c *Hub) { c.TraceSampleRatio = 1.5 }, "--trace-sample-ratio"},
		{"sample ratio negative", func(c *Hub) { c.TraceSampleRatio = -0.1 }, "--trace-sample-ratio"},
		{"public url scheme", func(c *Hub) { c.PublicURL = "ftp://hub.example.com" }, "--public-url"},
		{"public url no host", func(c *Hub) { c.PublicURL = "https://" }, "--public-url"},
		{"public url unparseable", func(c *Hub) { c.PublicURL = "https://%zz" }, "--public-url"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := validHub(t)
			tc.mutate(c)
			err := c.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() = %v, want an error wrapping ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.contains)
			}
		})
	}
}

func TestHubValidateAccumulates(t *testing.T) {
	t.Parallel()

	c := validHub(t)
	c.MCPAddr = "nope"
	c.LogLevel = "loud"
	c.MaxSpokes = -1
	c.TraceSampleRatio = 3

	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want four problems")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("Validate() error %T does not unwrap to a list; it must use errors.Join", err)
	}
	if n := len(joined.Unwrap()); n != 4 {
		t.Errorf("Validate() reported %d problems, want 4:\n%v", n, err)
	}
	for _, want := range []string{"--mcp-addr", "--log-level", "--max-spokes", "--trace-sample-ratio"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() does not mention %s:\n%v", want, err)
		}
	}
}

func TestHubValidateAcceptsPublicURLAndPairs(t *testing.T) {
	t.Parallel()

	c := validHub(t)
	c.PublicURL = "https://mcp.example.com/mcp"
	c.CACertFile, c.CAKeyFile = "/ca.pem", "/ca.key"
	c.TunnelPath = "/pmf/tunnel"
	c.ShutdownDrainDelay = 0
	c.MCPAddr = "0.0.0.0:0"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// TestHubValidateAcceptsHTTPPublicURL pins that a plain http --public-url is
// valid, not just https. The scheme check is "!= https && != http": without
// a case exercising the http side, negating that second comparison to
// "== http" is unobservable, because every other test's public URL is https.
// TestHubValidateAcceptsZeroRenewGrace pins that --renew-grace of exactly
// zero is legal, not merely non-negative: it is the documented way to
// disable the renewal grace period and require strict expiry, so
// checkNonNegative's "d < 0" must not have drifted to "d <= 0".
func TestHubValidateAcceptsZeroRenewGrace(t *testing.T) {
	t.Parallel()
	c := validHub(t)
	c.RenewGrace = 0
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for --renew-grace=0", err)
	}
}

func TestHubValidateAcceptsHTTPPublicURL(t *testing.T) {
	t.Parallel()
	c := validHub(t)
	c.PublicURL = "http://mcp.example.com/mcp"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for an http --public-url", err)
	}
}

// TestHubValidateEmptyPublicURLReportsExactlyOneProblem guards against a
// second, redundant checkURL call firing when --public-url is empty. Validate
// checks PublicURL == "" first (which reports "is required" and stops there
// conceptually) and then later, unconditionally when the guard says non-empty,
// runs checkURL again. Negating that second guard to "== \"\"" would run
// checkURL("") too, which finds a non-empty-string-shaped scheme problem and
// adds a second error that nothing today checks for.
func TestHubValidateEmptyPublicURLReportsExactlyOneProblem(t *testing.T) {
	t.Parallel()
	c := validHub(t)
	c.PublicURL = ""
	err := c.Validate()
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("Validate() error %T does not unwrap to a list; it must use errors.Join", err)
	}
	if n := len(joined.Unwrap()); n != 1 {
		t.Errorf("Validate() reported %d problems for empty --public-url, want 1:\n%v", n, err)
	}
}

// TestHubValidateZeroBudgetDoesNotAlsoFailBelowCheck guards the first half of
// the compound "budget > 0 && max > 0 && budget < max" guard. At budget == 0
// the guard's own checkPositiveBytes already reports the zero-budget problem;
// mutating "budget > 0" to "budget >= 0" would additionally, and wrongly, fire
// the below-check's own problem message, since 0 < any positive max is true.
func TestHubValidateZeroBudgetDoesNotAlsoFailBelowCheck(t *testing.T) {
	t.Parallel()
	c := validHub(t)
	c.MaxResponseBudgetBytes = 0
	err := c.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want an error wrapping ErrInvalid", err)
	}
	if strings.Contains(err.Error(), "below --max-response-bytes") {
		t.Errorf("Validate() = %q, a zero budget must not also trip the below-check", err)
	}
}

// TestHubValidateAcceptsBudgetEqualToMaxResponseBytes pins the boundary of the
// compound budget check's third clause, "budget < max": a budget exactly
// equal to max-response-bytes can still complete one response and must be
// accepted, which is the only case distinguishing "<" from the off-by-one
// "<=".
func TestHubValidateAcceptsBudgetEqualToMaxResponseBytes(t *testing.T) {
	t.Parallel()
	c := validHub(t)
	c.MaxResponseBudgetBytes = c.MaxResponseBytes
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil when the budget equals max-response-bytes", err)
	}
}

func TestSpokeValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*Spoke)
		contains string
	}{
		{"no endpoints", func(c *Spoke) { c.HubEndpoints = nil }, "--hub-endpoints"},
		{"endpoint neither url nor host:port", func(c *Spoke) { c.HubEndpoints = []string{"hub.example.com"} }, "--hub-endpoints"},
		{"endpoint empty", func(c *Spoke) { c.HubEndpoints = []string{""} }, "is empty"},
		{"endpoint unparseable URL", func(c *Spoke) { c.HubEndpoints = []string{"wss://%zz"} }, "not a URL"},
		{"endpoint without host", func(c *Spoke) { c.HubEndpoints = []string{":8443"} }, "has no host"},
		{"endpoint port zero", func(c *Spoke) { c.HubEndpoints = []string{"hub:0"} }, "invalid port"},
		{"endpoint port not numeric", func(c *Spoke) { c.HubEndpoints = []string{"hub:https"} }, "invalid port"},
		{"endpoint bad scheme", func(c *Spoke) { c.HubEndpoints = []string{"ftp://hub/tunnel"} }, "scheme"},
		{"endpoint url without host", func(c *Spoke) { c.HubEndpoints = []string{"wss:///tunnel"} }, "has no host"},
		{"endpoint url with credentials", func(c *Spoke) { c.HubEndpoints = []string{"wss://u:p@hub/tunnel"} }, "credentials"},
		{"endpoint url with query", func(c *Spoke) { c.HubEndpoints = []string{"wss://hub/tunnel?a=1"} }, "query or fragment"},
		{
			"duplicate endpoint",
			func(c *Spoke) { c.HubEndpoints = []string{"wss://hub/tunnel", "wss://hub/tunnel"} },
			"appears twice",
		},
		{"hub api url missing", func(c *Spoke) { c.HubAPIURL = "" }, "--hub-api-url"},
		{"hub api url scheme", func(c *Spoke) { c.HubAPIURL = "hub.example.com" }, "--hub-api-url"},
		{
			"insecure hub without acknowledgement",
			func(c *Spoke) { c.HubTLSInsecure = true },
			"PMF_ALLOW_INSECURE",
		},
		{
			"insecure prometheus without acknowledgement",
			func(c *Spoke) { c.PrometheusTLSSkipVerify = true },
			"PMF_ALLOW_INSECURE",
		},
		{"cluster id missing", func(c *Spoke) { c.ClusterID = "" }, "--cluster-id"},
		{"cluster id uppercase", func(c *Spoke) { c.ClusterID = "Prod" }, "--cluster-id"},
		{"cluster id leading dash", func(c *Spoke) { c.ClusterID = "-prod" }, "--cluster-id"},
		{"cluster id trailing dash", func(c *Spoke) { c.ClusterID = "prod-" }, "--cluster-id"},
		{"cluster id underscore", func(c *Spoke) { c.ClusterID = "prod_1" }, "--cluster-id"},
		{"cluster id too long", func(c *Spoke) { c.ClusterID = strings.Repeat("a", 64) }, "--cluster-id"},
		{"cluster sdlc missing", func(c *Spoke) { c.ClusterSDLC = "" }, "--cluster-sdlc"},
		{"cluster sdlc invalid character", func(c *Spoke) { c.ClusterSDLC = "prod!" }, "--cluster-sdlc"},
		{"cluster sdlc too long", func(c *Spoke) { c.ClusterSDLC = strings.Repeat("a", 33) }, "--cluster-sdlc"},
		{"negative node count", func(c *Spoke) { c.ClusterK8sNodes = -1 }, "--cluster-k8s-nodes"},
		{
			"label key invalid",
			func(c *Spoke) { c.ClusterLabels = map[string]string{"1env": "prod"} },
			"--cluster-labels",
		},
		{
			"label value control character",
			func(c *Spoke) { c.ClusterLabels = map[string]string{"env": "pr\x00od"} },
			"control character",
		},
		{
			"too many labels",
			func(c *Spoke) {
				c.ClusterLabels = map[string]string{}
				for i := range MaxClusterLabels + 1 {
					c.ClusterLabels["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
				}
			},
			"exceeds the limit",
		},
		{
			"display name control character",
			func(c *Spoke) { c.ClusterDisplayName = "prod\x1b[31m" },
			"--cluster-display-name",
		},
		{
			// indexControl checks "i >= 0"; a control character at byte 0 is
			// the only value distinguishing that from the off-by-one "i > 0".
			"display name control character at start",
			func(c *Spoke) { c.ClusterDisplayName = "\x01prod" },
			"--cluster-display-name",
		},
		{
			"description control character",
			func(c *Spoke) { c.ClusterDescription = "line\nbreak" },
			"--cluster-description",
		},
		{
			"description control character at start",
			func(c *Spoke) { c.ClusterDescription = "\x01desc" },
			"--cluster-description",
		},
		{"data dir", func(c *Spoke) { c.DataDir = "" }, "--data-dir"},
		{"identity secret required", func(c *Spoke) { c.IdentityBackend, c.IdentitySecretName = IdentityBackendSecret, "" }, "--identity-secret-name"},
		{"prometheus url missing", func(c *Spoke) { c.PrometheusURL = "" }, "--prometheus-url"},
		{"prometheus url scheme", func(c *Spoke) { c.PrometheusURL = "tcp://prom:9090" }, "--prometheus-url"},
		{"prometheus timeout", func(c *Spoke) { c.PrometheusTimeout = 0 }, "--prometheus-timeout"},
		{"prometheus max bytes", func(c *Spoke) { c.PrometheusMaxResponseBytes = 0 }, "--prometheus-max-response-bytes"},
		{"facts interval", func(c *Spoke) { c.FactsRefreshInterval = 0 }, "--facts-refresh-interval"},
		{"min backoff", func(c *Spoke) { c.ReconnectMinBackoff = 0 }, "--reconnect-min-backoff"},
		{"max backoff", func(c *Spoke) { c.ReconnectMaxBackoff = 0 }, "--reconnect-max-backoff"},
		{
			"max backoff below min",
			func(c *Spoke) { c.ReconnectMaxBackoff = time.Millisecond },
			"below --reconnect-min-backoff",
		},
		{"admin addr", func(c *Spoke) { c.AdminAddr = "9090" }, "--admin-addr"},
		{"log level", func(c *Spoke) { c.LogLevel = "trace" }, "--log-level"},
		{"log format", func(c *Spoke) { c.LogFormat = "logfmt" }, "--log-format"},
		{"sample ratio", func(c *Spoke) { c.TraceSampleRatio = 2 }, "--trace-sample-ratio"},
		{"drain delay", func(c *Spoke) { c.ShutdownDrainDelay = -time.Second }, "--shutdown-drain-delay"},
		{"shutdown grace", func(c *Spoke) { c.ShutdownGrace = 0 }, "--shutdown-grace"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := validSpoke(t)
			tc.mutate(c)
			err := c.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() = %v, want an error wrapping ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.contains)
			}
		})
	}
}

func TestSpokeValidateInsecureIsAllowedWhenAcknowledged(t *testing.T) {
	t.Parallel()

	c := validSpoke(t)
	c.HubTLSInsecure = true
	c.PrometheusTLSSkipVerify = true
	c.AllowInsecure = true
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil once PMF_ALLOW_INSECURE is set", err)
	}
}

func TestSpokeValidateAcceptsLegacyHostPortEndpoint(t *testing.T) {
	t.Parallel()
	c := validSpoke(t)
	c.HubEndpoints = []string{"hub.example.com:8443"}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() rejected the documented legacy host:port endpoint: %v", err)
	}
}

func TestCheckPairAcceptsBothPathsEmpty(t *testing.T) {
	t.Parallel()
	if err := checkPair("cert", "", "key", ""); err != nil {
		t.Errorf("checkPair(empty, empty) = %v, want nil", err)
	}
}

// TestSpokeValidateZeroMaxBackoffDoesNotAlsoFailBelowCheck guards the second
// clause of the compound "min > 0 && max > 0 && max < min" guard. At max == 0
// checkPositive already reports the zero-max-backoff problem; mutating
// "max > 0" to "max >= 0" would additionally, and wrongly, fire the
// below-check's own problem message, since a positive min is always > 0.
func TestSpokeValidateZeroMaxBackoffDoesNotAlsoFailBelowCheck(t *testing.T) {
	t.Parallel()
	c := validSpoke(t)
	c.ReconnectMaxBackoff = 0
	err := c.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want an error wrapping ErrInvalid", err)
	}
	if strings.Contains(err.Error(), "below --reconnect-min-backoff") {
		t.Errorf("Validate() = %q, a zero max-backoff must not also trip the below-check", err)
	}
}

// TestSpokeValidateAcceptsEqualBackoffs pins the boundary of the compound
// backoff check's third clause, "max < min": a max-backoff exactly equal to
// min-backoff means no growth, not an inversion, and must be accepted -- the
// only case distinguishing "<" from the off-by-one "<=".
func TestSpokeValidateAcceptsEqualBackoffs(t *testing.T) {
	t.Parallel()
	c := validSpoke(t)
	c.ReconnectMinBackoff = 5 * time.Second
	c.ReconnectMaxBackoff = 5 * time.Second
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil when max-backoff equals min-backoff", err)
	}
}

func TestSpokeValidateAccumulates(t *testing.T) {
	t.Parallel()

	c := validSpoke(t)
	c.ClusterID = "NOPE"
	c.HubAPIURL = ""
	c.LogFormat = "yaml"

	err := c.Validate()
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("Validate() error %T does not unwrap to a list; it must use errors.Join", err)
	}
	if n := len(joined.Unwrap()); n != 3 {
		t.Errorf("Validate() reported %d problems, want 3:\n%v", n, err)
	}
}
