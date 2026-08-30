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
		"PMF_HUB_ENDPOINTS": "hub.example.com:8443",
		"PMF_HUB_API_URL":   "https://hub.example.com",
		"PMF_CLUSTER_ID":    "prod-us-east-1",
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
		{"tunnel addr", func(c *Hub) { c.TunnelAddr = "nope" }, "--tunnel-addr"},
		{"admin addr", func(c *Hub) { c.AdminAddr = "nope" }, "--admin-addr"},
		{"admin addr host with space", func(c *Hub) { c.AdminAddr = "bad host:9090" }, "--admin-addr"},
		{"log level", func(c *Hub) { c.LogLevel = "verbose" }, "--log-level"},
		{"log format", func(c *Hub) { c.LogFormat = "xml" }, "--log-format"},
		{"data dir", func(c *Hub) { c.DataDir = "" }, "--data-dir"},
		{"pepper file", func(c *Hub) { c.PepperFile = "" }, "--pepper-file"},
		{"ca cert without key", func(c *Hub) { c.CACertFile, c.CAKeyFile = "/ca.pem", "" }, "--ca-key-file"},
		{"ca key without cert", func(c *Hub) { c.CACertFile, c.CAKeyFile = "", "/ca.key" }, "--ca-cert-file"},
		{"tunnel cert without key", func(c *Hub) { c.TunnelTLSCertFile = "/t.pem" }, "--tunnel-tls-key-file"},
		{"tunnel key without cert", func(c *Hub) { c.TunnelTLSKeyFile = "/t.key" }, "--tunnel-tls-cert-file"},
		{"trust domain empty", func(c *Hub) { c.TrustDomain = "" }, "--trust-domain"},
		{"trust domain uppercase", func(c *Hub) { c.TrustDomain = "Fleet.Local" }, "--trust-domain"},
		{"spoke cert ttl", func(c *Hub) { c.SpokeCertTTL = 0 }, "--spoke-cert-ttl"},
		{"enrollment token ttl", func(c *Hub) { c.EnrollmentTokenTTL = -time.Second }, "--enrollment-token-ttl"},
		{"agent key ttl", func(c *Hub) { c.AgentKeyTTL = 0 }, "--agent-key-ttl"},
		{"max spokes", func(c *Hub) { c.MaxSpokes = 0 }, "--max-spokes"},
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
	c.MaxSpokes = 0
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
	c.TunnelTLSCertFile, c.TunnelTLSKeyFile = "/t.pem", "/t.key"
	c.ShutdownDrainDelay = 0
	c.MCPAddr = "0.0.0.0:0"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
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
		{"endpoint not host:port", func(c *Spoke) { c.HubEndpoints = []string{"hub.example.com"} }, "--hub-endpoints"},
		{"endpoint without host", func(c *Spoke) { c.HubEndpoints = []string{":8443"} }, "has no host"},
		{"endpoint port zero", func(c *Spoke) { c.HubEndpoints = []string{"hub:0"} }, "invalid port"},
		{"endpoint port not numeric", func(c *Spoke) { c.HubEndpoints = []string{"hub:https"} }, "invalid port"},
		{
			"duplicate endpoint",
			func(c *Spoke) { c.HubEndpoints = []string{"hub:8443", "hub:8443"} },
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
			"description control character",
			func(c *Spoke) { c.ClusterDescription = "line\nbreak" },
			"--cluster-description",
		},
		{"data dir", func(c *Spoke) { c.DataDir = "" }, "--data-dir"},
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
