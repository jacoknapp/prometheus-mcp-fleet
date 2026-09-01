// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// env builds a getenv function over a map, so tests never touch the process
// environment and can therefore run in parallel.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestEnvKey(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, flagName, want string }{
		{"simple", "mcp-addr", "PMF_MCP_ADDR"},
		{"multi dash", "max-inflight-per-cluster", "PMF_MAX_INFLIGHT_PER_CLUSTER"},
		{"no dash", "pprof", "PMF_PPROF"},
		{"already upper", "Cluster-ID", "PMF_CLUSTER_ID"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := EnvKey(tc.flagName); got != tc.want {
				t.Errorf("EnvKey(%q) = %q, want %q", tc.flagName, got, tc.want)
			}
		})
	}
}

func TestHelpErrorMessageIsUsage(t *testing.T) {
	t.Parallel()
	err := &HelpError{Usage: "usage text"}
	if got := err.Error(); got != err.Usage {
		t.Errorf("Error() = %q, want %q", got, err.Usage)
	}
}

func TestSplitListDropsOnlyEmptyItems(t *testing.T) {
	t.Parallel()
	if got := splitList(" \t\n "); got != nil {
		t.Errorf("splitList of whitespace = %#v, want nil", got)
	}
	if got := splitList(" , , "); got != nil {
		t.Errorf("splitList of delimiters = %#v, want nil", got)
	}
}

// TestCsvValueStringNilSafety exercises every branch of csvValue.String's
// nil guard directly: a nil receiver, a non-nil receiver with a nil dst, and
// the ordinary populated case. Nothing in LoadHub/LoadSpoke's own tests ever
// calls String() on a nil csvValue -- it only surfaces via flag.PrintDefaults
// on a normally constructed flag -- so without a direct test here, negating
// either half of "v == nil || v.dst == nil" changes nothing any existing test
// can observe.
func TestCsvValueStringNilSafety(t *testing.T) {
	t.Parallel()

	var nilPtr *csvValue
	if got := nilPtr.String(); got != "" {
		t.Errorf("(*csvValue)(nil).String() = %q, want \"\"", got)
	}
	if got := (&csvValue{}).String(); got != "" {
		t.Errorf("csvValue{dst: nil}.String() = %q, want \"\"", got)
	}
	list := []string{"a", "b"}
	if got := (&csvValue{dst: &list}).String(); got != "a,b" {
		t.Errorf("csvValue{dst: &[a b]}.String() = %q, want %q", got, "a,b")
	}
}

// TestLabelsValueStringNilSafety is the labelsValue analogue of
// TestCsvValueStringNilSafety, for the same reason.
func TestLabelsValueStringNilSafety(t *testing.T) {
	t.Parallel()

	var nilPtr *labelsValue
	if got := nilPtr.String(); got != "" {
		t.Errorf("(*labelsValue)(nil).String() = %q, want \"\"", got)
	}
	if got := (&labelsValue{}).String(); got != "" {
		t.Errorf("labelsValue{dst: nil}.String() = %q, want \"\"", got)
	}
	m := map[string]string{"env": "prod"}
	if got := (&labelsValue{dst: &m}).String(); got != "env=prod" {
		t.Errorf("labelsValue{dst: &{env:prod}}.String() = %q, want %q", got, "env=prod")
	}
}

// TestCheckAddrAcceptsMaxPort pins 65535 as valid: checkAddr rejects "n >
// 65535", and 65535 is the only port that distinguishes that check from the
// off-by-one "n >= 65535".
func TestCheckAddrAcceptsMaxPort(t *testing.T) {
	t.Parallel()
	if err := checkAddr("addr", "host:65535"); err != nil {
		t.Errorf("checkAddr(host:65535) = %v, want nil", err)
	}
}

// TestCheckHubEndpointAcceptsBoundaryPorts pins both ends of the host:port
// form's valid port range. checkHubEndpoint rejects "n < 1 || n > 65535", and
// 1 and 65535 are the only values that distinguish those from the
// off-by-one "n <= 1" and "n >= 65535".
func TestCheckHubEndpointAcceptsBoundaryPorts(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{"hub.example.com:1", "hub.example.com:65535"} {
		if err := checkHubEndpoint("hub-endpoints", addr); err != nil {
			t.Errorf("checkHubEndpoint(%q) = %v, want nil", addr, err)
		}
	}
}

// TestCheckRatioAcceptsBoundaries pins both ends of the documented [0,1]
// range. checkRatio rejects "r < 0 || r > 1", and 0 and 1 are the only values
// that distinguish those from the off-by-one "r <= 0" and "r >= 1".
func TestCheckRatioAcceptsBoundaries(t *testing.T) {
	t.Parallel()
	for _, r := range []float64{0, 1} {
		if err := checkRatio("trace-sample-ratio", r); err != nil {
			t.Errorf("checkRatio(%v) = %v, want nil", r, err)
		}
	}
}

func TestLoadHubDefaults(t *testing.T) {
	t.Parallel()

	c, err := LoadHub(nil, env(nil))
	if err != nil {
		t.Fatalf("LoadHub() error = %v", err)
	}
	want := &Hub{
		MCPAddr:         DefaultMCPAddr,
		TunnelPath:      DefaultTunnelPath,
		AdminAddr:       DefaultHubAdminAddr,
		LogLevel:        DefaultLogLevel,
		LogFormat:       DefaultLogFormat,
		DataDir:         DefaultDataDir,
		PepperFile:      filepath.Join(DefaultDataDir, PepperFileName),
		StateBackend:    StateBackendAuto,
		StateSecretName: DefaultStateSecretName,
		CASecretName:    DefaultCASecretName,
		StateFile:       filepath.Join(DefaultDataDir, StateFileName),
		CACertFile:      filepath.Join(DefaultDataDir, CACertFileName),
		CAKeyFile:       filepath.Join(DefaultDataDir, CAKeyFileName),
		// Rotation is on by default: the CA rotating itself is the only
		// version of this that needs no operator, so an install that says
		// nothing gets it.
		CARotationEnabled:           true,
		CARotateAtRemainingFraction: DefaultCARotateAtRemainingFraction,
		CARotationPollInterval:      DefaultCARotationPollInterval,
		TrustDomain:                 DefaultTrustDomain,
		SpokeCertTTL:                336 * time.Hour,
		RenewGrace:                  30 * 24 * time.Hour,
		EnrollmentTokenTTL:          15 * time.Minute,
		AgentKeyTTL:                 2160 * time.Hour,
		AdminKeyTTL:                 2160 * time.Hour,
		MaxSpokes:                   0,
		QueryTimeout:                30 * time.Second,
		RangeQueryTimeout:           120 * time.Second,
		MaxResponseBytes:            33554432,
		MaxInflightPerCluster:       8,
		MaxResponseBudgetBytes:      268435456,
		FactsPollInterval:           60 * time.Second,
		ShutdownDrainDelay:          5 * time.Second,
		ShutdownGrace:               30 * time.Second,
		TraceSampleRatio:            DefaultTraceSampleRatio,
	}
	if diff := cmp.Diff(want, c); diff != "" {
		t.Errorf("LoadHub() defaults mismatch (-want +got):\n%s", diff)
	}
	// The defaults alone are deliberately not valid: --public-url has no
	// sensible default (it is the operator's external hostname) and is
	// required, so assert that it is the *only* thing missing.
	err = c.Validate()
	if err == nil {
		t.Fatal("default hub configuration validated, but --public-url is required")
	}
	if !strings.Contains(err.Error(), "--public-url") {
		t.Errorf("default hub configuration failed for an unexpected reason: %v", err)
	}
	c.PublicURL = "https://pmf.example.com/mcp"
	if err := c.Validate(); err != nil {
		t.Errorf("defaults plus --public-url must be valid, got %v", err)
	}
}

func TestLoadSpokeDefaults(t *testing.T) {
	t.Parallel()

	c, err := LoadSpoke(nil, env(nil))
	if err != nil {
		t.Fatalf("LoadSpoke() error = %v", err)
	}
	want := &Spoke{
		DataDir:                    DefaultDataDir,
		IdentityBackend:            IdentityBackendAuto,
		IdentitySecretName:         DefaultIdentitySecretName,
		PrometheusURL:              DefaultPrometheusURL,
		PrometheusTimeout:          25 * time.Second,
		PrometheusMaxResponseBytes: 33554432,
		FactsRefreshInterval:       10 * time.Minute,
		ReconnectMinBackoff:        500 * time.Millisecond,
		ReconnectMaxBackoff:        30 * time.Second,
		AdminAddr:                  DefaultSpokeAdminAddr,
		LogLevel:                   DefaultLogLevel,
		LogFormat:                  DefaultLogFormat,
		TraceSampleRatio:           DefaultTraceSampleRatio,
		ShutdownDrainDelay:         5 * time.Second,
		ShutdownGrace:              30 * time.Second,
	}
	if diff := cmp.Diff(want, c); diff != "" {
		t.Errorf("LoadSpoke() defaults mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadHubPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		kv   map[string]string
		want func(*Hub) any
		got  any
	}{
		{
			name: "default when neither is set",
			want: func(c *Hub) any { return c.MCPAddr },
			got:  DefaultMCPAddr,
		},
		{
			name: "env beats default",
			kv:   map[string]string{"PMF_MCP_ADDR": ":1111"},
			want: func(c *Hub) any { return c.MCPAddr },
			got:  ":1111",
		},
		{
			name: "flag beats env",
			args: []string{"--mcp-addr=:2222"},
			kv:   map[string]string{"PMF_MCP_ADDR": ":1111"},
			want: func(c *Hub) any { return c.MCPAddr },
			got:  ":2222",
		},
		{
			name: "single dash flag form",
			args: []string{"-mcp-addr", ":3333"},
			want: func(c *Hub) any { return c.MCPAddr },
			got:  ":3333",
		},
		{
			name: "empty env is treated as unset",
			kv:   map[string]string{"PMF_MCP_ADDR": ""},
			want: func(c *Hub) any { return c.MCPAddr },
			got:  DefaultMCPAddr,
		},
		{
			name: "duration from env",
			kv:   map[string]string{"PMF_QUERY_TIMEOUT": "45s"},
			want: func(c *Hub) any { return c.QueryTimeout },
			got:  45 * time.Second,
		},
		{
			name: "renew grace from flag",
			args: []string{"--renew-grace=48h"},
			want: func(c *Hub) any { return c.RenewGrace },
			got:  48 * time.Hour,
		},
		{
			name: "renew grace from env",
			kv:   map[string]string{"PMF_RENEW_GRACE": "72h"},
			want: func(c *Hub) any { return c.RenewGrace },
			got:  72 * time.Hour,
		},
		{
			name: "renew grace of zero is accepted, disabling the grace",
			args: []string{"--renew-grace=0"},
			want: func(c *Hub) any { return c.RenewGrace },
			got:  time.Duration(0),
		},
		{
			name: "duration flag beats env",
			args: []string{"--query-timeout=90s"},
			kv:   map[string]string{"PMF_QUERY_TIMEOUT": "45s"},
			want: func(c *Hub) any { return c.QueryTimeout },
			got:  90 * time.Second,
		},
		{
			name: "int from env",
			kv:   map[string]string{"PMF_MAX_SPOKES": "12"},
			want: func(c *Hub) any { return c.MaxSpokes },
			got:  12,
		},
		{
			name: "int64 from env",
			kv:   map[string]string{"PMF_MAX_RESPONSE_BYTES": "1024"},
			want: func(c *Hub) any { return c.MaxResponseBytes },
			got:  int64(1024),
		},
		{
			name: "bool from env accepts 1",
			kv:   map[string]string{"PMF_PPROF_ENABLED": "1"},
			want: func(c *Hub) any { return c.PprofEnabled },
			got:  true,
		},
		{
			name: "bool flag false beats env true",
			args: []string{"--pprof-enabled=false"},
			kv:   map[string]string{"PMF_PPROF_ENABLED": "true"},
			want: func(c *Hub) any { return c.PprofEnabled },
			got:  false,
		},
		{
			name: "float from env",
			kv:   map[string]string{"PMF_TRACE_SAMPLE_RATIO": "0.5"},
			want: func(c *Hub) any { return c.TraceSampleRatio },
			got:  0.5,
		},
		{
			name: "gate flag",
			args: []string{"--enable-status-config"},
			want: func(c *Hub) any { return c.EnableStatusConfig },
			got:  true,
		},
		{
			name: "tunnel path from env",
			kv:   map[string]string{"PMF_TUNNEL_PATH": "/pmf/tunnel"},
			want: func(c *Hub) any { return c.TunnelPath },
			got:  "/pmf/tunnel",
		},
		{
			name: "tunnel path flag beats env",
			args: []string{"--tunnel-path=/a"},
			kv:   map[string]string{"PMF_TUNNEL_PATH": "/b"},
			want: func(c *Hub) any { return c.TunnelPath },
			got:  "/a",
		},
		{
			name: "explicit pepper file is kept",
			args: []string{"--pepper-file=/secrets/pepper"},
			want: func(c *Hub) any { return c.PepperFile },
			got:  "/secrets/pepper",
		},
		{
			name: "pepper file follows data dir",
			args: []string{"--data-dir=/srv/pmf"},
			want: func(c *Hub) any { return c.PepperFile },
			got:  "/srv/pmf/pepper.key",
		},
		{
			name: "vendor neutral otel endpoint is honoured",
			kv:   map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "otel:4317"},
			want: func(c *Hub) any { return c.OTLPEndpoint },
			got:  "otel:4317",
		},
		{
			name: "prefixed otel endpoint wins over vendor neutral",
			kv: map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT":     "otel:4317",
				"PMF_OTEL_EXPORTER_OTLP_ENDPOINT": "pmf-otel:4317",
			},
			want: func(c *Hub) any { return c.OTLPEndpoint },
			got:  "pmf-otel:4317",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := LoadHub(tc.args, env(tc.kv))
			if err != nil {
				t.Fatalf("LoadHub(%q) error = %v", tc.args, err)
			}
			if diff := cmp.Diff(tc.got, tc.want(c)); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadSpokePrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		kv   map[string]string
		want func(*Spoke) any
		got  any
	}{
		{
			name: "endpoints from env",
			kv:   map[string]string{"PMF_HUB_ENDPOINTS": "wss://a/tunnel,wss://b/tunnel"},
			want: func(c *Spoke) any { return c.HubEndpoints },
			got:  []string{"wss://a/tunnel", "wss://b/tunnel"},
		},
		{
			name: "endpoints flag beats env",
			args: []string{"--hub-endpoints=wss://c/tunnel"},
			kv:   map[string]string{"PMF_HUB_ENDPOINTS": "wss://a/tunnel,wss://b/tunnel"},
			want: func(c *Spoke) any { return c.HubEndpoints },
			got:  []string{"wss://c/tunnel"},
		},
		{
			name: "labels from env",
			kv:   map[string]string{"PMF_CLUSTER_LABELS": "env=prod, region = us-east-1"},
			want: func(c *Spoke) any { return c.ClusterLabels },
			got:  map[string]string{"env": "prod", "region": "us-east-1"},
		},
		{
			name: "labels flag beats env",
			args: []string{"--cluster-labels=env=dev"},
			kv:   map[string]string{"PMF_CLUSTER_LABELS": "env=prod"},
			want: func(c *Spoke) any { return c.ClusterLabels },
			got:  map[string]string{"env": "dev"},
		},
		{
			name: "cluster id from env",
			kv:   map[string]string{"PMF_CLUSTER_ID": "prod-us-east-1"},
			want: func(c *Spoke) any { return c.ClusterID },
			got:  "prod-us-east-1",
		},
		{
			name: "insecure acknowledgement",
			kv:   map[string]string{"PMF_ALLOW_INSECURE": "1", "PMF_HUB_TLS_INSECURE": "true"},
			want: func(c *Spoke) any { return c.AllowInsecure && c.HubTLSInsecure },
			got:  true,
		},
		{
			name: "prometheus url from env",
			kv:   map[string]string{"PMF_PROMETHEUS_URL": "https://prom.svc:9090"},
			want: func(c *Spoke) any { return c.PrometheusURL },
			got:  "https://prom.svc:9090",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := LoadSpoke(tc.args, env(tc.kv))
			if err != nil {
				t.Fatalf("LoadSpoke(%q) error = %v", tc.args, err)
			}
			if diff := cmp.Diff(tc.got, tc.want(c)); diff != "" {
				t.Errorf("value mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		spoke    bool
		args     []string
		kv       map[string]string
		wantErr  error
		contains string
	}{
		{name: "unknown flag", args: []string{"--nope"}, wantErr: ErrUsage, contains: "nope"},
		{name: "stray argument", args: []string{"serve"}, wantErr: ErrUsage, contains: "serve"},
		{name: "bad flag value", args: []string{"--query-timeout=banana"}, wantErr: ErrUsage, contains: "query-timeout"},
		{name: "bad duration env", kv: map[string]string{"PMF_QUERY_TIMEOUT": "banana"}, wantErr: ErrEnv, contains: "PMF_QUERY_TIMEOUT"},
		{name: "bad int env", kv: map[string]string{"PMF_MAX_SPOKES": "many"}, wantErr: ErrEnv, contains: "PMF_MAX_SPOKES"},
		{name: "bad int64 env", kv: map[string]string{"PMF_MAX_RESPONSE_BYTES": "8MiB"}, wantErr: ErrEnv, contains: "PMF_MAX_RESPONSE_BYTES"},
		{name: "bad bool env", kv: map[string]string{"PMF_PPROF_ENABLED": "yes please"}, wantErr: ErrEnv, contains: "PMF_PPROF_ENABLED"},
		{name: "bad float env", kv: map[string]string{"PMF_TRACE_SAMPLE_RATIO": "half"}, wantErr: ErrEnv, contains: "PMF_TRACE_SAMPLE_RATIO"},
		{
			name:    "several bad env vars are reported together",
			kv:      map[string]string{"PMF_MAX_SPOKES": "many", "PMF_PPROF_ENABLED": "sure"},
			wantErr: ErrEnv, contains: "PMF_PPROF_ENABLED",
		},
		{
			name: "bad labels env", spoke: true,
			kv:      map[string]string{"PMF_CLUSTER_LABELS": "=oops"},
			wantErr: ErrEnv, contains: "PMF_CLUSTER_LABELS",
		},
		{
			name: "bad labels flag", spoke: true,
			args:    []string{"--cluster-labels=1bad=x"},
			wantErr: ErrUsage, contains: "cluster-labels",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var err error
			if tc.spoke {
				_, err = LoadSpoke(tc.args, env(tc.kv))
			} else {
				_, err = LoadHub(tc.args, env(tc.kv))
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want one wrapping %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("error %q does not mention %q", err, tc.contains)
			}
		})
	}
}

func TestLoadMultipleEnvErrorsAreJoined(t *testing.T) {
	t.Parallel()

	_, err := LoadHub(nil, env(map[string]string{
		"PMF_MAX_SPOKES":    "many",
		"PMF_PPROF_ENABLED": "sure",
		"PMF_QUERY_TIMEOUT": "soon",
	}))
	if err == nil {
		t.Fatal("LoadHub() error = nil, want three joined errors")
	}
	for _, want := range []string{"PMF_MAX_SPOKES", "PMF_PPROF_ENABLED", "PMF_QUERY_TIMEOUT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error does not mention %s:\n%s", want, err)
		}
	}
}

func TestLoadHelp(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			for _, load := range []struct {
				name string
				fn   func([]string, func(string) string) error
			}{
				{"hub", func(a []string, g func(string) string) error { _, err := LoadHub(a, g); return err }},
				{"spoke", func(a []string, g func(string) string) error { _, err := LoadSpoke(a, g); return err }},
			} {
				err := load.fn([]string{arg}, env(nil))
				if !errors.Is(err, ErrHelp) {
					t.Errorf("%s: error = %v, want ErrHelp", load.name, err)
				}
				if !errors.Is(err, flag.ErrHelp) {
					t.Errorf("%s: error = %v, want it to wrap flag.ErrHelp", load.name, err)
				}
				var he *HelpError
				if !errors.As(err, &he) {
					t.Fatalf("%s: error = %v, want a *HelpError", load.name, err)
				}
				for _, want := range []string{"Usage:", "-log-level", "PMF_LOG_LEVEL"} {
					if !strings.Contains(he.Usage, want) {
						t.Errorf("%s: usage text does not mention %q:\n%s", load.name, want, he.Usage)
					}
				}
			}
		})
	}
}

func TestLoadNilGetenvUsesProcessEnvironment(t *testing.T) {
	// Not parallel: it mutates the process environment.
	t.Setenv("PMF_TRUST_DOMAIN", "from-process.example")
	c, err := LoadHub(nil, nil)
	if err != nil {
		t.Fatalf("LoadHub() error = %v", err)
	}
	if c.TrustDomain != "from-process.example" {
		t.Errorf("TrustDomain = %q, want it read from the process environment", c.TrustDomain)
	}
	if os.Getenv("PMF_TRUST_DOMAIN") != "from-process.example" {
		t.Fatal("t.Setenv did not take effect")
	}

	s, err := LoadSpoke(nil, nil)
	if err != nil {
		t.Fatalf("LoadSpoke() error = %v", err)
	}
	if s.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want the default", s.DataDir)
	}
}
