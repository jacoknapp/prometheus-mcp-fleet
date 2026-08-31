// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

// logLine renders one log record containing v and returns it.
func logLine(t *testing.T, key string, v slog.LogValuer) string {
	t.Helper()
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config", slog.Any(key, v))
	return buf.String()
}

func TestHubLogValueRedactsURLCredentials(t *testing.T) {
	t.Parallel()

	c := validHub(t)
	c.PublicURL = "https://agent:hunter2@mcp.example.com/mcp"
	c.OTLPEndpoint = "https://otel:s3cr3t@collector:4317"

	line := logLine(t, "hub", c)
	for _, secret := range []string{"hunter2", "s3cr3t"} {
		if strings.Contains(line, secret) {
			t.Errorf("log line leaks %q:\n%s", secret, line)
		}
	}
	if !strings.Contains(line, "redacted@") {
		t.Errorf("log line does not mark the redaction:\n%s", line)
	}
	for _, want := range []string{"mcp_addr", "data_dir", "pepper_file", "trust_domain", "enable_status_config"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line is missing %q:\n%s", want, line)
		}
	}
}

func TestSpokeLogValueRedactsURLCredentials(t *testing.T) {
	t.Parallel()

	c := validSpoke(t)
	c.PrometheusURL = "https://scraper:p4ssw0rd@prom.svc:9090"
	c.HubAPIURL = "https://spoke:t0ken@hub.example.com"
	c.ClusterLabels = map[string]string{"env": "prod"}

	line := logLine(t, "spoke", c)
	for _, secret := range []string{"p4ssw0rd", "t0ken"} {
		if strings.Contains(line, secret) {
			t.Errorf("log line leaks %q:\n%s", secret, line)
		}
	}
	for _, want := range []string{"cluster_id", "env=prod", "hub_endpoints", "prometheus_bearer_token_file"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line is missing %q:\n%s", want, line)
		}
	}
}

func TestLogValueHandlesNil(t *testing.T) {
	t.Parallel()

	var h *Hub
	if got := h.LogValue().String(); got != "<nil>" {
		t.Errorf("(*Hub)(nil).LogValue() = %q, want \"<nil>\"", got)
	}
	var s *Spoke
	if got := s.LogValue().String(); got != "<nil>" {
		t.Errorf("(*Spoke)(nil).LogValue() = %q, want \"<nil>\"", got)
	}
}

func TestRedactURL(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"no credentials", "https://hub.example.com/x", "https://hub.example.com/x"},
		{"password", "https://u:p@h/x", "https://redacted@h/x"},
		{"user only", "https://u@h/x", "https://redacted@h/x"},
		{"host port only", "collector:4317", "collector:4317"},
		{"unparseable", "https://%zz", "[unparseable-url]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := redactURL(tc.in); got != tc.want {
				t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// snakeCaseKey is the key grammar the rest of this codebase logs in: an ASCII
// lower-case word, then any number of further words each joined by exactly one
// underscore.
var snakeCaseKey = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

// A camelCase key silently splits a log query in two. An operator grouping on
// state_backend has to find the line that says what the backend is, and a
// `stateBackend` sitting next to twenty snake_case siblings is exactly how that
// stops being true -- the same drift that had to be fixed once already in
// internal/hubapi, where `remoteAddr` and `remote_addr` were both in use.
//
// sloglint enforces this grammar at every log call site, but it inspects call
// arguments and cannot see inside a LogValue() implementation. These two groups
// are therefore the one place in the codebase where a key can drift without any
// linter noticing, which is what this test is for.
//
// It also asserts no credential reaches the record. Only the URL-valued fields
// can carry one inline -- everything else is a path, an address or a bound --
// so those are the fields stuffed with a sentinel here. A future field that can
// hold a credential must be added to the sentinel list AND routed through
// redactURL; neither this test nor the linter can infer the first from the
// second.
func TestLogValueKeysAreSnakeCaseAndCarryNoCredential(t *testing.T) {
	t.Parallel()

	const sentinel = "s3ntinel-must-not-be-logged"

	hub := validHub(t)
	hub.PublicURL = "https://agent:" + sentinel + "@mcp.example.com/mcp"
	hub.OTLPEndpoint = "https://otel:" + sentinel + "@collector:4317"

	spoke := validSpoke(t)
	spoke.PrometheusURL = "https://scraper:" + sentinel + "@prom.svc:9090"
	spoke.HubAPIURL = "https://spoke:" + sentinel + "@hub.example.com"
	spoke.OTLPEndpoint = "https://otel:" + sentinel + "@collector:4317"

	tests := []struct {
		name string
		v    slog.LogValuer
	}{
		{"hub", hub},
		{"spoke", spoke},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			attrs := tc.v.LogValue().Group()
			if len(attrs) == 0 {
				t.Fatal("LogValue() produced no attributes")
			}
			for _, a := range attrs {
				if !snakeCaseKey.MatchString(a.Key) {
					t.Errorf("key %q is not snake_case", a.Key)
				}
				if v := a.Value.String(); strings.Contains(v, sentinel) {
					t.Errorf("key %q leaks a credential: %s", a.Key, v)
				}
			}
			if line := logLine(t, tc.name, tc.v); strings.Contains(line, sentinel) {
				t.Errorf("rendered record leaks a credential:\n%s", line)
			}
		})
	}
}
