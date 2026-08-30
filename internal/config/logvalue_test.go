// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"log/slog"
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
