// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// theSecret is the value every case below tries, and fails, to leak.
const theSecret = "pmf_agt_s3cr3tvalue"

// holder exercises the case that matters most in practice: a secret embedded
// in a struct that something formats or serialises wholesale.
type holder struct {
	Name  string
	Token Secret
}

func TestSecretNeverLeaksThroughFormatting(t *testing.T) {
	t.Parallel()

	s := Secret(theSecret)
	h := holder{Name: "sre-oncall-bot", Token: s}

	tests := []struct {
		name string
		got  string
	}{
		{"verb v", fmt.Sprintf("%v", s)},
		{"verb plus v", fmt.Sprintf("%+v", s)},
		{"verb sharp v", fmt.Sprintf("%#v", s)},
		{"verb s", fmt.Sprintf("%s", s)},
		{"verb q", fmt.Sprintf("%q", s)},
		{"print", fmt.Sprint(s)},
		{"pointer verb v", fmt.Sprintf("%v", &s)},
		{"struct verb v", fmt.Sprintf("%v", h)},
		{"struct verb plus v", fmt.Sprintf("%+v", h)},
		{"struct verb sharp v", fmt.Sprintf("%#v", h)},
		{"struct pointer", fmt.Sprintf("%+v", &h)},
		{"slice of secrets", fmt.Sprintf("%v", []Secret{s})},
		{"map of secrets", fmt.Sprintf("%v", map[string]Secret{"k": s})},
		{"error wrapping", fmt.Errorf("token %v rejected", s).Error()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if strings.Contains(tc.got, theSecret) {
				t.Fatalf("secret leaked: %s", tc.got)
			}
			if !strings.Contains(tc.got, redacted) {
				t.Errorf("output %q does not contain %q", tc.got, redacted)
			}
		})
	}
}

func TestSecretNeverLeaksThroughJSON(t *testing.T) {
	t.Parallel()

	s := Secret(theSecret)
	tests := []struct {
		name string
		v    any
	}{
		{"bare", s},
		{"pointer", &s},
		{"struct field", holder{Name: "bot", Token: s}},
		{"struct pointer", &holder{Name: "bot", Token: s}},
		{"slice", []Secret{s}},
		{"map value", map[string]Secret{"token": s}},
		{"map key", map[Secret]string{s: "v"}},
		{"nested", map[string]any{"outer": map[string]any{"inner": s}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if bytes.Contains(b, []byte(theSecret)) {
				t.Fatalf("secret leaked: %s", b)
			}
			if !bytes.Contains(b, []byte("REDACTED")) {
				t.Errorf("output %s does not contain the redaction marker", b)
			}
		})
	}
}

func TestSecretNeverLeaksThroughSlog(t *testing.T) {
	t.Parallel()

	s := Secret(theSecret)
	tests := []struct {
		name    string
		handler func(*bytes.Buffer) slog.Handler
	}{
		{"json", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
		{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			log := slog.New(tc.handler(&buf))
			log.Info("issued",
				slog.Any("secret", s),
				slog.Any("pointer", &s),
				slog.Any("struct", holder{Name: "bot", Token: s}),
				slog.Any("slice", []Secret{s}),
				slog.String("safe", "kid-123"),
			)
			log.With(slog.Any("attached", s)).Error("failed")

			if strings.Contains(buf.String(), theSecret) {
				t.Fatalf("secret leaked: %s", buf.String())
			}
			if !strings.Contains(buf.String(), "REDACTED") {
				t.Errorf("output does not contain the redaction marker: %s", buf.String())
			}
			if !strings.Contains(buf.String(), "kid-123") {
				t.Errorf("non-secret attribute was dropped: %s", buf.String())
			}
		})
	}
}

func TestSecretAccessors(t *testing.T) {
	t.Parallel()

	s := Secret(theSecret)
	if got := s.Reveal(); got != theSecret {
		t.Errorf("Reveal() = %q, want the underlying value", got)
	}
	if s.IsZero() {
		t.Error("IsZero() = true for a populated secret")
	}
	if !Secret("").IsZero() {
		t.Error("IsZero() = false for an empty secret")
	}
	if got, err := Secret("").MarshalText(); err != nil || string(got) != redacted {
		t.Errorf("MarshalText() = %q, %v; want the redaction marker", got, err)
	}
}
