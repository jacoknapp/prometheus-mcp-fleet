// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// mintForTest returns a minted agent token, failing the test on error.
func mintForTest(t *testing.T) Minted {
	t.Helper()
	m, err := Mint(fleet.ClassAgent)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return m
}

func TestRawTokenRedactsUnderFmt(t *testing.T) {
	t.Parallel()
	m := mintForTest(t)
	raw := m.Raw.Reveal()

	// A struct wrapper is the realistic leak path: someone logs %+v of a
	// request or config object that happens to carry a token.
	type wrapper struct {
		Token RawToken
		Note  string
	}
	w := wrapper{Token: m.Raw, Note: "n"}

	tests := []struct {
		name string
		got  string
	}{
		{"%v", fmt.Sprintf("%v", m.Raw)},
		{"%+v", fmt.Sprintf("%+v", m.Raw)},
		{"%s", fmt.Sprintf("%s", m.Raw)},
		{"%q", fmt.Sprintf("%q", m.Raw)},
		{"%#v", fmt.Sprintf("%#v", m.Raw)},
		{"pointer %v", fmt.Sprintf("%v", &m.Raw)},
		{"struct %v", fmt.Sprintf("%v", w)},
		{"struct %+v", fmt.Sprintf("%+v", w)},
		{"struct %#v", fmt.Sprintf("%#v", w)},
		{"slice %v", fmt.Sprintf("%v", []RawToken{m.Raw})},
		{"map %v", fmt.Sprintf("%v", map[string]RawToken{"k": m.Raw})},
		{"Error", fmt.Errorf("context: %v", m.Raw).Error()},
		{"String", m.Raw.String()},
		{"GoString", m.Raw.GoString()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if strings.Contains(tc.got, raw) {
				t.Fatalf("formatted output leaked the token: %s", tc.got)
			}
			if !strings.Contains(tc.got, Redacted) {
				t.Fatalf("formatted output = %q, want it to contain %q", tc.got, Redacted)
			}
		})
	}

	if m.Raw.Reveal() != raw {
		t.Error("Reveal did not return the original token")
	}
	if m.Raw.IsZero() {
		t.Error("IsZero reported true for a minted token")
	}
	if !RawToken("").IsZero() {
		t.Error("IsZero reported false for an empty token")
	}
}

func TestRawTokenRedactsUnderJSON(t *testing.T) {
	t.Parallel()
	m := mintForTest(t)
	raw := m.Raw.Reveal()

	type payload struct {
		Token RawToken `json:"token"`
	}
	tests := []struct {
		name string
		in   any
	}{
		{"bare", m.Raw},
		{"pointer", &m.Raw},
		{"struct field", payload{Token: m.Raw}},
		{"slice", []RawToken{m.Raw}},
		{"map value", map[string]RawToken{"k": m.Raw}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if bytes.Contains(b, []byte(raw)) {
				t.Fatalf("JSON leaked the token: %s", b)
			}
			if !bytes.Contains(b, []byte(Redacted)) {
				t.Fatalf("JSON = %s, want it to contain %q", b, Redacted)
			}
		})
	}
}

func TestRawTokenRedactsUnderSlog(t *testing.T) {
	t.Parallel()
	m := mintForTest(t)
	raw := m.Raw.Reveal()

	tests := []struct {
		name string
		log  func(*slog.Logger)
	}{
		{"slog.Any", func(l *slog.Logger) { l.Info("issued", slog.Any("token", m.Raw)) }},
		{"slog.Any pointer", func(l *slog.Logger) { l.Info("issued", slog.Any("token", &m.Raw)) }},
		{"grouped", func(l *slog.Logger) {
			l.WithGroup("cred").Info("issued", slog.Any("token", m.Raw))
		}},
		{"minted", func(l *slog.Logger) { l.Info("issued", slog.Any("minted", m)) }},
		{"minted pointer", func(l *slog.Logger) { l.Info("issued", slog.Any("minted", &m)) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, h := range []string{"json", "text"} {
				var buf bytes.Buffer
				var logger *slog.Logger
				if h == "json" {
					logger = slog.New(slog.NewJSONHandler(&buf, nil))
				} else {
					logger = slog.New(slog.NewTextHandler(&buf, nil))
				}
				tc.log(logger)
				out := buf.String()
				if strings.Contains(out, raw) {
					t.Fatalf("%s handler leaked the token: %s", h, out)
				}
				if strings.Contains(out, string(m.Secret)) && len(m.Secret) > 0 {
					t.Fatalf("%s handler leaked the secret bytes: %s", h, out)
				}
			}
		})
	}
}

func TestMintedRedacts(t *testing.T) {
	t.Parallel()
	m := mintForTest(t)
	raw := m.Raw.Reveal()

	for _, got := range []string{
		fmt.Sprintf("%v", m),
		fmt.Sprintf("%+v", m),
		fmt.Sprintf("%#v", m),
		fmt.Sprintf("%s", m),
		fmt.Sprintf("%v", &m),
		fmt.Sprintf("%v", struct{ M Minted }{m}),
	} {
		if strings.Contains(got, raw) {
			t.Fatalf("Minted formatting leaked the token: %s", got)
		}
		if strings.Contains(got, string(m.Secret)) {
			t.Fatalf("Minted formatting leaked the secret: %s", got)
		}
		if !strings.Contains(got, Redacted) {
			t.Fatalf("Minted formatting = %q, want it to contain %q", got, Redacted)
		}
		if !strings.Contains(got, m.KID) {
			t.Fatalf("Minted formatting = %q, want it to keep the public kid %q", got, m.KID)
		}
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	want := map[string]string{"kid": m.KID, "raw": Redacted, "secret": Redacted}
	for k, v := range want {
		if decoded[k] != v {
			t.Errorf("json field %q = %q, want %q", k, decoded[k], v)
		}
	}
	if len(decoded) != len(want) {
		t.Errorf("json object = %s, want exactly the fields %v", b, want)
	}
}
