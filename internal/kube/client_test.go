// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	goodCA := filepath.Join(caDir, "good.pem")
	if err := os.WriteFile(goodCA, pemCert(selfSignedDER(t)), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	badCA := filepath.Join(caDir, "bad.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"valid", Config{APIServerURL: "https://api:443", Namespace: "monitoring"}, ""},
		{"valid with ca", Config{APIServerURL: "https://api:443", Namespace: "monitoring", CAFile: goodCA}, ""},
		{"empty url", Config{Namespace: "monitoring"}, "api server url is required"},
		{"unparseable url", Config{APIServerURL: "https://api:443/\x7f", Namespace: "ns"}, "api server url"},
		{"wrong scheme", Config{APIServerURL: "ftp://api", Namespace: "ns"}, "scheme must be https"},
		{"no host", Config{APIServerURL: "https:///path", Namespace: "ns"}, "has no host"},
		{"empty namespace", Config{APIServerURL: "https://api:443"}, "namespace: name is empty"},
		{"bad namespace", Config{APIServerURL: "https://api:443", Namespace: "../kube-system"}, "not a DNS subdomain"},
		{"missing ca", Config{APIServerURL: "https://api:443", Namespace: "ns", CAFile: filepath.Join(caDir, "nope.pem")}, "read ca bundle"},
		{"unparseable ca", Config{APIServerURL: "https://api:443", Namespace: "ns", CAFile: badCA}, "contains no certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				if c.Namespace() != tc.cfg.Namespace {
					t.Errorf("Namespace() = %q, want %q", c.Namespace(), tc.cfg.Namespace)
				}
				return
			}
			if err == nil {
				t.Fatalf("New = %v, want an error containing %q", c, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("New error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewTrimsTrailingSlash(t *testing.T) {
	t.Parallel()
	c, err := New(Config{APIServerURL: "https://api:443/", Namespace: "ns"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if want := "https://api:443"; c.base != want {
		t.Errorf("base = %q, want %q", c.base, want)
	}
}

func TestValidateName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"simple", "prometheus-mcp-fleet-state", true},
		{"single char", "a", true},
		{"dotted", "fleet.state.v1", true},
		{"empty", "", false},
		{"uppercase", "State", false},
		{"traversal", "../kube-system/secrets", false},
		{"slash", "ns/name", false},
		{"leading dash", "-state", false},
		{"trailing dot", "state.", false},
		{"too long", strings.Repeat("a", 254), false},
		{"max length", strings.Repeat("a", 253), true},
		{"space", "my state", false},
		{"nul", "state\x00", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateName(tc.in)
			if tc.ok && err != nil {
				t.Errorf("ValidateName(%q) = %v, want nil", tc.in, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("ValidateName(%q) = nil, want an error", tc.in)
			}
		})
	}
}

func TestDoRequestFailure(t *testing.T) {
	t.Parallel()

	t.Run("context cancelled", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSecret(t, w, http.StatusOK, &wireSecret{})
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.GetSecret(ctx, "state"); !errors.Is(err, context.Canceled) {
			t.Errorf("GetSecret error = %v, want context.Canceled", err)
		}
	})

	t.Run("server unreachable", func(t *testing.T) {
		t.Parallel()
		c, srv := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
		srv.Close()
		if _, err := c.GetSecret(t.Context(), "state"); err == nil {
			t.Error("GetSecret = nil, want a transport error")
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"metadata":{"name":`))
		})
		_, err := c.GetSecret(t.Context(), "state")
		if err == nil || !strings.Contains(err.Error(), "decode response") {
			t.Errorf("GetSecret error = %v, want a decode failure", err)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			chunk := make([]byte, 64<<10)
			for i := range chunk {
				chunk[i] = 'x'
			}
			for written := int64(0); written <= MaxResponseBytes; written += int64(len(chunk)) {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		})
		_, err := c.GetSecret(t.Context(), "state")
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Errorf("GetSecret error = %v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("unencodable request body", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSecret(t, w, http.StatusOK, &wireSecret{})
		})
		err := c.do(t.Context(), "test", http.MethodPost, "/x", make(chan int), nil)
		if err == nil || !strings.Contains(err.Error(), "encode request") {
			t.Errorf("do error = %v, want an encode failure", err)
		}
	})

	t.Run("bad method", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
		err := c.do(t.Context(), "test", "bad method", "/x", nil, nil)
		if err == nil || !strings.Contains(err.Error(), "build request") {
			t.Errorf("do error = %v, want a request construction failure", err)
		}
	})

	t.Run("no output decoding", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})
		if err := c.do(t.Context(), "test", http.MethodGet, "/x", nil, nil); err != nil {
			t.Errorf("do with a nil out = %v, want nil", err)
		}
	})
}

func TestRequestHeaders(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeTokenFile(t, tokenFile, "sa-token-value", time.Now().UnixNano())

	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		writeSecret(t, w, http.StatusOK, &wireSecret{Metadata: wireMeta{Name: "state"}})
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{
		APIServerURL: srv.URL,
		Namespace:    testNamespace,
		TokenFile:    tokenFile,
		HTTPClient:   srv.Client(),
		Logger:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetSecret(t.Context(), "state"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	for header, want := range map[string]string{
		"Authorization": "Bearer sa-token-value",
		"Accept":        "application/json",
		"User-Agent":    userAgent,
	} {
		if got.Get(header) != want {
			t.Errorf("%s = %q, want %q", header, got.Get(header), want)
		}
	}
}

func TestNoAuthorizationHeaderWithoutTokenFile(t *testing.T) {
	t.Parallel()
	var got http.Header
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		writeSecret(t, w, http.StatusOK, &wireSecret{Metadata: wireMeta{Name: "state"}})
	})
	if _, err := c.GetSecret(t.Context(), "state"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if v := got.Get("Authorization"); v != "" {
		t.Errorf("Authorization = %q, want it absent", v)
	}
}

func TestTokenFileUnreadable(t *testing.T) {
	t.Parallel()
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, http.StatusOK, &wireSecret{})
	})
	c.tokens = newTokenSource(filepath.Join(t.TempDir(), "absent"), DefaultTokenTTL, time.Now, slog.New(slog.DiscardHandler))
	if _, err := c.GetSecret(t.Context(), "state"); err == nil || !strings.Contains(err.Error(), "token file") {
		t.Errorf("GetSecret error = %v, want a token file error", err)
	}
}

// TestTokenRotation is the regression test for a token cached for the process
// lifetime: the API server starts rejecting the old value, and only a re-read
// of the rotated file recovers.
func TestTokenRotation(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	base := time.Now()
	writeTokenFile(t, tokenFile, "token-v1", base.UnixNano())

	const current = "token-v2"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+current {
			writeStatus(t, w, http.StatusUnauthorized, "Unauthorized", "the server has asked for the client to provide credentials")
			return
		}
		writeSecret(t, w, http.StatusOK, &wireSecret{Metadata: wireMeta{Name: "state", ResourceVersion: "7"}})
	}))
	t.Cleanup(srv.Close)

	now := base
	c, err := New(Config{APIServerURL: srv.URL, Namespace: testNamespace, TokenFile: tokenFile, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.tokens = newTokenSource(tokenFile, DefaultTokenTTL, func() time.Time { return now }, slog.New(slog.DiscardHandler))

	if _, err := c.GetSecret(t.Context(), "state"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("GetSecret with the stale token = %v, want ErrUnauthorized", err)
	}

	// The kubelet rotates the projected token by replacing the file.
	writeTokenFile(t, tokenFile, current, base.Add(time.Minute).UnixNano())

	// Within the TTL the client is still entitled to reuse the cached token.
	if _, err := c.GetSecret(t.Context(), "state"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("GetSecret inside the TTL = %v, want the cached token to still be used", err)
	}

	now = base.Add(DefaultTokenTTL + time.Second)
	got, err := c.GetSecret(t.Context(), "state")
	if err != nil {
		t.Fatalf("GetSecret after rotation: %v", err)
	}
	if got.ResourceVersion != "7" {
		t.Errorf("ResourceVersion = %q, want %q", got.ResourceVersion, "7")
	}
}

// TestTLSVerification proves the client really validates the API server
// against the configured bundle, which is the guarantee that lets it send a
// service account token at all.
func TestTLSVerification(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, http.StatusOK, &wireSecret{Metadata: wireMeta{Name: "state"}})
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	trusted := filepath.Join(dir, "server.pem")
	if err := os.WriteFile(trusted, pemCert(srv.Certificate().Raw), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	untrusted := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(untrusted, pemCert(selfSignedDER(t)), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	tests := []struct {
		name    string
		caFile  string
		wantErr bool
	}{
		{"bundle matches the server", trusted, false},
		{"bundle does not match the server", untrusted, true},
		{"system roots do not know the server", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(Config{APIServerURL: srv.URL, Namespace: testNamespace, CAFile: tc.caFile})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = c.GetSecret(t.Context(), "state")
			if tc.wantErr && err == nil {
				t.Fatal("GetSecret = nil, want a certificate verification failure")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("GetSecret: %v", err)
			}
			if tc.wantErr {
				var ce *x509.CertificateInvalidError
				var ue x509.UnknownAuthorityError
				if !errors.As(err, &ce) && !errors.As(err, &ue) {
					t.Errorf("error = %v, want an x509 verification failure", err)
				}
			}
		})
	}
}

func TestInCluster(t *testing.T) {
	ca := string(pemCert(selfSignedDER(t)))
	tests := []struct {
		name    string
		host    string
		port    string
		token   string
		ca      string
		ns      string
		want    error
		wantErr string
	}{
		{name: "healthy", host: "10.96.0.1", port: "443", token: "tok", ca: ca, ns: "monitoring"},
		{name: "no host", port: "443", token: "tok", ca: ca, ns: "monitoring", want: ErrNotInCluster},
		{name: "no port", host: "10.96.0.1", token: "tok", ca: ca, ns: "monitoring", want: ErrNotInCluster},
		{name: "no namespace file", host: "10.96.0.1", port: "443", token: "tok", ca: ca, want: ErrNotInCluster},
		{name: "no token file", host: "10.96.0.1", port: "443", ca: ca, ns: "monitoring", want: ErrNotInCluster},
		{name: "no ca file", host: "10.96.0.1", port: "443", token: "tok", ns: "monitoring", want: ErrNotInCluster},
		{name: "unusable namespace", host: "10.96.0.1", port: "443", token: "tok", ca: ca, ns: "Not A Namespace", wantErr: "namespace"},
		{name: "unreadable namespace file", host: "10.96.0.1", port: "443", token: "tok", ca: ca, ns: dirMarker, wantErr: "read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel.
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", tc.port)
			dir := serviceAccountDir(t, tc.token, tc.ca, tc.ns)
			c, err := inCluster(dir)
			switch {
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Fatalf("inCluster error = %v, want %v", err, tc.want)
				}
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("inCluster error = %v, want it to contain %q", err, tc.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("inCluster: %v", err)
				}
				if c.Namespace() != tc.ns {
					t.Errorf("Namespace() = %q, want %q", c.Namespace(), tc.ns)
				}
				if want := "https://10.96.0.1:443"; c.base != want {
					t.Errorf("base = %q, want %q", c.base, want)
				}
			}
		})
	}
}

func TestInClusterUsesTheDefaultDirectory(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := InCluster(); !errors.Is(err, ErrNotInCluster) {
		t.Fatalf("InCluster error = %v, want ErrNotInCluster", err)
	}
}

// selfSignedDER returns a throwaway self-signed certificate, used as a CA
// bundle that is valid PEM but not the test server's issuer.
func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}
