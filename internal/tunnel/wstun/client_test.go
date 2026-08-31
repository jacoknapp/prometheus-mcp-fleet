// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
)

var errHandshakeFixture = errors.New("handshake fixture failure")

type failingSigner struct{}

func (failingSigner) Public() crypto.PublicKey { return nil }
func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errHandshakeFixture
}

type deadlineConn struct {
	net.Conn
	failAll  bool
	failZero bool
}

func (c deadlineConn) SetDeadline(d time.Time) error {
	if c.failAll || (c.failZero && d.IsZero()) {
		return errHandshakeFixture
	}
	return c.Conn.SetDeadline(d)
}

type secondWriteFails struct{ writes int }

func (w *secondWriteFails) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 2 {
		return 0, errHandshakeFixture
	}
	return len(p), nil
}

// TestNormalizeEndpoint pins the grammar an operator's PMF_HUB_ENDPOINTS value
// is read with, including the host:port form kept for spokes upgrading from
// before ADR-0014.
func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		want     string
		wantErr  bool
	}{
		{name: "full wss url", endpoint: "wss://hub.example.com/tunnel", want: "wss://hub.example.com/tunnel"},
		{name: "custom path is kept", endpoint: "wss://hub.example.com/pmf/tunnel", want: "wss://hub.example.com/pmf/tunnel"},
		{name: "https becomes wss", endpoint: "https://hub.example.com/tunnel", want: "wss://hub.example.com/tunnel"},
		{name: "http becomes ws", endpoint: "http://hub.example.com/tunnel", want: "ws://hub.example.com/tunnel"},
		{name: "ws is kept", endpoint: "ws://127.0.0.1:8080/tunnel", want: "ws://127.0.0.1:8080/tunnel"},
		{name: "empty path defaults", endpoint: "wss://hub.example.com", want: "wss://hub.example.com" + DefaultPath},
		{name: "root path defaults", endpoint: "wss://hub.example.com/", want: "wss://hub.example.com" + DefaultPath},
		{name: "legacy host port", endpoint: "hub.example.com:8443", want: "wss://hub.example.com:8443" + DefaultPath},
		{name: "legacy ipv6 host port", endpoint: "[::1]:8443", want: "wss://[::1]:8443" + DefaultPath},
		{name: "surrounding space is tolerated", endpoint: "  wss://hub.example.com/tunnel ", want: "wss://hub.example.com/tunnel"},

		{name: "empty", endpoint: "", wantErr: true},
		{name: "bare hostname with no port", endpoint: "hub.example.com", wantErr: true},
		{name: "bare host with a path", endpoint: "hub.example.com/tunnel", wantErr: true},
		{name: "unknown scheme", endpoint: "grpc://hub.example.com/tunnel", wantErr: true},
		{name: "no host", endpoint: "wss:///tunnel", wantErr: true},
		{name: "credentials in the url", endpoint: "wss://user:pass@hub.example.com/tunnel", wantErr: true},
		{name: "query string", endpoint: "wss://hub.example.com/tunnel?token=x", wantErr: true},
		{name: "fragment", endpoint: "wss://hub.example.com/tunnel#frag", wantErr: true},
		{name: "unparseable", endpoint: "wss://hub.example.com/tun\x7fnel%zz", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeEndpoint(tc.endpoint)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidEndpoint) {
					t.Fatalf("NormalizeEndpoint(%q) error = %v, want ErrInvalidEndpoint", tc.endpoint, err)
				}
				// The message is what an operator sees, so it has to say what a
				// good value looks like.
				if !strings.Contains(err.Error(), "wss://") {
					t.Errorf("error %q does not show a valid endpoint", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeEndpoint(%q) error = %v", tc.endpoint, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeEndpoint(%q) = %q, want %q", tc.endpoint, got, tc.want)
			}
		})
	}
}

// TestClientHandshake drives the spoke half against a scripted hub, which is
// the only way to exercise a hub that misbehaves.
func TestClientHandshake(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	cert := ca.issue(t, "prod")

	tests := []struct {
		name string
		// hub plays the server side over one end of a net.Pipe.
		hub     func(t *testing.T, conn net.Conn, auth *clientAuth)
		wantErr error
		wantID  string
	}{
		{
			name: "accepted",
			hub: func(t *testing.T, conn net.Conn, _ *clientAuth) {
				nonce := make([]byte, nonceLen)
				write(t, conn, serverHello{Nonce: nonce, ProtocolVersion: ProtocolVersion, ServerID: "hub-7"})
				read(t, conn, &clientAuth{})
				write(t, conn, serverAccept{Accepted: true, ClusterID: "prod"})
			},
			wantID: "hub-7",
		},
		{
			name: "hub speaks another version",
			hub: func(t *testing.T, conn net.Conn, _ *clientAuth) {
				write(t, conn, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: "v99"})
			},
			wantErr: ErrProtocolVersion,
		},
		{
			name: "hub sends a short nonce",
			hub: func(t *testing.T, conn net.Conn, _ *clientAuth) {
				write(t, conn, serverHello{Nonce: []byte{1, 2, 3}, ProtocolVersion: ProtocolVersion})
			},
			wantErr: ErrHandshakeFailed,
		},
		{
			name: "hub refuses",
			hub: func(t *testing.T, conn net.Conn, _ *clientAuth) {
				write(t, conn, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion})
				read(t, conn, &clientAuth{})
				write(t, conn, serverAccept{Accepted: false, Reason: "certificate has been revoked"})
			},
			wantErr: ErrHandshakeFailed,
		},
		{
			name: "hub derived a different cluster id",
			hub: func(t *testing.T, conn net.Conn, _ *clientAuth) {
				write(t, conn, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion})
				read(t, conn, &clientAuth{})
				write(t, conn, serverAccept{Accepted: true, ClusterID: "staging"})
			},
			wantErr: ErrClusterMismatch,
		},
		{
			name: "hub hangs up before saying anything",
			hub: func(_ *testing.T, conn net.Conn, _ *clientAuth) {
				_ = conn.Close()
			},
			wantErr: ErrHandshakeFailed,
		},
		{
			name: "hub sends a message that is not a handshake",
			hub: func(_ *testing.T, conn net.Conn, _ *clientAuth) {
				_, _ = conn.Write([]byte{0, 0, 0, 4, 'n', 'o', 'p', 'e'})
			},
			wantErr: ErrHandshakeFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

			var auth clientAuth
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.hub(t, server, &auth)
			}()

			signer, err := signerFor(cert)
			if err != nil {
				t.Fatalf("signerFor: %v", err)
			}
			id, err := clientHandshake(client, ClientConfig{ClusterID: "prod", Certificate: cert}, signer)
			_ = client.Close()
			<-done

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("clientHandshake() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("clientHandshake() error = %v", err)
			}
			if id != tc.wantID {
				t.Errorf("server id = %q, want %q", id, tc.wantID)
			}
		})
	}
}

// TestClientHandshakeLocalFailures covers failures originating on the spoke,
// rather than malformed messages sent by the scripted hubs above.
func TestClientHandshakeLocalFailures(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	cert := ca.issue(t, "prod")
	signer, err := signerFor(cert)
	if err != nil {
		t.Fatalf("signerFor: %v", err)
	}

	t.Run("cannot install handshake deadline", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		_, err := clientHandshake(deadlineConn{Conn: client, failAll: true}, ClientConfig{ClusterID: "prod", Certificate: cert}, signer)
		if !errors.Is(err, ErrHandshakeFailed) || !errors.Is(err, errHandshakeFixture) {
			t.Errorf("clientHandshake() = %v, want handshake/deadline failure", err)
		}
	})

	t.Run("signer fails", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_ = writeMessage(server, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion})
		}()
		_, err := clientHandshake(client, ClientConfig{ClusterID: "prod", Certificate: cert}, failingSigner{})
		if !errors.Is(err, ErrHandshakeFailed) || !errors.Is(err, errHandshakeFixture) {
			t.Errorf("clientHandshake() = %v, want signer failure", err)
		}
	})

	t.Run("auth write fails", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			_ = writeMessage(server, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion})
			_ = server.Close()
		}()
		_, err := clientHandshake(client, ClientConfig{ClusterID: "prod", Certificate: cert}, signer)
		if !errors.Is(err, ErrHandshakeFailed) {
			t.Errorf("clientHandshake() = %v, want handshake write failure", err)
		}
	})

	t.Run("hub closes before verdict", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			_ = writeMessage(server, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion})
			var auth clientAuth
			_ = readMessage(server, &auth)
			_ = server.Close()
		}()
		_, err := clientHandshake(client, ClientConfig{ClusterID: "prod", Certificate: cert}, signer)
		if !errors.Is(err, ErrHandshakeFailed) {
			t.Errorf("clientHandshake() = %v, want missing-verdict failure", err)
		}
	})

	t.Run("cannot clear deadline", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_ = writeMessage(server, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion})
			var auth clientAuth
			_ = readMessage(server, &auth)
			_ = writeMessage(server, serverAccept{Accepted: true, ClusterID: "prod"})
		}()
		_, err := clientHandshake(deadlineConn{Conn: client, failZero: true}, ClientConfig{ClusterID: "prod", Certificate: cert}, signer)
		if !errors.Is(err, ErrHandshakeFailed) || !errors.Is(err, errHandshakeFixture) {
			t.Errorf("clientHandshake() = %v, want clear-deadline failure", err)
		}
	})
}

// TestDialHandshakeClassification covers failures that occur after a valid
// HTTP upgrade, where Dial must distinguish protocol negotiation and caller
// cancellation from an identity rejection.
func TestDialHandshakeClassification(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	cert := ca.issue(t, "prod")

	t.Run("server omits the subprotocol", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, nil)
			if err == nil {
				defer ws.CloseNow()
			}
		}))
		defer ts.Close()
		err := Dial(context.Background(), ClientConfig{
			URL: "ws" + strings.TrimPrefix(ts.URL, "http"), Certificate: cert,
			ClusterID: "prod", HTTPClient: ts.Client(),
		}, &tunneltest.EchoHandler{})
		var de *grpctun.DialError
		if !errors.As(err, &de) || de.Reason != grpctun.ReasonUpgradeRejected || !errors.Is(err, ErrSubprotocol) {
			t.Errorf("Dial() = %v, want subprotocol upgrade rejection", err)
		}
	})

	t.Run("caller cancels during handshake", func(t *testing.T) {
		t.Parallel()
		upgraded := make(chan struct{})
		release := make(chan struct{})
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
			if err != nil {
				return
			}
			conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
			if err := writeMessage(conn, serverHello{Nonce: make([]byte, nonceLen), ProtocolVersion: ProtocolVersion}); err != nil {
				return
			}
			var auth clientAuth
			if err := readMessage(conn, &auth); err != nil {
				return
			}
			close(upgraded)
			<-release
			ws.CloseNow()
		}))
		defer ts.Close()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Dial(ctx, ClientConfig{
				URL: "ws" + strings.TrimPrefix(ts.URL, "http"), Certificate: cert,
				ClusterID: "prod", HTTPClient: ts.Client(), Logger: quiet(),
			}, &tunneltest.EchoHandler{})
		}()
		<-upgraded
		cancel()
		close(release)
		err := <-done
		var de *grpctun.DialError
		if !errors.As(err, &de) || de.Reason != grpctun.ReasonContextCancelled || !errors.Is(err, context.Canceled) {
			t.Errorf("Dial() = %v, want context-cancelled classification", err)
		}
	})
}

// TestDialUsesTheConfiguredLogger proves cfg.Logger is not silently discarded:
// Dial's own "tunnel connected" line must reach the caller's Logger, not a
// default one built regardless of what was configured.
func TestDialUsesTheConfiguredLogger(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	cert := hub.ca.issue(t, "prod")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Dial(ctx, ClientConfig{
			URL:         hub.wsURL(),
			Certificate: cert,
			ClusterID:   "prod",
			Logger:      logger,
			HTTPClient:  hub.http.Client(),
			Generation:  1,
		}, &tunneltest.EchoHandler{})
	}()

	select {
	case <-hub.sessions:
	case err := <-done:
		cancel()
		t.Fatalf("Dial returned before a session was established: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("no session within 20s")
	}
	cancel()
	<-done

	if !strings.Contains(buf.String(), "tunnel connected") {
		t.Errorf("the configured Logger recorded nothing about the connection (got %q); "+
			"Dial must not fall back to a default logger when one was supplied", buf.String())
	}
}

// TestSignerFor covers the two ways a spoke can have no usable key.
func TestSignerFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cert tls.Certificate
	}{
		{name: "no certificate at all", cert: tls.Certificate{}},
		{
			name: "a key that cannot sign",
			cert: tls.Certificate{Certificate: [][]byte{{0x30}}, PrivateKey: "not a key"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := signerFor(tc.cert); err == nil {
				t.Fatal("signerFor accepted a certificate it cannot sign with")
			}
		})
	}
}

// TestHTTPClient covers building the transport from a trust bundle.
func TestHTTPClient(t *testing.T) {
	t.Parallel()

	supplied := &http.Client{}
	if got, err := (ClientConfig{HTTPClient: supplied}).httpClient(); err != nil || got != supplied {
		t.Errorf("httpClient() = %v, %v, want the supplied client", got, err)
	}
	if _, err := (ClientConfig{CABundle: []byte("garbage")}).httpClient(); err == nil {
		t.Error("httpClient() accepted a bundle with no certificate in it")
	}

	ca := newTestCA(t)
	pem := pemEncode(t, ca.cert.Raw)
	client, err := (ClientConfig{CABundle: pem}).httpClient()
	if err != nil {
		t.Fatalf("httpClient() error = %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Error("the trust bundle was not installed")
	}
	if tr.ForceAttemptHTTP2 {
		t.Error("HTTP/2 is attempted; an RFC 6455 upgrade needs HTTP/1.1")
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %s, want 10s", tr.TLSHandshakeTimeout)
	}

	t.Run("no bundle uses the system pool without error", func(t *testing.T) {
		t.Parallel()
		client, err := (ClientConfig{}).httpClient()
		if err != nil {
			t.Fatalf("httpClient() error = %v, want nil when no CABundle is configured", err)
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
		}
		if tr.TLSClientConfig.RootCAs != nil {
			t.Error("RootCAs is set despite no CABundle being configured; want the system pool (nil)")
		}
	})
}

// TestUpgradeReason pins the classification a reconnect metric is labelled
// with.
func TestUpgradeReason(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		resp *http.Response
		err  error
		want grpctun.Reason
	}{
		{name: "caller gave up", ctx: cancelled, err: errors.New("x"), want: grpctun.ReasonContextCancelled},
		{
			name: "something answered",
			ctx:  context.Background(),
			resp: &http.Response{StatusCode: http.StatusNotFound},
			err:  errors.New("x"),
			want: grpctun.ReasonUpgradeRejected,
		},
		{
			name: "the hub certificate did not verify",
			ctx:  context.Background(),
			err:  &tls.CertificateVerificationError{},
			want: grpctun.ReasonTLSHandshake,
		},
		{
			name: "the hub certificate names another host",
			ctx:  context.Background(),
			err:  x509.HostnameError{Host: "hub.example.com"},
			want: grpctun.ReasonTLSHandshake,
		},
		{
			name: "nothing was listening",
			ctx:  context.Background(),
			err:  errors.New("connection refused"),
			want: grpctun.ReasonDial,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := upgradeReason(tc.ctx, tc.resp, tc.err); got != tc.want {
				t.Errorf("upgradeReason() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUpgradeCauseUsesTheActualRequestPath proves the hint names the tunnel
// path that was actually dialled, not always DefaultPath. Every existing
// TestUpgradeFailureHints fixture happens to dial DefaultPath itself, so a
// custom path parsed from the target is indistinguishable from one that fell
// back to the default unless a genuinely different path is used here.
func TestUpgradeCauseUsesTheActualRequestPath(t *testing.T) {
	t.Parallel()

	resp := &http.Response{StatusCode: http.StatusNotFound}
	got := upgradeCause("wss://hub.example.com/pmf/tunnel", resp, errors.New("boom"))
	if !strings.Contains(got.Error(), "/pmf/tunnel") {
		t.Errorf("upgradeCause() = %v, want it to name the actual tunnel path /pmf/tunnel", got)
	}
}

// TestLooksLikeHTML covers the sniffing behind the "an Ingress answered this"
// hint, including a response whose body has already been consumed.
func TestLooksLikeHTML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{
			name: "declared as html",
			resp: &http.Response{Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}},
			want: true,
		},
		{
			name: "body sniffed as html",
			resp: &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("\n<!doctype html>"))},
			want: true,
		},
		{
			name: "json body",
			resp: &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"nope"}`))},
			want: false,
		},
		{name: "no body", resp: &http.Response{Header: http.Header{}}, want: false},
		{
			name: "body already closed",
			resp: &http.Response{Header: http.Header{}, Body: io.NopCloser(errReader{})},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := looksLikeHTML(tc.resp); got != tc.want {
				t.Errorf("looksLikeHTML() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestVerifyTranscriptKeyTypes covers the key algorithms a spoke certificate
// may carry, and the ones it may not.
func TestVerifyTranscriptKeyTypes(t *testing.T) {
	t.Parallel()

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("read nonce: %v", err)
	}

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		leaf := selfSigned(t, key.Public(), key)
		sig, err := certproof.Sign(key, nonce, ProtocolVersion, "prod")
		if err != nil {
			t.Fatalf("certproof.Sign: %v", err)
		}
		if err := certproof.Verify(leaf, sig, nonce, ProtocolVersion, "prod"); err != nil {
			t.Errorf("certproof.Verify() = %v, want nil", err)
		}
		// A signature over a different cluster id must not verify: that binding
		// is the reason the transcript exists.
		if err := certproof.Verify(leaf, sig, nonce, ProtocolVersion, "staging"); !errors.Is(err, ErrBadSignature) {
			t.Errorf("certproof.Verify() over a rescoped transcript = %v, want ErrBadSignature", err)
		}
	})

	t.Run("ed25519 is not supported", func(t *testing.T) {
		t.Parallel()

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519 key: %v", err)
		}
		leaf := selfSigned(t, pub, priv)
		if err := certproof.Verify(leaf, []byte("sig"), nonce, ProtocolVersion, "prod"); !errors.Is(err, ErrBadSignature) {
			t.Errorf("certproof.Verify() = %v, want ErrBadSignature", err)
		}
	})
}

// TestHandshakeMessageFraming covers the length-prefixed envelope's refusals,
// which run before the peer has authenticated and are therefore the first thing
// a hostile connection reaches.
func TestHandshakeMessageFraming(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wire []byte
	}{
		{name: "truncated length", wire: []byte{0, 0}},
		{name: "zero length", wire: []byte{0, 0, 0, 0}},
		{name: "declared larger than the cap", wire: []byte{0xff, 0xff, 0xff, 0xff}},
		{name: "truncated body", wire: []byte{0, 0, 0, 16, 'a', 'b'}},
		{name: "body is not json", wire: []byte{0, 0, 0, 4, 'n', 'o', 'p', 'e'}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var hello serverHello
			if err := readMessage(newSlowReader(tc.wire), &hello); !errors.Is(err, ErrHandshakeFailed) {
				t.Errorf("readMessage() = %v, want ErrHandshakeFailed", err)
			}
		})
	}

	t.Run("write refuses an oversized message", func(t *testing.T) {
		t.Parallel()
		huge := serverHello{Nonce: make([]byte, maxHandshakeBytes)}
		if err := writeMessage(io.Discard, huge); !errors.Is(err, ErrHandshakeFailed) {
			t.Errorf("writeMessage() = %v, want ErrHandshakeFailed", err)
		}
	})

	t.Run("write reports a broken pipe", func(t *testing.T) {
		t.Parallel()
		if err := writeMessage(errWriter{}, serverHello{}); err == nil {
			t.Error("writeMessage() = nil on a dead writer")
		}
	})

	t.Run("write reports an encoding failure", func(t *testing.T) {
		t.Parallel()
		if err := writeMessage(io.Discard, func() {}); err == nil || !strings.Contains(err.Error(), "encode") {
			t.Errorf("writeMessage() = %v, want encoding failure", err)
		}
	})

	t.Run("write reports a broken body write", func(t *testing.T) {
		t.Parallel()
		w := &secondWriteFails{}
		if err := writeMessage(w, serverHello{}); !errors.Is(err, errHandshakeFixture) || w.writes != 2 {
			t.Errorf("writeMessage() = %v after %d writes, want body-write failure", err, w.writes)
		}
	})

	// A message whose encoded length is exactly maxHandshakeBytes is legal;
	// only strictly larger is refused. The oversized fixture above marshals to
	// well past the cap, so it cannot tell ">" from ">=" at the boundary.
	t.Run("write allows a message exactly at the cap", func(t *testing.T) {
		t.Parallel()
		if err := writeMessage(io.Discard, fixedSizeJSONString(maxHandshakeBytes)); err != nil {
			t.Errorf("writeMessage() at exactly the cap = %v, want nil", err)
		}
	})

	// The mirror image on the read side: a declared size exactly at the cap
	// must be accepted, not just one under it.
	t.Run("read allows a declared size exactly at the cap", func(t *testing.T) {
		t.Parallel()
		payload, err := fixedSizeJSONString(maxHandshakeBytes).MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if len(payload) != maxHandshakeBytes {
			t.Fatalf("constructed payload is %d bytes, want %d", len(payload), maxHandshakeBytes)
		}
		var lenPrefix [4]byte
		binary.BigEndian.PutUint32(lenPrefix[:], uint32(len(payload)))
		wire := append(lenPrefix[:], payload...)
		var out string
		if err := readMessage(bytes.NewReader(wire), &out); err != nil {
			t.Errorf("readMessage() at exactly the cap = %v, want nil", err)
		}
	})
}

// fixedSizeJSONString marshals to a JSON string literal of exactly n bytes
// (n-2 filler characters plus the two quotes), so a handshake framing test can
// pin the byte-cap boundary exactly rather than merely "comfortably over it".
type fixedSizeJSONString int

func (n fixedSizeJSONString) MarshalJSON() ([]byte, error) {
	inner := int(n) - 2
	out := make([]byte, 0, n)
	out = append(out, '"')
	out = append(out, bytes.Repeat([]byte("a"), inner)...)
	out = append(out, '"')
	return out, nil
}

// --- helpers -------------------------------------------------------------

func write(t *testing.T, conn net.Conn, v any) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Errorf("set deadline: %v", err)
		return
	}
	if err := writeMessage(conn, v); err != nil {
		t.Errorf("write handshake message: %v", err)
	}
}

func read(t *testing.T, conn net.Conn, v any) {
	t.Helper()
	if err := readMessage(conn, v); err != nil {
		t.Errorf("read handshake message: %v", err)
	}
}

// selfSigned mints a certificate carrying pub, so certproof.Verify has a leaf
// of the right key type to work against.
func selfSigned(t *testing.T, pub, signer any) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "transcript test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// pemEncode renders DER as a PEM certificate block.
func pemEncode(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// errReader stands in for a response body the websocket library already closed.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("body is closed") }

// errWriter fails every write, so writeMessage's error paths are reachable.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// slowReader hands out one byte at a time, so readMessage's io.ReadFull calls
// are exercised across boundaries rather than satisfied in a single read.
type slowReader struct {
	b []byte
	i int
}

func newSlowReader(b []byte) *slowReader { return &slowReader{b: b} }

func (r *slowReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.b[r.i]
	r.i++
	return 1, nil
}
