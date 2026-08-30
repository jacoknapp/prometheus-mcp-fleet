// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// TestRemoteAddr covers the audit address, which comes from a header an ingress
// sets and is therefore never allowed to influence anything but a log line.
func TestRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remote     string
		forwarded  string
		wantResult string
	}{
		{name: "no header", remote: "10.0.0.1:5555", wantResult: "10.0.0.1:5555"},
		{name: "single hop", remote: "10.0.0.1:5555", forwarded: "203.0.113.7", wantResult: "203.0.113.7"},
		{
			name:       "first entry of a chain",
			remote:     "10.0.0.1:5555",
			forwarded:  "203.0.113.7, 10.0.0.9, 10.0.0.1",
			wantResult: "203.0.113.7",
		},
		{name: "padded", remote: "10.0.0.1:5555", forwarded: "  198.51.100.4  ", wantResult: "198.51.100.4"},
		{name: "empty header falls back", remote: "10.0.0.1:5555", forwarded: " , ", wantResult: "10.0.0.1:5555"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/tunnel", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			r.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			if got := remoteAddr(r); got != tc.wantResult {
				t.Errorf("remoteAddr() = %q, want %q", got, tc.wantResult)
			}
		})
	}
}

// TestRejectionReason keeps the refusal a spoke is told mapped to the category
// it can act on.
func TestRejectionReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "revoked", err: fmt.Errorf("%w: serial ab", ErrRevoked), want: "certificate has been revoked"},
		{name: "mismatch", err: fmt.Errorf("%w: x", ErrClusterMismatch), want: "reported cluster id does not match the certificate"},
		{name: "signature", err: ErrBadSignature, want: "signature does not verify"},
		{name: "untrusted", err: fmt.Errorf("%w: x", ErrUntrustedCertificate), want: "certificate is not trusted by this hub"},
		{name: "version", err: fmt.Errorf("%w: x", ErrProtocolVersion), want: "incompatible tunnel protocol version"},
		{name: "anything else", err: errors.New("boom"), want: "handshake failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := rejectionReason(tc.err); got != tc.want {
				t.Errorf("rejectionReason() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReserveSession covers the cap that decides, as opposed to the advisory
// pre-upgrade read.
func TestReserveSession(t *testing.T) {
	t.Parallel()

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()
		s := &Server{}
		for i := range 3 {
			if !s.reserveSession() {
				t.Fatalf("reserveSession() refused at %d with no cap configured", i)
			}
		}
		if s.atSessionLimit() {
			t.Error("atSessionLimit() = true with no cap configured")
		}
	})

	t.Run("capped", func(t *testing.T) {
		t.Parallel()
		s := &Server{cfg: ServerConfig{MaxSessions: 2}}
		// Both calls must run: || would short-circuit and reserve only one.
		first, second := s.reserveSession(), s.reserveSession()
		if !first || !second {
			t.Fatal("reserveSession() refused inside the cap")
		}
		if !s.atSessionLimit() {
			t.Error("atSessionLimit() = false at the cap")
		}
		if s.reserveSession() {
			t.Error("reserveSession() = true beyond the cap")
		}
		s.sessions.Add(-1)
		if !s.reserveSession() {
			t.Error("reserveSession() = false after a slot was released")
		}
	})
}

func TestNewServerUsesDefaultLogger(t *testing.T) {
	t.Parallel()
	s, err := NewServer(ServerConfig{Verify: newTestCA(t).verify})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.log == nil {
		t.Error("NewServer left the logger nil")
	}
}

// TestConnSourceAccept covers the seam's own lifecycle, which the HTTP handler
// depends on but does not exercise on its unhappy paths.
func TestConnSourceAccept(t *testing.T) {
	t.Parallel()

	t.Run("cancelled caller", func(t *testing.T) {
		t.Parallel()
		src := newConnSource("test")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := src.Accept(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("Accept() = %v, want context.Canceled", err)
		}
	})

	t.Run("closed source", func(t *testing.T) {
		t.Parallel()
		src := newConnSource("test")
		if err := src.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		// Close is idempotent: Shutdown calls it and so may the handler.
		if err := src.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if _, _, err := src.Accept(context.Background()); !errors.Is(err, ErrServerClosed) {
			t.Errorf("Accept() = %v, want ErrServerClosed", err)
		}
		if err := src.offer(context.Background(), &adoption{}); !errors.Is(err, ErrServerClosed) {
			t.Errorf("offer() = %v, want ErrServerClosed", err)
		}
	})

	t.Run("nobody is serving", func(t *testing.T) {
		t.Parallel()
		src := newConnSource("test")
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := src.offer(ctx, &adoption{})
		if !errors.Is(err, ErrServerClosed) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("offer() = %v, want an ErrServerClosed wrapping a deadline", err)
		}
	})

	t.Run("handoff", func(t *testing.T) {
		t.Parallel()
		src := newConnSource("test")
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })

		go func() {
			_ = src.offer(context.Background(), &adoption{
				conn: local,
				id:   tunnel.Identity{ClusterID: "prod"},
			})
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, id, err := src.Accept(ctx)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if conn != local {
			t.Error("Accept returned a different connection than was offered")
		}
		if id.ClusterID != "prod" {
			t.Errorf("ClusterID = %q, want prod", id.ClusterID)
		}
		if got := src.Addr(); got != "test" {
			t.Errorf("Addr() = %q, want test", got)
		}
	})
}

// TestSessionConnCloseIsIdempotent guards the signal that lets the HTTP handler
// return: closing twice must not panic on a closed channel.
func TestSessionConnCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })

	done := make(chan struct{})
	c := &sessionConn{Conn: local, done: done}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = c.Close()

	select {
	case <-done:
	default:
		t.Error("Close did not signal the handler that the session had ended")
	}
}

// TestRequestsSubprotocol covers the header parsing that decides whether a peer
// is one of ours before anything is upgraded.
func TestRequestsSubprotocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent", values: nil, want: false},
		{name: "exact", values: []string{Subprotocol}, want: true},
		{name: "in a list", values: []string{"chat, " + Subprotocol}, want: true},
		{name: "across headers", values: []string{"chat", Subprotocol}, want: true},
		{name: "case insensitive", values: []string{"PMF.TUNNEL.V1"}, want: true},
		{name: "another version", values: []string{"pmf.tunnel.v2"}, want: false},
		{name: "prefix only", values: []string{"pmf.tunnel"}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/tunnel", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			for _, v := range tc.values {
				r.Header.Add("Sec-WebSocket-Protocol", v)
			}
			if got := requestsSubprotocol(r); got != tc.want {
				t.Errorf("requestsSubprotocol(%q) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

// TestAuthenticateOverAPipe drives the hub half directly, so the paths that a
// real client cannot reach — a dead connection mid-exchange — are covered.
func TestAuthenticateOverAPipe(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	srv, err := NewServer(ServerConfig{Verify: ca.verify, Logger: quiet()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	t.Run("peer hangs up before the hello lands", func(t *testing.T) {
		t.Parallel()
		hub, peer := net.Pipe()
		_ = peer.Close()
		if _, err := srv.authenticate(hub, "10.0.0.1:1"); err == nil {
			t.Error("authenticate() = nil against a dead connection")
		}
	})

	t.Run("connection refuses the hello", func(t *testing.T) {
		t.Parallel()
		hub, peer := net.Pipe()
		defer hub.Close()
		defer peer.Close()
		if _, err := srv.authenticate(writeFailConn{Conn: hub}, "10.0.0.1:1"); !errors.Is(err, ErrHandshakeFailed) || !errors.Is(err, errHandshakeFixture) {
			t.Errorf("authenticate() = %v, want hello-write failure", err)
		}
	})

	t.Run("connection refuses the handshake deadline", func(t *testing.T) {
		t.Parallel()
		hub, peer := net.Pipe()
		defer hub.Close()
		defer peer.Close()
		if _, err := srv.authenticate(deadlineConn{Conn: hub, failAll: true}, "10.0.0.1:1"); !errors.Is(err, ErrHandshakeFailed) || !errors.Is(err, errHandshakeFixture) {
			t.Errorf("authenticate() = %v, want handshake/deadline failure", err)
		}
	})

	t.Run("entropy source fails", func(t *testing.T) {
		t.Parallel()
		broken, err := NewServer(ServerConfig{Verify: ca.verify, Logger: quiet()})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		broken.rand = fixtureErrorReader{}
		hub, peer := net.Pipe()
		defer hub.Close()
		defer peer.Close()
		if _, err := broken.authenticate(hub, "10.0.0.1:1"); !errors.Is(err, ErrHandshakeFailed) || !errors.Is(err, errHandshakeFixture) {
			t.Errorf("authenticate() = %v, want entropy failure", err)
		}
	})

	t.Run("peer stalls after the hello", func(t *testing.T) {
		t.Parallel()
		short, err := NewServer(ServerConfig{
			Verify:           ca.verify,
			Logger:           quiet(),
			HandshakeTimeout: 100 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		hub, peer := net.Pipe()
		t.Cleanup(func() { _ = hub.Close(); _ = peer.Close() })

		go func() {
			var hello serverHello
			_ = readMessage(peer, &hello)
			// ...and then nothing.
		}()
		if _, err := short.authenticate(hub, "10.0.0.1:1"); err == nil {
			t.Error("authenticate() = nil against a peer that never answered")
		}
	})

	t.Run("accepted", func(t *testing.T) {
		t.Parallel()
		hub, peer := net.Pipe()
		t.Cleanup(func() { _ = hub.Close(); _ = peer.Close() })

		cert := ca.issue(t, "prod")
		go func() {
			if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return
			}
			var hello serverHello
			if err := readMessage(peer, &hello); err != nil {
				return
			}
			_ = writeMessage(peer, signedAuth(t, cert, hello.Nonce, "prod"))
		}()

		id, err := srv.authenticate(hub, "203.0.113.7")
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if id.ClusterID != "prod" {
			t.Errorf("ClusterID = %q, want prod", id.ClusterID)
		}
		if id.RemoteAddr != "203.0.113.7" {
			t.Errorf("RemoteAddr = %q, want the forwarded address", id.RemoteAddr)
		}
	})

	t.Run("verifier that reports no serial still yields an auditable identity", func(t *testing.T) {
		t.Parallel()

		bare, err := NewServer(ServerConfig{
			Logger: quiet(),
			Verify: func(chain []*x509.Certificate) (tunnel.Identity, error) {
				id, verr := ca.verify(chain)
				// A verifier is only contractually required to name the
				// cluster; the transport fills the rest in from the leaf.
				return tunnel.Identity{ClusterID: id.ClusterID}, verr
			},
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}

		hub, peer := net.Pipe()
		t.Cleanup(func() { _ = hub.Close(); _ = peer.Close() })
		cert := ca.issue(t, "prod")
		go func() {
			var hello serverHello
			if err := readMessage(peer, &hello); err != nil {
				return
			}
			_ = writeMessage(peer, signedAuth(t, cert, hello.Nonce, "prod"))
		}()

		id, err := bare.authenticate(hub, "10.0.0.1:1")
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if id.CertSerial == "" || id.CertNotAfter.IsZero() {
			t.Errorf("identity = %+v, want the serial and expiry filled in from the leaf", id)
		}
	})
}

// TestServeHTTPRareRefusals covers the upgrade and atomic-cap failures that do
// not require a complete gRPC session.
func TestServeHTTPRareRefusals(t *testing.T) {
	ca := newTestCA(t)

	t.Run("malformed upgrade", func(t *testing.T) {
		srv, err := NewServer(ServerConfig{Verify: ca.verify, Logger: quiet()})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, DefaultPath, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Sec-WebSocket-Protocol", Subprotocol)
		rw := &recordingResponseWriter{header: make(http.Header)}
		srv.serveHTTP(rw, req)
		if rw.status == 0 || rw.status == http.StatusSwitchingProtocols {
			t.Errorf("status = %d, want an upgrade refusal", rw.status)
		}
	})

	t.Run("session fills while peer authenticates", func(t *testing.T) {
		var srv *Server
		verify := func(chain []*x509.Certificate) (tunnel.Identity, error) {
			id, err := ca.verify(chain)
			if err == nil {
				srv.sessions.Store(1)
			}
			return id, err
		}
		var err error
		srv, err = NewServer(ServerConfig{Verify: verify, Logger: quiet(), MaxSessions: 1})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), &websocket.DialOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			t.Fatalf("websocket dial: %v", err)
		}
		conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		defer conn.Close()
		hello := readHello(t, conn)
		cert := ca.issue(t, "prod")
		if err := writeMessage(conn, signedAuth(t, cert, hello.Nonce, "prod")); err != nil {
			t.Fatalf("write ClientAuth: %v", err)
		}
		accept := readAccept(t, conn)
		if accept.Accepted || !strings.Contains(accept.Reason, "session limit") {
			t.Errorf("ServerAccept = %+v, want session-limit refusal", accept)
		}
	})

	t.Run("peer closes before accepted verdict", func(t *testing.T) {
		verified := make(chan struct{})
		release := make(chan struct{})
		verify := func(chain []*x509.Certificate) (tunnel.Identity, error) {
			id, err := ca.verify(chain)
			close(verified)
			<-release
			return id, err
		}
		srv, err := NewServer(ServerConfig{Verify: verify, Logger: quiet()})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), &websocket.DialOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			t.Fatalf("websocket dial: %v", err)
		}
		conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		hello := readHello(t, conn)
		cert := ca.issue(t, "prod")
		if err := writeMessage(conn, signedAuth(t, cert, hello.Nonce, "prod")); err != nil {
			t.Fatalf("write ClientAuth: %v", err)
		}
		<-verified
		ws.CloseNow()
		close(release)
		deadline := time.Now().Add(time.Second)
		for srv.sessions.Load() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := srv.sessions.Load(); got != 0 {
			t.Errorf("live session count = %d after failed verdict write, want 0", got)
		}
	})
}

// recordingResponseWriter intentionally lacks http.Hijacker, making a
// WebSocket upgrade fail after the handler's own preflight checks pass.
type recordingResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

type fixtureErrorReader struct{}

func (fixtureErrorReader) Read([]byte) (int, error) { return 0, errHandshakeFixture }

type writeFailConn struct{ net.Conn }

func (writeFailConn) Write([]byte) (int, error) { return 0, errHandshakeFixture }

func (w *recordingResponseWriter) Header() http.Header    { return w.header }
func (w *recordingResponseWriter) WriteHeader(status int) { w.status = status }
func (w *recordingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
