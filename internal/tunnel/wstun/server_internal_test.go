// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

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
		if !s.reserveSession() || !s.reserveSession() {
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
