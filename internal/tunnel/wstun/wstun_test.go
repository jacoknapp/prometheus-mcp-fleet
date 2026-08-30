// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
)

// TestConformance runs the shared tunnel contract suite over a real
// httptest.Server. Passing the same suite as memtun and grpctun is the whole
// argument that moving the transport under a WebSocket changed nothing above
// it.
func TestConformance(t *testing.T) {
	t.Parallel()

	tunneltest.RunConformance(t, func(t *testing.T, h tunnel.Handler) (tunnel.Session, func()) {
		t.Helper()

		hub := newHarness(t, nil)
		cert := hub.ca.issue(t, tunneltest.ClusterID)

		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() {
			errCh <- Dial(ctx, ClientConfig{
				URL:         hub.wsURL(),
				Certificate: cert,
				ClusterID:   tunneltest.ClusterID,
				Logger:      quiet(),
				HTTPClient:  hub.http.Client(),
				Generation:  tunneltest.Generation,
			}, h)
		}()

		select {
		case s := <-hub.sessions:
			return s, func() {
				cancel()
				select {
				case <-errCh:
				case <-time.After(15 * time.Second):
					t.Error("the spoke side of the tunnel did not return after cancellation")
				}
			}
		case err := <-errCh:
			cancel()
			t.Fatalf("Dial returned before a session was established: %v", err)
		case <-time.After(20 * time.Second):
			cancel()
			t.Fatal("no tunnel session was established within 20s")
		}
		return nil, func() {}
	})
}

// TestHandshakeRejections covers every way a peer can fail to prove it is a
// spoke. Each case drives the handshake by hand, because the point is to lie
// about a part of it that the real client never would.
func TestHandshakeRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// build produces the ClientAuth to send, given the hub's challenge.
		build func(t *testing.T, h *harness, nonce []byte) clientAuth
		// mutate adjusts the server before it is built.
		mutate func(*ServerConfig)
		// wantReason is a substring of the refusal the hub sends back.
		wantReason string
	}{
		{
			name: "no certificate at all",
			build: func(t *testing.T, h *harness, nonce []byte) clientAuth {
				auth := signedAuth(t, h.ca.issue(t, "prod"), nonce, "prod")
				auth.Chain = nil
				return auth
			},
			wantReason: "not trusted",
		},
		{
			name: "certificate from another authority",
			build: func(t *testing.T, _ *harness, nonce []byte) clientAuth {
				return signedAuth(t, newTestCA(t).issue(t, "prod"), nonce, "prod")
			},
			wantReason: "not trusted",
		},
		{
			name: "unparseable certificate",
			build: func(t *testing.T, h *harness, nonce []byte) clientAuth {
				auth := signedAuth(t, h.ca.issue(t, "prod"), nonce, "prod")
				auth.Chain = [][]byte{[]byte("not DER")}
				return auth
			},
			wantReason: "not trusted",
		},
		{
			name: "revoked serial",
			build: func(t *testing.T, h *harness, nonce []byte) clientAuth {
				return signedAuth(t, h.ca.issue(t, "prod"), nonce, "prod")
			},
			mutate:     func(c *ServerConfig) { c.IsRevoked = func(string) bool { return true } },
			wantReason: "revoked",
		},
		{
			name: "signature over a different nonce",
			build: func(t *testing.T, h *harness, _ []byte) clientAuth {
				return signedAuth(t, h.ca.issue(t, "prod"), bytes.Repeat([]byte{0x11}, nonceLen), "prod")
			},
			wantReason: "signature",
		},
		{
			name: "reported cluster id disagrees with the certificate",
			build: func(t *testing.T, h *harness, nonce []byte) clientAuth {
				// Signed correctly, over the identity the spoke claims — so
				// only the certificate catches it.
				return signedAuth(t, h.ca.issue(t, "prod"), nonce, "staging")
			},
			wantReason: "does not match the certificate",
		},
		{
			name: "incompatible protocol version",
			build: func(t *testing.T, h *harness, nonce []byte) clientAuth {
				auth := signedAuth(t, h.ca.issue(t, "prod"), nonce, "prod")
				auth.ProtocolVersion = "v99"
				return auth
			},
			wantReason: "protocol version",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hub := newHarness(t, tc.mutate)
			conn := hub.rawConn(t)

			hello := readHello(t, conn)
			if len(hello.Nonce) != nonceLen {
				t.Fatalf("nonce is %d bytes, want %d", len(hello.Nonce), nonceLen)
			}
			if hello.ServerID != "hub-test-0" {
				t.Errorf("ServerID = %q, want the configured replica name", hello.ServerID)
			}

			if err := writeMessage(conn, tc.build(t, hub, hello.Nonce)); err != nil {
				t.Fatalf("write ClientAuth: %v", err)
			}
			accept := readAccept(t, conn)
			if accept.Accepted {
				t.Fatal("the hub accepted a peer that should have been refused")
			}
			if !contains(accept.Reason, tc.wantReason) {
				t.Errorf("refusal reason = %q, want it to mention %q", accept.Reason, tc.wantReason)
			}
			if hub.server.Sessions() != 0 {
				t.Errorf("Sessions() = %d after a refused handshake, want 0", hub.server.Sessions())
			}
		})
	}
}

// TestReplayedClientAuthIsRefused proves the nonce does what it is there for: a
// ClientAuth captured from one connection is useless on the next.
func TestReplayedClientAuthIsRefused(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	cert := hub.ca.issue(t, "prod")

	first := hub.rawConn(t)
	firstHello := readHello(t, first)
	captured := signedAuth(t, cert, firstHello.Nonce, "prod")

	// The captured message is genuine: replay it on the original connection and
	// the hub accepts it, which is what makes the second half meaningful.
	if err := writeMessage(first, captured); err != nil {
		t.Fatalf("write ClientAuth: %v", err)
	}
	if accept := readAccept(t, first); !accept.Accepted {
		t.Fatalf("the hub refused a valid handshake: %s", accept.Reason)
	}

	second := hub.rawConn(t)
	secondHello := readHello(t, second)
	if bytes.Equal(firstHello.Nonce, secondHello.Nonce) {
		t.Fatal("the hub reused a nonce across two connections")
	}
	if err := writeMessage(second, captured); err != nil {
		t.Fatalf("write replayed ClientAuth: %v", err)
	}
	accept := readAccept(t, second)
	if accept.Accepted {
		t.Fatal("the hub accepted a replayed ClientAuth against a fresh nonce")
	}
	if !contains(accept.Reason, "signature") {
		t.Errorf("refusal reason = %q, want it to mention the signature", accept.Reason)
	}
}

// TestStalledHandshakeConsumesOnlyAHandshakeSlot asserts that a peer which
// upgrades and then says nothing is bounded by the handshake semaphore, not by
// MaxSessions. If it held a session slot, a flood of silent upgrades would lock
// real spokes out for the whole handshake timeout.
func TestStalledHandshakeConsumesOnlyAHandshakeSlot(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, func(c *ServerConfig) {
		c.HandshakeTimeout = 30 * time.Second
		c.MaxPendingHandshakes = 1
		c.MaxSessions = 4
	})

	stalled := hub.rawConn(t)
	readHello(t, stalled)

	if got := hub.server.Sessions(); got != 0 {
		t.Errorf("Sessions() = %d during an unauthenticated handshake, want 0", got)
	}
	resp := upgradeRequest(t, hub.http.URL+DefaultPath, hub.http.Client(),
		http.Header{"Sec-WebSocket-Protocol": []string{Subprotocol}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second upgrade during a stalled handshake = %d, want 503", resp.StatusCode)
	}
}

// TestStalledHandshakeReleasesItsSlot asserts the timeout actually fires and
// hands the slot back, so the bound above is temporary rather than a wedge.
func TestStalledHandshakeReleasesItsSlot(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, func(c *ServerConfig) {
		c.HandshakeTimeout = 200 * time.Millisecond
		c.MaxPendingHandshakes = 1
	})

	stalled := hub.rawConn(t)
	readHello(t, stalled)

	deadline := time.Now().Add(20 * time.Second)
	for {
		errCh, cancel := hub.dial(t, hub.ca.issue(t, "prod"), "prod", &tunneltest.EchoHandler{})
		select {
		case s := <-hub.sessions:
			if s.Identity().ClusterID != "prod" {
				t.Errorf("ClusterID = %q, want prod", s.Identity().ClusterID)
			}
			cancel()
			<-errCh
			return
		case <-errCh:
			cancel()
			if time.Now().After(deadline) {
				t.Fatal("the handshake slot was never released after the timeout")
			}
			time.Sleep(50 * time.Millisecond)
		case <-time.After(20 * time.Second):
			cancel()
			t.Fatal("neither a session nor an error within 20s")
		}
	}
}

// TestMaxSessionsRefusesBeforeTheUpgrade asserts the cap is applied where it can
// still answer with HTTP. A cap enforced after the upgrade has already paid for
// everything it was meant to prevent.
func TestMaxSessionsRefusesBeforeTheUpgrade(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, func(c *ServerConfig) { c.MaxSessions = 1 })

	errCh, cancel := hub.dial(t, hub.ca.issue(t, "prod"), "prod", &tunneltest.EchoHandler{})
	defer func() { cancel(); <-errCh }()

	select {
	case <-hub.sessions:
	case err := <-errCh:
		t.Fatalf("the first spoke failed to attach: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("the first spoke did not attach within 20s")
	}

	resp := upgradeRequest(t, hub.http.URL+DefaultPath, hub.http.Client(),
		http.Header{"Sec-WebSocket-Protocol": []string{Subprotocol}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second upgrade = %d, want 503", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Error("the hub upgraded a connection it was going to refuse anyway")
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Error("a 503 carries no Retry-After, so a spoke has nothing to back off on")
	}
}

// TestSubprotocolIsRequired covers a peer that did not ask for the tunnel
// subprotocol, and one that asked for something else.
func TestSubprotocolIsRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header http.Header
	}{
		{name: "absent", header: nil},
		{name: "wrong", header: http.Header{"Sec-WebSocket-Protocol": []string{"chat"}}},
		{name: "similar but not ours", header: http.Header{"Sec-WebSocket-Protocol": []string{"pmf.tunnel.v2"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hub := newHarness(t, nil)
			resp := upgradeRequest(t, hub.http.URL+DefaultPath, hub.http.Client(), tc.header)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("upgrade = %d, want 400", resp.StatusCode)
			}
		})
	}
}

// TestSubprotocolIsAcceptedCaseInsensitively guards the header parsing, which
// sees whatever an intermediary chose to rewrite.
func TestSubprotocolIsAcceptedCaseInsensitively(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	resp := upgradeRequest(t, hub.http.URL+DefaultPath, hub.http.Client(),
		http.Header{"Sec-WebSocket-Protocol": []string{"chat, PMF.Tunnel.V1"}})
	if resp.StatusCode == http.StatusBadRequest {
		t.Error("the subprotocol check is case sensitive; RFC 6455 tokens are not")
	}
}

// TestUpgradeFailureHints covers the first-install failure an operator will
// actually hit: an Ingress that is not routing the tunnel path.
func TestUpgradeFailureHints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    []string
	}{
		{
			name:    "not routed at all",
			handler: http.NotFound,
			want:    []string{"404", "Ingress", DefaultPath},
		},
		{
			name: "answered by a web page",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte("<html><body>default backend</body></html>"))
			},
			want: []string{"HTML", "Ingress"},
		},
		{
			name: "answered by something broken",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			},
			want: []string{"502", "101"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewServer(tc.handler)
			t.Cleanup(ts.Close)
			err := Dial(context.Background(), ClientConfig{
				URL:        "ws" + strings.TrimPrefix(ts.URL, "http") + DefaultPath,
				HTTPClient: ts.Client(),
				Logger:     quiet(),
				// A certificate is needed before the handshake but never
				// reaches it: the upgrade fails first.
				Certificate: newTestCA(t).issue(t, "prod"),
				ClusterID:   "prod",
			}, &tunneltest.EchoHandler{})

			if !errors.Is(err, ErrUpgradeRejected) {
				t.Fatalf("error = %v, want it to wrap ErrUpgradeRejected", err)
			}
			var de *grpctun.DialError
			if !errors.As(err, &de) {
				t.Fatalf("error = %v, want a *grpctun.DialError a metric can label", err)
			}
			if de.Reason != grpctun.ReasonUpgradeRejected {
				t.Errorf("Reason = %q, want %q", de.Reason, grpctun.ReasonUpgradeRejected)
			}
			for _, want := range tc.want {
				if !contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestDialClassifiesFailures asserts every early exit still returns something a
// reconnect loop can count.
func TestDialClassifiesFailures(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	valid := hub.ca.issue(t, "prod")

	tests := []struct {
		name    string
		cfg     ClientConfig
		handler tunnel.Handler
		want    grpctun.Reason
	}{
		{
			name:    "nil handler",
			cfg:     ClientConfig{URL: hub.wsURL(), Certificate: valid},
			handler: nil,
			want:    grpctun.ReasonDial,
		},
		{
			name:    "endpoint is not a URL",
			cfg:     ClientConfig{URL: "not a url at all", Certificate: valid},
			handler: &tunneltest.EchoHandler{},
			want:    grpctun.ReasonDial,
		},
		{
			name:    "no certificate has been issued yet",
			cfg:     ClientConfig{URL: hub.wsURL()},
			handler: &tunneltest.EchoHandler{},
			want:    grpctun.ReasonAuthRejected,
		},
		{
			name: "unusable CA bundle",
			cfg: ClientConfig{
				URL:         "wss://hub.invalid/tunnel",
				Certificate: valid,
				CABundle:    []byte("not a PEM bundle"),
			},
			handler: &tunneltest.EchoHandler{},
			want:    grpctun.ReasonDial,
		},
		{
			name:    "nothing listening",
			cfg:     ClientConfig{URL: "ws://127.0.0.1:1/tunnel", Certificate: valid},
			handler: &tunneltest.EchoHandler{},
			want:    grpctun.ReasonDial,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.cfg
			cfg.Logger = quiet()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			err := Dial(ctx, cfg, tc.handler)
			var de *grpctun.DialError
			if !errors.As(err, &de) {
				t.Fatalf("error = %v, want a *grpctun.DialError", err)
			}
			if de.Reason != tc.want {
				t.Errorf("Reason = %q, want %q (error: %v)", de.Reason, tc.want, err)
			}
		})
	}
}

// TestDialRejectionIsClassifiedAsAuth asserts a hub that refuses the identity
// produces the label an operator needs to tell "cannot reach the hub" from
// "the hub will not have me".
func TestDialRejectionIsClassifiedAsAuth(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	foreign := newTestCA(t).issue(t, "prod")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := Dial(ctx, ClientConfig{
		URL:         hub.wsURL(),
		Certificate: foreign,
		ClusterID:   "prod",
		Logger:      quiet(),
		HTTPClient:  hub.http.Client(),
	}, &tunneltest.EchoHandler{})

	var de *grpctun.DialError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want a *grpctun.DialError", err)
	}
	if de.Reason != grpctun.ReasonAuthRejected {
		t.Errorf("Reason = %q, want %q", de.Reason, grpctun.ReasonAuthRejected)
	}
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("error = %v, want it to wrap ErrHandshakeFailed", err)
	}
}

// TestSessionIdentityComesFromTheCertificate asserts the hub reports what the
// certificate says, not what the spoke claims, including the audit address.
func TestSessionIdentityComesFromTheCertificate(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	cert := hub.ca.issue(t, "prod")
	errCh, cancel := hub.dial(t, cert, "prod", &tunneltest.EchoHandler{})
	defer func() { cancel(); <-errCh }()

	select {
	case s := <-hub.sessions:
		id := s.Identity()
		if id.ClusterID != "prod" {
			t.Errorf("ClusterID = %q, want prod", id.ClusterID)
		}
		if id.CertSerial == "" {
			t.Error("CertSerial is empty; the audit log has nothing to record")
		}
		if id.CertNotAfter.IsZero() {
			t.Error("CertNotAfter is zero")
		}
		if id.RemoteAddr == "" {
			t.Error("RemoteAddr is empty")
		}
		if hub.server.Sessions() != 1 {
			t.Errorf("Sessions() = %d, want 1", hub.server.Sessions())
		}
	case err := <-errCh:
		t.Fatalf("Dial returned before a session: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("no session within 20s")
	}
}

// TestServerRejectsBadConfig covers the constructor's own guards.
func TestServerRejectsBadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  ServerConfig
	}{
		{name: "no verifier", cfg: ServerConfig{}},
		{
			name: "negative session cap",
			cfg:  ServerConfig{Verify: newTestCA(t).verify, MaxSessions: -1},
		},
		{
			name: "negative handshake cap",
			cfg:  ServerConfig{Verify: newTestCA(t).verify, MaxPendingHandshakes: -1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewServer(tc.cfg); err == nil {
				t.Fatal("NewServer accepted a configuration it should have refused")
			}
		})
	}
}

// TestListenerAddrNamesTheMountPoint keeps readiness logs useful now that there
// is no bound socket to report.
func TestListenerAddrNamesTheMountPoint(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(ServerConfig{Verify: newTestCA(t).verify, Logger: quiet(), Path: "/pmf/tunnel"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := srv.Listener().Addr(); !contains(got, "/pmf/tunnel") {
		t.Errorf("Addr() = %q, want it to name the mount point", got)
	}
}

// TestListenerShutdownStopsAdoption asserts a handshake that completes after
// shutdown is closed rather than left hanging.
func TestListenerShutdownStopsAdoption(t *testing.T) {
	t.Parallel()

	hub := newHarness(t, nil)
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := hub.server.Listener().Shutdown(shutCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-hub.serveErr; !errors.Is(err, grpctun.ErrListenerClosed) {
		t.Errorf("Serve() = %v, want ErrListenerClosed", err)
	}
	// Put it back so the harness cleanup has something to drain.
	hub.serveErr <- nil

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := Dial(ctx, ClientConfig{
		URL:         hub.wsURL(),
		Certificate: hub.ca.issue(t, "prod"),
		ClusterID:   "prod",
		Logger:      quiet(),
		HTTPClient:  hub.http.Client(),
	}, &tunneltest.EchoHandler{})
	if err == nil {
		t.Fatal("Dial succeeded against a listener that had been shut down")
	}
}

// contains is strings.Contains, named for readability in the assertions above.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
