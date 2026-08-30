// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
)

// trustDomain is the authority component of the URI SANs the throwaway CA
// below issues, mirroring what internal/ca does for real.
const trustDomain = "fleet.test"

// quiet keeps test output readable; the transport logs every refusal.
func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// testCA is a throwaway certificate authority, generated per test.
//
// It is deliberately not internal/ca: what this package needs from an authority
// is a Verify function, and building one here proves the seam is a function
// rather than a dependency on the hub's PKI.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

// newTestCA mints a self-signed root.
func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wstun test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a spoke certificate carrying the URI SAN the identity is read
// from.
func (c *testCA) issue(t *testing.T, clusterID string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate spoke key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: clusterID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "pmf", Host: trustDomain, Path: "/spoke/" + clusterID}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create spoke certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse spoke certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// verify is the ServerConfig.Verify this CA supplies: chain verification plus
// the identity rule, exactly as internal/ca does it for the real fleet.
func (c *testCA) verify(chain []*x509.Certificate) (tunnel.Identity, error) {
	if len(chain) == 0 {
		return tunnel.Identity{}, errors.New("no certificate presented")
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, cert := range chain[1:] {
		inter.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return tunnel.Identity{}, err
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "pmf" || leaf.URIs[0].Host != trustDomain {
		return tunnel.Identity{}, errors.New("certificate carries no spoke identity")
	}
	id, ok := strings.CutPrefix(leaf.URIs[0].Path, "/spoke/")
	if !ok || id == "" {
		return tunnel.Identity{}, errors.New("certificate carries no spoke identity")
	}
	return tunnel.Identity{
		ClusterID:    id,
		CertSerial:   fmt.Sprintf("%x", leaf.SerialNumber),
		CertNotAfter: leaf.NotAfter,
	}, nil
}

// harness is a hub: a wstun.Server mounted at /tunnel on an httptest.Server,
// with its listener already serving.
type harness struct {
	ca       *testCA
	server   *Server
	http     *httptest.Server
	sessions chan tunnel.Session
	serveErr chan error
}

// newHarness stands one up. mutate may adjust the ServerConfig before the
// server is built; Verify and Logger are already set.
func newHarness(t *testing.T, mutate func(*ServerConfig)) *harness {
	t.Helper()

	ca := newTestCA(t)
	// Keepalive is deliberately slack here. The conformance suite runs many
	// parallel subtests in three transport packages at once under -race, and
	// the production 10s/5s ping budget is not survivable on an oversubscribed
	// box — a late ping ACK would fail the test for a reason that has nothing
	// to do with the tunnel contract.
	cfg := ServerConfig{
		Verify:    ca.verify,
		Logger:    quiet(),
		ServerID:  "hub-test-0",
		Keepalive: grpctun.KeepaliveParams{Time: time.Minute, Timeout: 30 * time.Second, PermitWithoutStream: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(DefaultPath, srv.Handler())
	ts := httptest.NewServer(mux)

	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{
		ca:       ca,
		server:   srv,
		http:     ts,
		sessions: make(chan tunnel.Session, 4),
		serveErr: make(chan error, 1),
	}
	go func() {
		h.serveErr <- srv.Listener().Serve(ctx, tunnel.SessionHandlerFunc(
			func(_ context.Context, s tunnel.Session) (func(), error) {
				h.sessions <- s
				return nil, nil
			}))
	}()

	t.Cleanup(func() {
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = srv.Listener().Shutdown(shutCtx)
		<-h.serveErr
		ts.Close()
	})
	return h
}

// wsURL is the tunnel endpoint clients dial.
func (h *harness) wsURL() string {
	return "ws" + strings.TrimPrefix(h.http.URL, "http") + DefaultPath
}

// dial runs the real spoke client in the background and returns the channel its
// error will arrive on.
func (h *harness) dial(t *testing.T, cert tls.Certificate, clusterID string, handler tunnel.Handler) (<-chan error, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Dial(ctx, ClientConfig{
			URL:          h.wsURL(),
			Certificate:  cert,
			ClusterID:    clusterID,
			AgentVersion: "test",
			Logger:       quiet(),
			HTTPClient:   h.http.Client(),
			Generation:   1,
		}, handler)
	}()
	return errCh, cancel
}

// rawConn upgrades without performing the handshake, so a test can send
// whatever it likes.
func (h *harness) rawConn(t *testing.T, subprotocols ...string) net.Conn {
	t.Helper()

	if len(subprotocols) == 0 {
		subprotocols = []string{Subprotocol}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	ws, _, err := websocket.Dial(ctx, h.wsURL(), &websocket.DialOptions{
		HTTPClient:      h.http.Client(),
		Subprotocols:    subprotocols,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		cancel()
		t.Fatalf("raw websocket dial: %v", err)
	}
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	t.Cleanup(func() {
		_ = conn.Close()
		cancel()
	})
	return conn
}

// readHello reads the hub's challenge.
func readHello(t *testing.T, conn net.Conn) serverHello {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var hello serverHello
	if err := readMessage(conn, &hello); err != nil {
		t.Fatalf("read ServerHello: %v", err)
	}
	return hello
}

// readAccept reads the hub's verdict.
func readAccept(t *testing.T, conn net.Conn) serverAccept {
	t.Helper()
	var accept serverAccept
	if err := readMessage(conn, &accept); err != nil {
		t.Fatalf("read ServerAccept: %v", err)
	}
	return accept
}

// signedAuth builds a well-formed ClientAuth over the given nonce.
func signedAuth(t *testing.T, cert tls.Certificate, nonce []byte, clusterID string) clientAuth {
	t.Helper()
	signer, err := signerFor(cert)
	if err != nil {
		t.Fatalf("signerFor: %v", err)
	}
	sig, err := certproof.Sign(signer, nonce, ProtocolVersion, clusterID)
	if err != nil {
		t.Fatalf("certproof.Sign: %v", err)
	}
	return clientAuth{
		Chain:           cert.Certificate,
		Signature:       sig,
		ClusterID:       clusterID,
		ProtocolVersion: ProtocolVersion,
	}
}

// upgradeRequest performs a genuine WebSocket upgrade attempt with the standard
// HTTP client, so a test can inspect a refusal that never became a connection.
func upgradeRequest(t *testing.T, target string, client *http.Client, header http.Header) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}
