// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mtls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// handshakeResult carries both ends' view of one net.Pipe TLS handshake.
type handshakeResult struct {
	serverErr   error
	clientErr   error
	serverState tls.ConnectionState
	clientState tls.ConnectionState
}

// doHandshake runs a full TLS handshake between two crypto/tls endpoints over
// net.Pipe. The server writes one byte afterwards and the client reads it, so
// that a server-side alert raised after the client's flight is drained instead
// of deadlocking the unbuffered pipe.
func doHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) handshakeResult {
	t.Helper()

	sConn, cConn := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	_ = sConn.SetDeadline(deadline)
	_ = cConn.SetDeadline(deadline)
	t.Cleanup(func() {
		_ = sConn.Close()
		_ = cConn.Close()
	})

	srv := tls.Server(sConn, serverCfg)
	cli := tls.Client(cConn, clientCfg)

	var (
		res handshakeResult
		wg  sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		res.serverErr = srv.HandshakeContext(context.Background())
		if res.serverErr == nil {
			res.serverState = srv.ConnectionState()
			_, res.serverErr = srv.Write([]byte{'k'})
		}
		_ = sConn.Close()
	}()
	go func() {
		defer wg.Done()
		res.clientErr = cli.HandshakeContext(context.Background())
		if res.clientErr == nil {
			res.clientState = cli.ConnectionState()
			buf := make([]byte, 1)
			if _, err := cli.Read(buf); err != nil {
				res.clientErr = err
			}
		}
		_ = cConn.Close()
	}()
	wg.Wait()
	return res
}

// tunnelPair builds a CA, a hub server certificate and a spoke client
// certificate for clusterID.
func tunnelPair(t *testing.T, opts Options, clusterID string) (*CA, tls.Certificate, tls.Certificate) {
	t.Helper()
	c := mustCA(t, opts)
	serverCert, err := c.IssueServer([]string{"hub.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	return c, serverCert, spokeCert(t, c, clusterID)
}

// spokeCert mints a client certificate and pairs it with its key.
func spokeCert(t *testing.T, c *CA, clusterID string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	csrDER := newCSR(t, key, csrOptions{})
	_, cert, err := c.IssueSpokeFromCSR(csrDER, clusterID)
	if err != nil {
		t.Fatalf("IssueSpokeFromCSR: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

func TestServerTLSConfigShape(t *testing.T) {
	t.Parallel()

	c, serverCert, _ := tunnelPair(t, Options{}, "prod")
	cfg := c.ServerTLSConfig(serverCert, nil)

	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("versions = %x..%x, want TLS 1.3 only", cfg.MinVersion, cfg.MaxVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if diff := cmp.Diff([]string{"h2"}, cfg.NextProtos); diff != "" {
		t.Errorf("NextProtos (-want +got):\n%s", diff)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate is nil")
	}
	// The hook must refuse a call with no verified chain rather than
	// dereferencing into it.
	if err := cfg.VerifyPeerCertificate(nil, nil); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("empty chain: got %v, want ErrNoIdentity", err)
	}
	if err := cfg.VerifyPeerCertificate(nil, [][]*x509.Certificate{{}}); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("empty chain element: got %v, want ErrNoIdentity", err)
	}
}

func TestClientTLSConfigShape(t *testing.T) {
	t.Parallel()

	c, _, clientCert := tunnelPair(t, Options{}, "prod")
	cfg, err := mtls.ClientTLSConfig(clientCert, c.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("versions = %x..%x, want TLS 1.3 only", cfg.MinVersion, cfg.MaxVersion)
	}
	if cfg.ServerName != "hub.test" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set")
	}
	if diff := cmp.Diff([]string{"h2"}, cfg.NextProtos); diff != "" {
		t.Errorf("NextProtos (-want +got):\n%s", diff)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil")
	}
}

func TestClientTLSConfigErrors(t *testing.T) {
	t.Parallel()

	c, _, clientCert := tunnelPair(t, Options{}, "prod")

	tests := []struct {
		name       string
		bundle     []byte
		serverName string
		wantErr    error
	}{
		{name: "ok", bundle: c.BundlePEM(), serverName: "hub.test"},
		{name: "empty server name", bundle: c.BundlePEM(), wantErr: mtls.ErrNoServerName},
		{name: "nil bundle", serverName: "hub.test", wantErr: mtls.ErrInvalidBundle},
		{name: "garbage bundle", bundle: []byte("not pem"), serverName: "hub.test", wantErr: mtls.ErrInvalidBundle},
		{
			name:       "pem without certificates",
			bundle:     pemBlock("PRIVATE KEY", []byte{1, 2, 3}),
			serverName: "hub.test",
			wantErr:    mtls.ErrInvalidBundle,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := mtls.ClientTLSConfig(clientCert, tc.bundle, tc.serverName)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Error("a config was returned alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHandshakeSucceedsAndCarriesIdentity(t *testing.T) {
	t.Parallel()

	c, serverCert, clientCert := tunnelPair(t, Options{TrustDomain: "fleet.local"}, "prod-us-east-1")
	clientCfg, err := mtls.ClientTLSConfig(clientCert, c.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatal(err)
	}
	res := doHandshake(t, c.ServerTLSConfig(serverCert, nil), clientCfg)
	if res.serverErr != nil {
		t.Fatalf("server handshake: %v", res.serverErr)
	}
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
	if res.serverState.Version != tls.VersionTLS13 {
		t.Errorf("negotiated version = %x, want TLS 1.3", res.serverState.Version)
	}
	if res.serverState.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN = %q, want h2", res.serverState.NegotiatedProtocol)
	}
	if len(res.serverState.PeerCertificates) == 0 {
		t.Fatal("server saw no peer certificate")
	}
	id, err := c.IdentityFromCert(res.serverState.PeerCertificates[0])
	if err != nil {
		t.Fatalf("IdentityFromCert: %v", err)
	}
	if id.ClusterID != "prod-us-east-1" {
		t.Errorf("ClusterID = %q", id.ClusterID)
	}
}

func TestHandshakeRejectsForeignCA(t *testing.T) {
	t.Parallel()

	hub, serverCert, _ := tunnelPair(t, Options{TrustDomain: "fleet.local"}, "prod")
	// A second CA with the same trust domain: the URI SAN looks perfect, only
	// the signature is wrong. Chain verification must still refuse it.
	rogue := mustCA(t, Options{TrustDomain: "fleet.local"})
	rogueClient := spokeCert(t, rogue, "prod")

	clientCfg, err := mtls.ClientTLSConfig(rogueClient, hub.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatal(err)
	}
	res := doHandshake(t, hub.ServerTLSConfig(serverCert, nil), clientCfg)
	if res.serverErr == nil {
		t.Fatal("server accepted a certificate from a foreign CA")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(res.serverErr, &unknown) {
		t.Errorf("server error = %v, want an unknown-authority error", res.serverErr)
	}
	if res.clientErr == nil {
		t.Error("client did not observe the rejection")
	}
}

func TestHandshakeRejectsRevokedSerial(t *testing.T) {
	t.Parallel()

	c, serverCert, clientCert := tunnelPair(t, Options{TrustDomain: "fleet.local"}, "prod")
	revoked := SerialHex(clientCert.Leaf.SerialNumber)

	var (
		mu      sync.Mutex
		queried []string
	)
	isRevoked := func(serial string) bool {
		mu.Lock()
		defer mu.Unlock()
		queried = append(queried, serial)
		return serial == revoked
	}

	clientCfg, err := mtls.ClientTLSConfig(clientCert, c.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatal(err)
	}
	res := doHandshake(t, c.ServerTLSConfig(serverCert, isRevoked), clientCfg)
	if !errors.Is(res.serverErr, ErrCertRevoked) {
		t.Fatalf("server error = %v, want ErrCertRevoked", res.serverErr)
	}
	// Scope the lock: isRevoked takes it too, and holding it past this point
	// would deadlock the second handshake below.
	mu.Lock()
	seen := append([]string(nil), queried...)
	mu.Unlock()
	if diff := cmp.Diff([]string{revoked}, seen); diff != "" {
		t.Errorf("revocation lookups (-want +got):\n%s", diff)
	}

	// The same predicate must let a different, unrevoked spoke through.
	other := spokeCert(t, c, "staging")
	otherCfg, err := mtls.ClientTLSConfig(other, c.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatal(err)
	}
	res = doHandshake(t, c.ServerTLSConfig(serverCert, isRevoked), otherCfg)
	if res.serverErr != nil {
		t.Errorf("unrevoked spoke was rejected: %v", res.serverErr)
	}
}

func TestHandshakeRejectsCertificateWithoutIdentity(t *testing.T) {
	t.Parallel()

	c, serverCert, _ := tunnelPair(t, Options{TrustDomain: "fleet.local"}, "prod")
	// A certificate this CA signed, that chains perfectly, but carries no URI
	// SAN. It must not be able to open a tunnel with an empty cluster ID.
	key := newKey(t)
	der, leaf, err := c.sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "spoke:prod"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, key.Public(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := mtls.ClientTLSConfig(
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		c.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatal(err)
	}
	res := doHandshake(t, c.ServerTLSConfig(serverCert, nil), clientCfg)
	if !errors.Is(res.serverErr, ErrNoIdentity) {
		t.Fatalf("server error = %v, want ErrNoIdentity", res.serverErr)
	}
}

func TestHandshakeRequiresClientCertificate(t *testing.T) {
	t.Parallel()

	c, serverCert, _ := tunnelPair(t, Options{}, "prod")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.BundlePEM()) {
		t.Fatal("bad bundle")
	}
	clientCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "hub.test",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}
	res := doHandshake(t, c.ServerTLSConfig(serverCert, nil), clientCfg)
	if res.serverErr == nil {
		t.Fatal("server accepted an anonymous client")
	}
}

func TestHandshakeRejectsExpiredClientCertificate(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	c, serverCert, clientCert := tunnelPair(t, Options{
		TrustDomain:   "fleet.local",
		CATTL:         365 * 24 * time.Hour,
		SpokeCertTTL:  time.Hour,
		ServerCertTTL: 365 * 24 * time.Hour,
		Clock:         clock.Now,
	}, "prod")

	clientCfg, err := mtls.ClientTLSConfig(clientCert, c.BundlePEM(), "hub.test")
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.Time = clock.Now

	if res := doHandshake(t, c.ServerTLSConfig(serverCert, nil), clientCfg); res.serverErr != nil {
		t.Fatalf("handshake before expiry: %v", res.serverErr)
	}

	clock.Advance(time.Hour + time.Second)
	res := doHandshake(t, c.ServerTLSConfig(serverCert, nil), clientCfg)
	if res.serverErr == nil {
		t.Fatal("server accepted an expired client certificate")
	}
	var invalid x509.CertificateInvalidError
	if !errors.As(res.serverErr, &invalid) || invalid.Reason != x509.Expired {
		t.Errorf("server error = %v, want an expiry error", res.serverErr)
	}
}

func TestHandshakeClientRejectsWrongServerName(t *testing.T) {
	t.Parallel()

	c, serverCert, clientCert := tunnelPair(t, Options{}, "prod")
	clientCfg, err := mtls.ClientTLSConfig(clientCert, c.BundlePEM(), "not-the-hub.test")
	if err != nil {
		t.Fatal(err)
	}
	res := doHandshake(t, c.ServerTLSConfig(serverCert, nil), clientCfg)
	if res.clientErr == nil {
		t.Fatal("client accepted a certificate for the wrong name")
	}
}
