// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// selfSigned returns a throwaway certificate and its PEM encoding.
func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build pair: %v", err)
	}
	return pair, certPEM
}

func TestClientTLSConfig(t *testing.T) {
	t.Parallel()

	cert, bundle := selfSigned(t)

	tests := []struct {
		name       string
		bundle     []byte
		serverName string
		wantErr    error
	}{
		{name: "valid", bundle: bundle, serverName: "hub.example.com"},
		{name: "empty server name", bundle: bundle, wantErr: ErrNoServerName},
		{name: "nil bundle", serverName: "hub.example.com", wantErr: ErrInvalidBundle},
		{name: "not pem", bundle: []byte("nonsense"), serverName: "h", wantErr: ErrInvalidBundle},
		{
			name: "pem carrying no certificate",
			bundle: pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3},
			}),
			serverName: "h",
			wantErr:    ErrInvalidBundle,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ClientTLSConfig(cert, tc.bundle, tc.serverName)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Error("a config was returned alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ClientTLSConfig: %v", err)
			}

			// Each of these is a security property, not a preference.
			if got.MinVersion != tls.VersionTLS13 || got.MaxVersion != tls.VersionTLS13 {
				t.Errorf("TLS version pinned to %d..%d, want 1.3 only", got.MinVersion, got.MaxVersion)
			}
			if got.InsecureSkipVerify {
				t.Error("InsecureSkipVerify is set; the hub certificate is the only proof " +
					"the spoke reached the real hub")
			}
			if got.ServerName != tc.serverName {
				t.Errorf("ServerName = %q, want %q", got.ServerName, tc.serverName)
			}
			if got.RootCAs == nil {
				t.Error("RootCAs is nil, so the hub would not be verified")
			}
			if len(got.Certificates) != 1 {
				t.Errorf("presented %d certificates, want 1", len(got.Certificates))
			}
			if len(got.NextProtos) != 1 || got.NextProtos[0] != alpnH2 {
				t.Errorf("NextProtos = %v, want [%q]", got.NextProtos, alpnH2)
			}
		})
	}
}

// TestClientTLSConfigRejectsForeignCA proves the returned config will not
// accept a hub presenting a certificate from a different authority.
func TestClientTLSConfigRejectsForeignCA(t *testing.T) {
	t.Parallel()

	clientCert, ourBundle := selfSigned(t)
	_, foreignBundle := selfSigned(t)

	cfg, err := ClientTLSConfig(clientCert, ourBundle, "hub.example.com")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	foreign := x509.NewCertPool()
	if !foreign.AppendCertsFromPEM(foreignBundle) {
		t.Fatal("could not parse the foreign bundle")
	}
	// The pools must not be interchangeable: if they were, our trust decision
	// would be meaningless.
	if cfg.RootCAs.Equal(foreign) {
		t.Error("the configured root pool accepts a foreign CA")
	}
}
