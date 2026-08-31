// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testTime is the instant every fake clock in this package starts at. It is
// far from any daylight-saving or leap boundary and comfortably inside the
// validity of anything the tests mint.
var testTime = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

// fakeClock is a manually advanced clock safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// paths returns a fresh certificate and key path inside a per-test directory.
func paths(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
}

// mustCA creates a CA in a fresh directory.
func mustCA(t *testing.T, opts Options) *CA {
	t.Helper()
	certPath, keyPath := paths(t)
	c, err := Create(certPath, keyPath, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return c
}

// newKey returns a fresh P-256 key.
func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// certWithoutIdentity returns a valid client certificate from c that carries
// no URI SAN. It is useful for proving chain validity alone cannot establish a
// fleet identity.
func certWithoutIdentity(t *testing.T, c *CA) *x509.Certificate {
	t.Helper()
	_, leaf, err := c.sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "identity-less client"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, newKey(t).Public(), DefaultSpokeCertTTL)
	if err != nil {
		t.Fatalf("sign identity-less certificate: %v", err)
	}
	return leaf
}

// intermediateSignedSpokeCert mints a fresh intermediate CA certificate
// (itself signed by authority) and then uses that intermediate, not
// authority, to sign a spoke leaf for clusterID. The leaf's issuer is
// therefore the intermediate rather than the root.
//
// authority's root has MaxPathLen 0 (see ca.go), so a chain running through
// this intermediate can never fully verify in this fleet. The pair exists to
// let a test tell apart *why* verification fails: whether the intermediate
// reached the verifier as an offered intermediate (and was rejected only for
// exceeding the path length) or never reached it at all (no path to any root
// found).
func intermediateSignedSpokeCert(t *testing.T, authority *CA, clusterID string) (leaf, intermediate *x509.Certificate) {
	t.Helper()
	interKey := newKey(t)
	_, interCert, err := authority.sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "intermediate"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, interKey.Public(), DefaultSpokeCertTTL)
	if err != nil {
		t.Fatalf("sign intermediate: %v", err)
	}

	leafKey := newKey(t)
	now := authority.now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spoke:" + clusterID},
		URIs:                  []*url.URL{authority.SpokeURI(clusterID)},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, interCert, leafKey.Public(), interKey)
	if err != nil {
		t.Fatalf("create leaf signed by intermediate: %v", err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf signed by intermediate: %v", err)
	}
	return leaf, interCert
}

func issuedSpokeCert(t *testing.T, c *CA, clusterID string) *x509.Certificate {
	t.Helper()
	key := newKey(t)
	csrDER := newCSR(t, key, csrOptions{})
	_, cert, err := c.IssueSpokeFromCSR(csrDER, clusterID)
	if err != nil {
		t.Fatalf("IssueSpokeFromCSR: %v", err)
	}
	return cert
}

// csrOptions describes what a test CSR should claim. Every field here is
// something the CA must ignore.
type csrOptions struct {
	subject pkix.Name
	dns     []string
	uris    []*url.URL
	emails  []string
}

// newCSR builds a DER certificate signing request signed by key.
func newCSR(t *testing.T, key crypto.Signer, o csrOptions) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        o.subject,
		DNSNames:       o.dns,
		URIs:           o.uris,
		EmailAddresses: o.emails,
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return der
}

// simpleCSR builds a minimal valid P-256 CSR and returns it with its key.
func simpleCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k := newKey(t)
	return newCSR(t, k, csrOptions{subject: pkix.Name{CommonName: "ignored"}}), k
}

// certWithURIs builds a throwaway self-signed certificate carrying exactly the
// supplied URI SANs. IdentityFromCert never checks signatures, so this is
// enough to exercise every malformed-SAN branch without needing the CA key.
func certWithURIs(t *testing.T, uris []*url.URL, cn string) *x509.Certificate {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0abc),
		Subject:      pkix.Name{CommonName: cn},
		URIs:         uris,
		NotBefore:    testTime,
		NotAfter:     testTime.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// mustURL parses a URL or fails the test.
func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url %q: %v", s, err)
	}
	return u
}

// pemBlock encodes a single PEM block.
func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
