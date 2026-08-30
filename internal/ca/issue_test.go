// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSpokeURI(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{TrustDomain: "fleet.example"})
	got := c.SpokeURI("prod-us-east-1")
	if diff := cmp.Diff("pmf://fleet.example/spoke/prod-us-east-1", got.String()); diff != "" {
		t.Errorf("SpokeURI (-want +got):\n%s", diff)
	}
}

func TestIssueSpokeFromCSRDiscardsRequestedAttributes(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	c := mustCA(t, Options{TrustDomain: "fleet.local", SpokeCertTTL: 14 * 24 * time.Hour, Clock: clock.Now})

	key := newKey(t)
	csrDER := newCSR(t, key, csrOptions{
		subject: pkix.Name{
			CommonName:   "admin",
			Organization: []string{"evil corp"},
		},
		dns:    []string{"hub.internal", "*.fleet.local"},
		emails: []string{"root@example.com"},
		uris: []*url.URL{
			mustURL(t, "pmf://fleet.local/spoke/some-other-cluster"),
			mustURL(t, "spiffe://fleet.local/ns/kube-system/sa/default"),
		},
	})

	certPEM, cert, err := c.IssueSpokeFromCSR(csrDER, "prod-eu")
	if err != nil {
		t.Fatalf("IssueSpokeFromCSR: %v", err)
	}

	if got, want := cert.Subject.CommonName, "spoke:prod-eu"; got != want {
		t.Errorf("CommonName = %q, want %q", got, want)
	}
	if strings.Contains(cert.Subject.String(), "admin") {
		t.Errorf("issued subject %q still contains the requested CN", cert.Subject.String())
	}
	if len(cert.Subject.Organization) != 0 {
		t.Errorf("Organization = %v, want none", cert.Subject.Organization)
	}
	if diff := cmp.Diff([]string(nil), cert.DNSNames); diff != "" {
		t.Errorf("DNSNames (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string(nil), cert.EmailAddresses); diff != "" {
		t.Errorf("EmailAddresses (-want +got):\n%s", diff)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want none", cert.IPAddresses)
	}
	gotURIs := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		gotURIs = append(gotURIs, u.String())
	}
	if diff := cmp.Diff([]string{"pmf://fleet.local/spoke/prod-eu"}, gotURIs); diff != "" {
		t.Errorf("URIs (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, cert.ExtKeyUsage); diff != "" {
		t.Errorf("ExtKeyUsage (-want +got):\n%s", diff)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %b, want %b", cert.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Errorf("IsCA = %v, BasicConstraintsValid = %v, want false/true", cert.IsCA, cert.BasicConstraintsValid)
	}
	if got, want := cert.NotBefore.UTC(), testTime.Add(-clockSkew); !got.Equal(want) {
		t.Errorf("NotBefore = %s, want %s (5m of skew tolerance)", got, want)
	}
	if got, want := cert.NotAfter.UTC(), testTime.Add(14*24*time.Hour); !got.Equal(want) {
		t.Errorf("NotAfter = %s, want %s", got, want)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Error("issued certificate does not carry the CSR's public key")
	}

	blk, rest := pem.Decode(certPEM)
	if blk == nil || blk.Type != pemTypeCertificate {
		t.Fatalf("returned PEM is not a certificate: %q", certPEM)
	}
	if len(rest) != 0 {
		t.Errorf("returned PEM has %d trailing bytes", len(rest))
	}
	if diff := cmp.Diff(cert.Raw, blk.Bytes); diff != "" {
		t.Errorf("PEM and parsed certificate disagree (-cert +pem):\n%s", diff)
	}

	// And it must actually chain to the CA as a client certificate.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       c.Pool(),
		CurrentTime: testTime.Add(time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued certificate does not verify: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       c.Pool(),
		CurrentTime: testTime.Add(time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Error("issued client certificate verified for serverAuth")
	}
}

func TestIssueSpokeFromCSRSerialsAreUnique(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{})
	seen := map[string]bool{}
	for range 8 {
		csrDER, _ := simpleCSR(t)
		_, cert, err := c.IssueSpokeFromCSR(csrDER, "prod")
		if err != nil {
			t.Fatalf("IssueSpokeFromCSR: %v", err)
		}
		s := SerialHex(cert.SerialNumber)
		if seen[s] {
			t.Fatalf("duplicate serial %s", s)
		}
		seen[s] = true
	}
}

func TestIssueSpokeFromCSRKeyProfile(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{})

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		csr     func(t *testing.T) []byte
		wantErr error
	}{
		{
			name: "ecdsa p256 accepted",
			csr:  func(t *testing.T) []byte { d, _ := simpleCSR(t); return d },
		},
		{
			name: "rsa 2048 accepted",
			csr:  func(t *testing.T) []byte { return newCSR(t, rsa2048, csrOptions{}) },
		},
		{
			name:    "rsa 1024 rejected",
			csr:     func(t *testing.T) []byte { return newCSR(t, rsa1024, csrOptions{}) },
			wantErr: ErrCSRInvalid,
		},
		{
			name:    "ecdsa p384 rejected",
			csr:     func(t *testing.T) []byte { return newCSR(t, p384, csrOptions{}) },
			wantErr: ErrCSRInvalid,
		},
		{
			name:    "ed25519 rejected",
			csr:     func(t *testing.T) []byte { return newCSR(t, ed, csrOptions{}) },
			wantErr: ErrCSRInvalid,
		},
		{
			name:    "not der at all",
			csr:     func(*testing.T) []byte { return []byte("hello") },
			wantErr: ErrCSRInvalid,
		},
		{
			name:    "empty",
			csr:     func(*testing.T) []byte { return nil },
			wantErr: ErrCSRInvalid,
		},
		{
			name: "tampered signature",
			csr: func(t *testing.T) []byte {
				d, _ := simpleCSR(t)
				out := append([]byte(nil), d...)
				out[len(out)-1] ^= 0xff
				return out
			},
			wantErr: ErrCSRInvalid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, cert, err := c.IssueSpokeFromCSR(tc.csr(t), "prod")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
				if cert != nil {
					t.Error("a certificate was returned alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cert.Subject.CommonName != "spoke:prod" {
				t.Errorf("CommonName = %q", cert.Subject.CommonName)
			}
		})
	}
}

func TestCheckCSRPublicKeyRSACeiling(t *testing.T) {
	t.Parallel()

	// Generating a 16384-bit RSA key is far too slow for a unit test, so the
	// ceiling is exercised directly against a synthetic modulus.
	big16k := &rsa.PublicKey{E: 65537, N: new(big.Int).Lsh(big.NewInt(1), 16383)}
	err := checkCSRPublicKey(big16k)
	if !errors.Is(err, ErrCSRInvalid) {
		t.Fatalf("got %v, want ErrCSRInvalid", err)
	}
	if !strings.Contains(err.Error(), "16384") {
		t.Errorf("error should name the offending size: %v", err)
	}
}

func TestIssueSpokeFromCSRRejectsBadClusterID(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{})
	csrDER, _ := simpleCSR(t)
	for _, id := range []string{"", "Prod", "prod.us", "prod/../admin", strings.Repeat("a", 64), "prod\n"} {
		_, _, err := c.IssueSpokeFromCSR(csrDER, id)
		if !errors.Is(err, ErrInvalidClusterID) {
			t.Errorf("cluster id %q: got %v, want ErrInvalidClusterID", id, err)
		}
	}
}

func TestIssueClampsToCAExpiryAndRefusesAfterIt(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	c := mustCA(t, Options{
		CATTL:        time.Hour,
		SpokeCertTTL: 14 * 24 * time.Hour,
		Clock:        clock.Now,
	})
	caExpiry := testTime.Add(time.Hour)

	csrDER, _ := simpleCSR(t)
	_, cert, err := c.IssueSpokeFromCSR(csrDER, "prod")
	if err != nil {
		t.Fatalf("IssueSpokeFromCSR: %v", err)
	}
	if got := cert.NotAfter.UTC(); !got.Equal(caExpiry) {
		t.Errorf("leaf NotAfter = %s, want it clamped to the CA's %s", got, caExpiry)
	}
	// One nanosecond before expiry issuance still works.
	clock.Advance(time.Hour - time.Nanosecond)
	if _, _, err := c.IssueSpokeFromCSR(csrDER, "prod"); err != nil {
		t.Fatalf("issuance just before CA expiry: %v", err)
	}

	// At expiry, and after it, it must not.
	clock.Advance(time.Nanosecond)
	if _, _, err := c.IssueSpokeFromCSR(csrDER, "prod"); !errors.Is(err, ErrCAExpired) {
		t.Errorf("issuance at CA expiry: got %v, want ErrCAExpired", err)
	}
	clock.Advance(24 * time.Hour)
	if _, _, err := c.IssueSpokeFromCSR(csrDER, "prod"); !errors.Is(err, ErrCAExpired) {
		t.Errorf("issuance after CA expiry: got %v, want ErrCAExpired", err)
	}
}
