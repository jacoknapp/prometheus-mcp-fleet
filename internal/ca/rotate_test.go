// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// mustNewRoot mints a successor root in memory and fails the test if it
// cannot.
func mustNewRoot(t *testing.T, opts Options) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM, err := NewRootPEM(opts)
	if err != nil {
		t.Fatalf("NewRootPEM: %v", err)
	}
	return certPEM, keyPEM
}

func TestNewRootPEM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr error
		check   func(t *testing.T, cert *x509.Certificate)
	}{
		{
			name: "defaults produce a path-length-zero signing root",
			opts: Options{},
			check: func(t *testing.T, cert *x509.Certificate) {
				t.Helper()
				if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
					t.Error("minted root is not a certificate-signing CA")
				}
				if !cert.MaxPathLenZero {
					t.Error("minted root may sign intermediates; it must sign leaves only")
				}
			},
		},
		{
			name: "the trust domain reaches the subject",
			opts: Options{TrustDomain: "other.example"},
			check: func(t *testing.T, cert *x509.Certificate) {
				t.Helper()
				if !strings.Contains(cert.Subject.CommonName, "other.example") {
					t.Errorf("common name %q does not name the trust domain", cert.Subject.CommonName)
				}
			},
		},
		{
			name:    "an invalid trust domain is refused before any key is generated",
			opts:    Options{TrustDomain: "NOT A DOMAIN"},
			wantErr: ErrInvalidOptions,
		},
		{
			name:    "a non-positive CA lifetime is refused",
			opts:    Options{CATTL: -time.Hour},
			wantErr: ErrInvalidOptions,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPEM, keyPEM, err := NewRootPEM(tc.opts)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("NewRootPEM() error = %v, want one wrapping %v", err, tc.wantErr)
				}
				if certPEM != nil || keyPEM != nil {
					t.Error("NewRootPEM returned material alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRootPEM: %v", err)
			}
			// The material must be loadable as an authority in its own right:
			// a successor that cannot be parsed back is a rotation that
			// deadlocks at promotion.
			c, perr := Parse(certPEM, keyPEM, tc.opts)
			if perr != nil {
				t.Fatalf("Parse of the minted root: %v", perr)
			}
			tc.check(t, c.Certificate())
		})
	}
}

// TestNewRootPEMMintsADistinctRootEachTime pins the property the whole
// rotation rests on: successive roots share a subject and are told apart only
// by their key material.
func TestNewRootPEMMintsADistinctRootEachTime(t *testing.T) {
	t.Parallel()

	firstPEM, _ := mustNewRoot(t, Options{})
	secondPEM, _ := mustNewRoot(t, Options{})

	first, err := ParseTrustBundlePEM(firstPEM)
	if err != nil {
		t.Fatalf("parse first root: %v", err)
	}
	second, err := ParseTrustBundlePEM(secondPEM)
	if err != nil {
		t.Fatalf("parse second root: %v", err)
	}
	if diff := cmp.Diff(first[0].Subject.CommonName, second[0].Subject.CommonName); diff != "" {
		t.Errorf("successive roots should share a subject (-first +second):\n%s", diff)
	}
	if Fingerprint(first[0]) == Fingerprint(second[0]) {
		t.Error("successive roots have the same fingerprint; a rotation could not be tracked")
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := mustNewRoot(t, Options{})
	otherCertPEM, otherKeyPEM := mustNewRoot(t, Options{})

	tests := []struct {
		name             string
		certPEM, keyPEM  []byte
		opts             Options
		wantErr          error
		wantBundleLength int
	}{
		{
			name: "signer only", certPEM: certPEM, keyPEM: keyPEM,
			wantBundleLength: 1,
		},
		{
			name: "signer plus an additional root", certPEM: certPEM, keyPEM: keyPEM,
			opts:             Options{AdditionalRootsPEM: otherCertPEM},
			wantBundleLength: 2,
		},
		{
			name: "the signer named twice is still one root", certPEM: certPEM, keyPEM: keyPEM,
			opts:             Options{AdditionalRootsPEM: certPEM},
			wantBundleLength: 1,
		},
		{
			name: "a key that does not match the certificate", certPEM: certPEM, keyPEM: otherKeyPEM,
			wantErr: ErrInvalidCA,
		},
		{
			name: "a certificate that is not PEM", certPEM: []byte("not pem"), keyPEM: keyPEM,
			wantErr: ErrInvalidCA,
		},
		{
			name: "a key that is not PEM", certPEM: certPEM, keyPEM: []byte("not pem"),
			wantErr: ErrInvalidCA,
		},
		{
			name: "a malformed additional root", certPEM: certPEM, keyPEM: keyPEM,
			opts:    Options{AdditionalRootsPEM: []byte("-----BEGIN CERTIFICATE-----\nzz\n-----END CERTIFICATE-----\n")},
			wantErr: ErrInvalidCA,
		},
		{
			name: "invalid options", certPEM: certPEM, keyPEM: keyPEM,
			opts:    Options{TrustDomain: "NOPE"},
			wantErr: ErrInvalidOptions,
		},
		{
			name: "two certificates in the signer slot", certPEM: append(append([]byte{}, certPEM...), otherCertPEM...),
			keyPEM:  keyPEM,
			wantErr: ErrInvalidCA,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := Parse(tc.certPEM, tc.keyPEM, tc.opts)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Parse() error = %v, want one wrapping %v", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "PRIVATE KEY") {
					t.Errorf("Parse error carries key material: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := len(c.TrustBundle()); got != tc.wantBundleLength {
				t.Errorf("trust bundle holds %d roots, want %d", got, tc.wantBundleLength)
			}
		})
	}
}

// TestAdoptPEMSwapsSignerAndBundle walks the two material changes a rotation
// makes -- widening the bundle, then moving the signer -- through one *CA
// handle, which is what lets the running request path follow a rotation
// without being rebuilt.
func TestAdoptPEMSwapsSignerAndBundle(t *testing.T) {
	t.Parallel()

	oldCertPEM, oldKeyPEM := mustNewRoot(t, Options{})
	newCertPEM, newKeyPEM := mustNewRoot(t, Options{})

	authority, err := Parse(oldCertPEM, oldKeyPEM, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	oldFingerprint := Fingerprint(authority.Certificate())

	// A leaf issued before anything moves must keep verifying through every
	// phase; that is the whole promise of the overlap.
	leaf := issuedSpokeCert(t, authority, "alpha")

	// Phase: publishing. Old root still signs, successor is trusted.
	if err := authority.AdoptPEM(oldCertPEM, oldKeyPEM, newCertPEM); err != nil {
		t.Fatalf("AdoptPEM (publishing): %v", err)
	}
	if got := Fingerprint(authority.Certificate()); got != oldFingerprint {
		t.Error("publishing changed the signer; only the trust bundle may widen")
	}
	if got := len(authority.TrustBundle()); got != 2 {
		t.Errorf("trust bundle holds %d roots during publishing, want 2", got)
	}
	mustVerify(t, authority, leaf)

	// Phase: signing. Successor signs, outgoing root stays trusted.
	if err := authority.AdoptPEM(newCertPEM, newKeyPEM, oldCertPEM); err != nil {
		t.Fatalf("AdoptPEM (signing): %v", err)
	}
	if got := Fingerprint(authority.Certificate()); got == oldFingerprint {
		t.Error("promotion did not move the signer")
	}
	if got := len(authority.TrustBundle()); got != 2 {
		t.Errorf("trust bundle holds %d roots during signing, want 2", got)
	}
	mustVerify(t, authority, leaf)

	// A leaf issued now must chain to the successor, and the old leaf must
	// still name the outgoing root.
	fresh := issuedSpokeCert(t, authority, "beta")
	freshIssuer, ok := authority.IssuerFingerprint(fresh)
	if !ok || freshIssuer == oldFingerprint {
		t.Errorf("a freshly issued leaf reports issuer %q, ok=%v; want the successor", freshIssuer, ok)
	}
	oldIssuer, ok := authority.IssuerFingerprint(leaf)
	if !ok || oldIssuer != oldFingerprint {
		t.Errorf("the pre-rotation leaf reports issuer %q, ok=%v; want %q", oldIssuer, ok, oldFingerprint)
	}

	// Phase: steady. The outgoing root is dropped and its leaf stops
	// verifying -- which is exactly why that step is gated on nothing needing
	// it any more.
	if err := authority.AdoptPEM(newCertPEM, newKeyPEM, nil); err != nil {
		t.Fatalf("AdoptPEM (steady): %v", err)
	}
	if got := len(authority.TrustBundle()); got != 1 {
		t.Errorf("trust bundle holds %d roots when steady, want 1", got)
	}
	if _, err := authority.VerifyChain([]*x509.Certificate{leaf}); !errors.Is(err, ErrUntrustedChain) {
		t.Errorf("the pre-rotation leaf still verifies after its root was dropped: %v", err)
	}
	mustVerify(t, authority, fresh)
}

// TestAdoptPEMRejectsBadMaterialWithoutChangingAnything is the safety property
// behind every phase: a hub that half-adopted a rotation would sign with one
// root and trust another.
func TestAdoptPEMRejectsBadMaterialWithoutChangingAnything(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := mustNewRoot(t, Options{})
	otherCertPEM, otherKeyPEM := mustNewRoot(t, Options{})

	tests := []struct {
		name                  string
		cert, key, additional []byte
		wantErr               error
	}{
		{"unparseable certificate", []byte("nope"), keyPEM, nil, ErrInvalidCA},
		{"unparseable key", certPEM, []byte("nope"), nil, ErrInvalidCA},
		{"mismatched keypair", certPEM, otherKeyPEM, nil, ErrInvalidCA},
		{"unparseable additional root", certPEM, keyPEM, []byte("nope"), ErrInvalidCA},
		{"additional root that is not a CA", certPEM, keyPEM, leafPEM(t), ErrInvalidCA},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			authority, err := Parse(otherCertPEM, otherKeyPEM, Options{})
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			before := Fingerprint(authority.Certificate())
			beforeBundle := authority.BundlePEM()

			if err := authority.AdoptPEM(tc.cert, tc.key, tc.additional); !errors.Is(err, tc.wantErr) {
				t.Fatalf("AdoptPEM() error = %v, want one wrapping %v", err, tc.wantErr)
			}
			if got := Fingerprint(authority.Certificate()); got != before {
				t.Error("a rejected adoption moved the signer")
			}
			if diff := cmp.Diff(beforeBundle, authority.BundlePEM()); diff != "" {
				t.Errorf("a rejected adoption changed the trust bundle (-before +after):\n%s", diff)
			}
			// The authority must still be able to issue and verify.
			mustVerify(t, authority, issuedSpokeCert(t, authority, "alpha"))
		})
	}
}

// TestAdoptPEMIsSafeUnderConcurrentUse runs a rotation against readers that
// are issuing and verifying at the same time. Under -race this is the test
// that says the atomic snapshot really is one: a reader must never see a
// certificate signed by one root and a bundle that does not contain it.
func TestAdoptPEMIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	oldCertPEM, oldKeyPEM := mustNewRoot(t, Options{})
	newCertPEM, newKeyPEM := mustNewRoot(t, Options{})
	authority, err := Parse(oldCertPEM, oldKeyPEM, Options{AdditionalRootsPEM: newCertPEM})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	csrDER, _ := simpleCSR(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Issue and immediately verify. Both sides read the snapshot,
				// and a torn read -- a certificate signed by one root while
				// the bundle holds another -- shows up here as an authority
				// refusing what it has just issued.
				_, leaf, err := authority.IssueSpokeFromCSR(csrDER, "alpha")
				if err != nil {
					t.Errorf("IssueSpokeFromCSR: %v", err)
					return
				}
				if _, verr := authority.VerifyChain([]*x509.Certificate{leaf}); verr != nil {
					t.Errorf("an authority refused a certificate it had just issued: %v", verr)
					return
				}
			}
		}()
	}
	for range 50 {
		if err := authority.AdoptPEM(newCertPEM, newKeyPEM, oldCertPEM); err != nil {
			t.Errorf("AdoptPEM: %v", err)
			break
		}
		if err := authority.AdoptPEM(oldCertPEM, oldKeyPEM, newCertPEM); err != nil {
			t.Errorf("AdoptPEM: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

// leafPEM is a PEM certificate that is not a CA, for proving the trust bundle
// refuses one.
func leafPEM(t *testing.T) []byte {
	t.Helper()
	return pemBlock(pemTypeCertificate, certWithURIs(t, nil, "not-a-ca").Raw)
}

// mustVerify asserts that leaf still chains to c.
func mustVerify(t *testing.T, c *CA, leaf *x509.Certificate) {
	t.Helper()
	if _, err := c.VerifyChain([]*x509.Certificate{leaf}); err != nil {
		t.Fatalf("a certificate that should still verify does not: %v", err)
	}
}
