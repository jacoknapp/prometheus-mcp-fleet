// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// selfSignedRoot mints a throwaway self-signed certificate with the supplied
// CA flag and key usage. It exists to produce the malformed trust anchors a
// bundle must refuse, which no legitimate code path in this package can
// generate.
func selfSignedRoot(t *testing.T, cn string, isCA bool, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x5eed),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             testTime.Add(-time.Hour),
		NotAfter:              testTime.Add(24 * time.Hour),
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
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

// withRoots returns a copy of o trusting the supplied additional roots.
func withRoots(o Options, pemBytes []byte) Options {
	o.AdditionalRootsPEM = pemBytes
	return o
}

// fingerprints renders a trust bundle as the identifiers a rotation is tracked
// by, which is a far more readable diff than a slice of parsed certificates.
func fingerprints(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, Fingerprint(c))
	}
	return out
}

func TestParseTrustBundlePEM(t *testing.T) {
	t.Parallel()

	one := mustCA(t, Options{TrustDomain: "one.test"})
	two := mustCA(t, Options{TrustDomain: "two.test"})
	leaf := issuedSpokeCert(t, one, "alpha")
	noCertSign := selfSignedRoot(t, "no-certsign", true, x509.KeyUsageDigitalSignature)

	tests := []struct {
		name      string
		bundle    []byte
		wantRoots []string
		wantErr   error
	}{
		{
			name:      "single root",
			bundle:    one.BundlePEM(),
			wantRoots: fingerprints([]*x509.Certificate{one.Certificate()}),
		},
		{
			name:      "two roots keep their order",
			bundle:    append(append([]byte{}, one.BundlePEM()...), two.BundlePEM()...),
			wantRoots: fingerprints([]*x509.Certificate{one.Certificate(), two.Certificate()}),
		},
		{
			name: "commentary between blocks is ignored",
			bundle: append(append([]byte("# outgoing root, retire after 2026-10-01\n"),
				one.BundlePEM()...), append([]byte("\n# incoming root\n"), two.BundlePEM()...)...),
			wantRoots: fingerprints([]*x509.Certificate{one.Certificate(), two.Certificate()}),
		},
		{
			name:    "empty",
			bundle:  nil,
			wantErr: ErrInvalidCA,
		},
		{
			name:    "no PEM block at all",
			bundle:  []byte("this is not a certificate\n"),
			wantErr: ErrInvalidCA,
		},
		{
			name:    "wrong block type",
			bundle:  pemBlock(pemTypePrivateKey, []byte{0x01, 0x02}),
			wantErr: ErrInvalidCA,
		},
		{
			name:    "unparseable certificate",
			bundle:  pemBlock(pemTypeCertificate, []byte{0x30, 0x00}),
			wantErr: ErrInvalidCA,
		},
		{
			name:    "leaf offered as a root",
			bundle:  pemBlock(pemTypeCertificate, leaf.Raw),
			wantErr: ErrInvalidCA,
		},
		{
			name:    "CA without the certSign usage",
			bundle:  pemBlock(pemTypeCertificate, noCertSign.Raw),
			wantErr: ErrInvalidCA,
		},
		{
			name:    "one good root then one bad",
			bundle:  append(append([]byte{}, one.BundlePEM()...), pemBlock(pemTypeCertificate, leaf.Raw)...),
			wantErr: ErrInvalidCA,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseTrustBundlePEM(tc.bundle)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseTrustBundlePEM() error = %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Errorf("ParseTrustBundlePEM() returned %d roots alongside an error", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTrustBundlePEM() error = %v", err)
			}
			if diff := cmp.Diff(tc.wantRoots, fingerprints(got)); diff != "" {
				t.Errorf("ParseTrustBundlePEM() roots (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	t.Parallel()

	one := mustCA(t, Options{TrustDomain: "one.test"})
	// Two roots for the same trust domain share a subject exactly, which is
	// the case a rotation actually produces and the reason the identifier is
	// taken over the DER rather than over the name.
	two := mustCA(t, Options{TrustDomain: "one.test"})

	if diff := cmp.Diff(one.Certificate().Subject.String(), two.Certificate().Subject.String()); diff != "" {
		t.Fatalf("successor root does not share the outgoing root's subject, so this test proves nothing (-one +two):\n%s", diff)
	}
	if got := Fingerprint(one.Certificate()); len(got) != 64 {
		t.Errorf("Fingerprint() = %q, want 64 hex characters of untruncated sha-256", got)
	}
	if diff := cmp.Diff(Fingerprint(one.Certificate()), Fingerprint(one.Certificate())); diff != "" {
		t.Errorf("Fingerprint() is not deterministic (-first +second):\n%s", diff)
	}
	if Fingerprint(one.Certificate()) == Fingerprint(two.Certificate()) {
		t.Error("two distinct roots with the same subject share a fingerprint")
	}
	if got := Fingerprint(nil); got != "" {
		t.Errorf("Fingerprint(nil) = %q, want the empty string", got)
	}
}

func TestTrustBundleAndPool(t *testing.T) {
	t.Parallel()

	outgoing := mustCA(t, Options{TrustDomain: "rot.test"})

	t.Run("steady state trusts only the signer", func(t *testing.T) {
		t.Parallel()

		want := fingerprints([]*x509.Certificate{outgoing.Certificate()})
		if diff := cmp.Diff(want, fingerprints(outgoing.TrustBundle())); diff != "" {
			t.Errorf("TrustBundle() (-want +got):\n%s", diff)
		}
		if got := len(outgoing.Pool().Subjects()); got != 1 { //nolint:staticcheck // system pool is never used here
			t.Errorf("pool has %d subjects, want 1", got)
		}
	})

	t.Run("overlap trusts both, signer first", func(t *testing.T) {
		t.Parallel()

		incoming := mustCA(t, Options{TrustDomain: "rot.test"})
		certPath, keyPath := paths(t)
		signer, err := Create(certPath, keyPath, withRoots(Options{TrustDomain: "rot.test"}, incoming.BundlePEM()))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		want := fingerprints([]*x509.Certificate{signer.Certificate(), incoming.Certificate()})
		if diff := cmp.Diff(want, fingerprints(signer.TrustBundle())); diff != "" {
			t.Errorf("TrustBundle() (-want +got):\n%s", diff)
		}
		parsed, err := ParseTrustBundlePEM(signer.BundlePEM())
		if err != nil {
			t.Fatalf("BundlePEM does not round-trip: %v", err)
		}
		if diff := cmp.Diff(want, fingerprints(parsed)); diff != "" {
			t.Errorf("BundlePEM() roots (-want +got):\n%s", diff)
		}
		if got := len(signer.Pool().Subjects()); got != 2 { //nolint:staticcheck // system pool is never used here
			t.Errorf("pool has %d subjects, want 2", got)
		}
	})

	t.Run("TrustBundle is a defensive copy", func(t *testing.T) {
		t.Parallel()

		b := outgoing.TrustBundle()
		b[0] = nil
		if got := outgoing.TrustBundle(); got[0] == nil {
			t.Error("mutating the returned slice changed the CA's trust bundle")
		}
	})

	t.Run("duplicates collapse", func(t *testing.T) {
		t.Parallel()

		// Concatenating the whole rotation bundle into AdditionalRootsPEM
		// names the active signer again. That is the natural thing to
		// configure and must not double the bundle.
		incoming := mustCA(t, Options{TrustDomain: "rot.test"})
		both := append(append([]byte{}, incoming.BundlePEM()...), incoming.BundlePEM()...)
		certPath, keyPath := paths(t)
		signer, err := Create(certPath, keyPath, withRoots(Options{TrustDomain: "rot.test"},
			append(append([]byte{}, both...), incoming.BundlePEM()...)))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		want := fingerprints([]*x509.Certificate{signer.Certificate(), incoming.Certificate()})
		if diff := cmp.Diff(want, fingerprints(signer.TrustBundle())); diff != "" {
			t.Errorf("TrustBundle() (-want +got):\n%s", diff)
		}
	})

	t.Run("the signer cannot be configured out of its own bundle", func(t *testing.T) {
		t.Parallel()

		// Additional roots are additive, so a bundle naming only somebody
		// else still leaves the signer trusted and still leaves it first.
		other := mustCA(t, Options{TrustDomain: "rot.test"})
		certPath, keyPath := paths(t)
		if _, err := Create(certPath, keyPath, Options{TrustDomain: "rot.test"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		signer, err := Load(certPath, keyPath, withRoots(Options{TrustDomain: "rot.test"}, other.BundlePEM()))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if diff := cmp.Diff(Fingerprint(signer.Certificate()), Fingerprint(signer.TrustBundle()[0])); diff != "" {
			t.Errorf("active signer is not the first root (-signer +bundle[0]):\n%s", diff)
		}
		if got := len(signer.TrustBundle()); got != 2 {
			t.Errorf("trust bundle holds %d roots, want the signer plus the configured root", got)
		}
	})
}

func TestIssuerFingerprint(t *testing.T) {
	t.Parallel()

	opts := Options{TrustDomain: "rot.test", Clock: newFakeClock(testTime).Now}
	outgoing := mustCA(t, opts)
	oldLeaf := issuedSpokeCert(t, outgoing, "alpha")

	certPath, keyPath := paths(t)
	incoming, err := Create(certPath, keyPath, withRoots(opts, outgoing.BundlePEM()))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	newLeaf := issuedSpokeCert(t, incoming, "beta")
	stranger := mustCA(t, opts)
	strangerLeaf := issuedSpokeCert(t, stranger, "gamma")

	tests := []struct {
		name   string
		leaf   *x509.Certificate
		want   string
		wantOK bool
	}{
		{name: "issued by the active signer", leaf: newLeaf, want: Fingerprint(incoming.Certificate()), wantOK: true},
		{name: "issued by the outgoing root", leaf: oldLeaf, want: Fingerprint(outgoing.Certificate()), wantOK: true},
		{name: "issued by nothing in the bundle", leaf: strangerLeaf},
		{name: "nil", leaf: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := incoming.IssuerFingerprint(tc.leaf)
			if ok != tc.wantOK {
				t.Fatalf("IssuerFingerprint() ok = %v, want %v", ok, tc.wantOK)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("IssuerFingerprint() (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAdditionalRootsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		additiona []byte
		wantErr   error
	}{
		{name: "garbage", additiona: []byte("not pem at all"), wantErr: ErrInvalidCA},
		{name: "wrong block type", additiona: pemBlock(pemTypePrivateKey, []byte{0x01}), wantErr: ErrInvalidCA},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Create", func(t *testing.T) {
				t.Parallel()

				certPath, keyPath := paths(t)
				_, err := Create(certPath, keyPath, withRoots(Options{}, tc.additiona))
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Create() error = %v, want %v", err, tc.wantErr)
				}
				if _, statErr := os.Stat(keyPath); statErr == nil {
					t.Error("Create left a key behind after refusing the trust bundle")
				}
			})

			t.Run("Load", func(t *testing.T) {
				t.Parallel()

				certPath, keyPath := paths(t)
				if _, err := Create(certPath, keyPath, Options{}); err != nil {
					t.Fatalf("Create: %v", err)
				}
				if _, err := Load(certPath, keyPath, withRoots(Options{}, tc.additiona)); !errors.Is(err, tc.wantErr) {
					t.Fatalf("Load() error = %v, want %v", err, tc.wantErr)
				}
			})
		})
	}
}

func TestAdditionalRootsBlankIsSteadyState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		additiona []byte
	}{
		{name: "nil", additiona: nil},
		{name: "empty", additiona: []byte{}},
		{name: "whitespace only", additiona: []byte("\n\t  \n")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			certPath, keyPath := paths(t)
			c, err := Create(certPath, keyPath, withRoots(Options{}, tc.additiona))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			want := fingerprints([]*x509.Certificate{c.Certificate()})
			if diff := cmp.Diff(want, fingerprints(c.TrustBundle())); diff != "" {
				t.Errorf("TrustBundle() (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLoadRejectsMultiCertificateSignerFile pins the loud failure that replaced
// a silent one: before the trust bundle existed, an operator told to "serve
// both roots" would concatenate them into the signer certificate file, where
// everything after the first block was discarded without a word.
func TestLoadRejectsMultiCertificateSignerFile(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	signer, err := Create(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	other := mustCA(t, Options{})
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	dir := t.TempDir()
	joinedCert := filepath.Join(dir, "ca.crt")
	joinedKey := filepath.Join(dir, "ca.key")
	joined := append(append([]byte{}, signer.BundlePEM()...), other.BundlePEM()...)
	if err := os.WriteFile(joinedCert, joined, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(joinedKey, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, err := Load(joinedCert, joinedKey, Options{}); !errors.Is(err, ErrInvalidCA) {
		t.Fatalf("Load() error = %v, want %v", err, ErrInvalidCA)
	}
}

// TestRotationWalkthrough executes the documented rotation end to end. It is
// the test that would have failed before this package could rotate at all: at
// every step a certificate issued by the outgoing root must keep verifying,
// and only the final step may break it.
func TestRotationWalkthrough(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	opts := Options{TrustDomain: "rot.test", Clock: clock.Now}
	dir := t.TempDir()
	oldCert, oldKey := filepath.Join(dir, "old.crt"), filepath.Join(dir, "old.key")
	newCert, newKey := filepath.Join(dir, "new.crt"), filepath.Join(dir, "new.key")

	// Step 0. The fleet as it stands: one root, one enrolled spoke.
	before, err := Create(oldCert, oldKey, opts)
	if err != nil {
		t.Fatalf("Create outgoing root: %v", err)
	}
	oldLeaf := issuedSpokeCert(t, before, "alpha")
	oldRootPEM := before.BundlePEM()

	// Step 1. Mint the successor root. It signs nothing yet.
	successor, err := Create(newCert, newKey, opts)
	if err != nil {
		t.Fatalf("Create successor root: %v", err)
	}
	newRootPEM := successor.BundlePEM()

	// Step 2. The running hub keeps its signer and widens its trust. This is
	// the bundle that goes out to every spoke.
	overlap, err := Load(oldCert, oldKey, withRoots(opts, newRootPEM))
	if err != nil {
		t.Fatalf("Load overlap: %v", err)
	}
	wantOverlap := fingerprints([]*x509.Certificate{before.Certificate(), successor.Certificate()})
	if diff := cmp.Diff(wantOverlap, fingerprints(overlap.TrustBundle())); diff != "" {
		t.Errorf("overlap trust bundle (-want +got):\n%s", diff)
	}
	wantID := tunnel.Identity{
		ClusterID:    "alpha",
		CertSerial:   SerialHex(oldLeaf.SerialNumber),
		CertNotAfter: oldLeaf.NotAfter,
	}
	gotID, err := overlap.VerifyChain([]*x509.Certificate{oldLeaf})
	if err != nil {
		t.Fatalf("overlap.VerifyChain(old leaf): %v", err)
	}
	if diff := cmp.Diff(wantID, gotID); diff != "" {
		t.Errorf("overlap identity (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(Fingerprint(before.Certificate()), Fingerprint(overlap.Certificate())); diff != "" {
		t.Errorf("overlap must still sign with the outgoing root (-want +got):\n%s", diff)
	}

	// Step 3. Cut the signer over. Trust now names the outgoing root instead.
	cutover, err := Load(newCert, newKey, withRoots(opts, oldRootPEM))
	if err != nil {
		t.Fatalf("Load cutover: %v", err)
	}
	if diff := cmp.Diff(Fingerprint(successor.Certificate()), Fingerprint(cutover.Certificate())); diff != "" {
		t.Errorf("cutover did not move the active signer (-want +got):\n%s", diff)
	}
	if _, err := cutover.VerifyChain([]*x509.Certificate{oldLeaf}); err != nil {
		t.Fatalf("cutover.VerifyChain(old leaf) = %v, want the unmigrated spoke to keep working", err)
	}
	newLeaf := issuedSpokeCert(t, cutover, "alpha")
	if got, ok := cutover.IssuerFingerprint(newLeaf); !ok || got != Fingerprint(successor.Certificate()) {
		t.Errorf("renewed certificate issuer = (%q, %v), want the successor root", got, ok)
	}
	if got, ok := cutover.IssuerFingerprint(oldLeaf); !ok || got != Fingerprint(before.Certificate()) {
		t.Errorf("unmigrated certificate issuer = (%q, %v), want the outgoing root", got, ok)
	}

	// Step 4. Once nothing chains to the outgoing root, drop it.
	retired, err := Load(newCert, newKey, opts)
	if err != nil {
		t.Fatalf("Load retired: %v", err)
	}
	if diff := cmp.Diff(fingerprints([]*x509.Certificate{successor.Certificate()}), fingerprints(retired.TrustBundle())); diff != "" {
		t.Errorf("retired trust bundle (-want +got):\n%s", diff)
	}
	if _, err := retired.VerifyChain([]*x509.Certificate{newLeaf}); err != nil {
		t.Fatalf("retired.VerifyChain(migrated leaf): %v", err)
	}
	_, err = retired.VerifyChain([]*x509.Certificate{oldLeaf})
	if !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("retired.VerifyChain(old leaf) = %v, want %v", err, ErrUntrustedChain)
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Errorf("retired.VerifyChain(old leaf) = %v, want it to wrap x509.UnknownAuthorityError", err)
	}
}

// TestOverlapPreservesVerificationRules proves the widened trust bundle relaxes
// nothing else: an offered intermediate is still not a root, a certificate
// without clientAuth is still refused, and the renewal grace still applies per
// root rather than blanket-forgiving anything that parses.
func TestOverlapPreservesVerificationRules(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	opts := Options{TrustDomain: "rot.test", Clock: clock.Now}
	outgoing := mustCA(t, opts)
	certPath, keyPath := paths(t)
	overlap, err := Create(certPath, keyPath, withRoots(opts, outgoing.BundlePEM()))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("an offered intermediate is not promoted to a root", func(t *testing.T) {
		t.Parallel()

		stranger := mustCA(t, opts)
		leaf, intermediate := intermediateSignedSpokeCert(t, stranger, "alpha")
		// The intermediate is a certSign CA, so it would be a perfectly good
		// root if the bundle accepted what the peer offers. It must not.
		_, err := overlap.VerifyChain([]*x509.Certificate{leaf, intermediate})
		if !errors.Is(err, ErrUntrustedChain) {
			t.Fatalf("VerifyChain() error = %v, want %v", err, ErrUntrustedChain)
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Errorf("VerifyChain() error = %v, want x509.UnknownAuthorityError: the offered "+
				"intermediate must not be reachable as a trust anchor", err)
		}
	})

	t.Run("clientAuth is still required for a leaf from the outgoing root", func(t *testing.T) {
		t.Parallel()

		_, serverLeaf, err := outgoing.sign(&x509.Certificate{
			Subject:               pkix.Name{CommonName: "server only"},
			URIs:                  []*url.URL{outgoing.SpokeURI("alpha")},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, newKey(t).Public(), DefaultSpokeCertTTL)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := overlap.VerifyChain([]*x509.Certificate{serverLeaf}); !errors.Is(err, ErrUntrustedChain) {
			t.Fatalf("VerifyChain() error = %v, want %v", err, ErrUntrustedChain)
		}
	})

	t.Run("renewal grace reaches a leaf from the outgoing root", func(t *testing.T) {
		t.Parallel()

		local := newFakeClock(testTime)
		localOpts := Options{TrustDomain: "rot.test", Clock: local.Now}
		old := mustCA(t, localOpts)
		leaf := issuedSpokeCert(t, old, "alpha")
		cp, kp := paths(t)
		hub, err := Create(cp, kp, withRoots(localOpts, old.BundlePEM()))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		local.Advance(DefaultSpokeCertTTL + time.Hour)
		id, expired, err := hub.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, 24*time.Hour)
		if err != nil {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v", err)
		}
		if !expired {
			t.Error("VerifyChainAllowingExpiry() reported the leaf as unexpired")
		}
		if diff := cmp.Diff("alpha", id.ClusterID); diff != "" {
			t.Errorf("identity (-want +got):\n%s", diff)
		}

		local.Advance(48 * time.Hour)
		if _, _, err := hub.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, 24*time.Hour); !errors.Is(err, ErrGraceExhausted) {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v, want %v", err, ErrGraceExhausted)
		}
	})
}
