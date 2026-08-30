// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package certproof_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
)

// tunnelProtocolVersion is the wstun handshake's version string. It is written
// out rather than imported so this test cannot be made to pass by changing the
// constant it is meant to be different from.
const tunnelProtocolVersion = "v1"

// TestTranscriptIsUnambiguous is the property the whole construction rests on:
// no two different (nonce, version, cluster) triples may produce the same
// bytes. Length-prefixing is what guarantees it, and the cases below are the
// ones a naive concatenation would collide on.
func TestTranscriptIsUnambiguous(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		aNonce             []byte
		aVersion, aCluster string
		bNonce             []byte
		bVersion, bCluster string
	}{
		{
			name:   "a boundary moved between nonce and version",
			aNonce: []byte("ab"), aVersion: "c", aCluster: "prod",
			bNonce: []byte("a"), bVersion: "bc", bCluster: "prod",
		},
		{
			name:   "a boundary moved between version and cluster",
			aNonce: []byte("n"), aVersion: "v1", aCluster: "prod",
			bNonce: []byte("n"), bVersion: "v", bCluster: "1prod",
		},
		{
			name:   "the same fields under different exchanges",
			aNonce: []byte("n"), aVersion: tunnelProtocolVersion, aCluster: "prod",
			bNonce: []byte("n"), bVersion: certproof.RenewProtocolVersion, bCluster: "prod",
		},
		{
			name:   "an empty field is not the same as an absent one",
			aNonce: nil, aVersion: "", aCluster: "prod",
			bNonce: nil, bVersion: "prod", bCluster: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := certproof.Transcript(tc.aNonce, tc.aVersion, tc.aCluster)
			if err != nil {
				t.Fatalf("Transcript(a): %v", err)
			}
			b, err := certproof.Transcript(tc.bNonce, tc.bVersion, tc.bCluster)
			if err != nil {
				t.Fatalf("Transcript(b): %v", err)
			}
			if bytes.Equal(a, b) {
				t.Errorf("two different inputs produced the same transcript:\n%q", a)
			}
		})
	}
}

// TestTranscriptIsDomainSeparated proves the transcript cannot be mistaken for
// a bare nonce or for some other signed structure.
func TestTranscriptIsDomainSeparated(t *testing.T) {
	t.Parallel()

	got, err := certproof.Transcript([]byte("nonce"), "v1", "prod")
	if err != nil {
		t.Fatalf("Transcript: %v", err)
	}
	if !bytes.HasPrefix(got, []byte("prometheus-mcp-fleet/tunnel-auth\x00")) {
		t.Errorf("transcript does not begin with the domain tag: %q", got)
	}
	// The tag is on the wire: every deployed spoke computes these exact bytes,
	// so a change here is a fleet-wide handshake break, not a refactor.
	if bytes.Contains(got[:32], []byte{0}) {
		t.Error("the domain tag is not the expected fixed prefix")
	}
}

// TestRenewIsNotTheTunnelVersion guards the domain separation between the two
// exchanges that share this construction.
func TestRenewIsNotTheTunnelVersion(t *testing.T) {
	t.Parallel()
	if certproof.RenewProtocolVersion == tunnelProtocolVersion {
		t.Fatal("renewal and the tunnel handshake share a protocol version, so a " +
			"signature captured from one can be redeemed at the other")
	}
}

// TestSignVerifyRoundTrip covers each key algorithm a spoke certificate might
// carry, and every way a proof must fail.
func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  func(t *testing.T) crypto.Signer
	}{
		{name: "ecdsa p256", key: func(t *testing.T) crypto.Signer { return newECDSA(t) }},
		{name: "rsa 2048", key: func(t *testing.T) crypto.Signer { return newRSA(t) }},
	}

	nonce := []byte("a fixed challenge")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := tc.key(t)
			leaf := selfSigned(t, key)

			sig, err := certproof.Sign(key, nonce, certproof.RenewProtocolVersion, "prod")
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			if err := certproof.Verify(leaf, sig, nonce, certproof.RenewProtocolVersion, "prod"); err != nil {
				t.Fatalf("Verify() = %v, want nil", err)
			}

			// Every one of these is a genuine proof over something else.
			rescoped := []struct {
				name             string
				nonce            []byte
				version, cluster string
			}{
				{name: "another nonce", nonce: []byte("a different challenge"), version: certproof.RenewProtocolVersion, cluster: "prod"},
				{name: "another cluster", nonce: nonce, version: certproof.RenewProtocolVersion, cluster: "staging"},
				{name: "another exchange", nonce: nonce, version: tunnelProtocolVersion, cluster: "prod"},
			}
			for _, rc := range rescoped {
				if err := certproof.Verify(leaf, sig, rc.nonce, rc.version, rc.cluster); !errors.Is(err, certproof.ErrBadSignature) {
					t.Errorf("Verify() against %s = %v, want ErrBadSignature", rc.name, err)
				}
			}

			tampered := bytes.Clone(sig)
			tampered[len(tampered)-1] ^= 0x01
			if err := certproof.Verify(leaf, tampered, nonce, certproof.RenewProtocolVersion, "prod"); !errors.Is(err, certproof.ErrBadSignature) {
				t.Errorf("Verify() of a tampered signature = %v, want ErrBadSignature", err)
			}

			other := selfSigned(t, newECDSA(t))
			if err := certproof.Verify(other, sig, nonce, certproof.RenewProtocolVersion, "prod"); !errors.Is(err, certproof.ErrBadSignature) {
				t.Errorf("Verify() against another certificate = %v, want ErrBadSignature", err)
			}
		})
	}
}

// TestVerifyRejectsAnUnsupportedKeyType covers a certificate this build cannot
// check a signature against.
//
// It must be a refusal and not a pass: a key type the verifier does not
// understand has proven nothing, and treating "cannot check" as "no objection"
// is how an algorithm-confusion bypass gets written.
func TestVerifyRejectsAnUnsupportedKeyType(t *testing.T) {
	t.Parallel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leaf := selfSigned(t, key)

	if err := certproof.Verify(leaf, []byte("any signature"), []byte("nonce"),
		certproof.RenewProtocolVersion, "prod"); !errors.Is(err, certproof.ErrBadSignature) {
		t.Errorf("Verify() = %v, want ErrBadSignature", err)
	}
}

// TestVerifyRejectsNoCertificate proves the nil leaf a caller could reach after
// an empty chain fails closed rather than panicking.
func TestVerifyRejectsNoCertificate(t *testing.T) {
	t.Parallel()
	if err := certproof.Verify(nil, []byte("sig"), []byte("nonce"), "v1", "prod"); !errors.Is(err, certproof.ErrBadSignature) {
		t.Errorf("Verify(nil) = %v, want ErrBadSignature", err)
	}
}

// TestSignReportsAFailingKey covers a signer that cannot sign, which is what a
// hardware key that has gone away looks like.
func TestSignReportsAFailingKey(t *testing.T) {
	t.Parallel()
	_, err := certproof.Sign(brokenSigner{}, []byte("nonce"), "v1", "prod")
	if err == nil {
		t.Fatal("Sign() = nil, want the signer's error")
	}
	if !errors.Is(err, errBroken) {
		t.Errorf("Sign() = %v, want it to wrap the signer's error", err)
	}
}

// errBroken is what brokenSigner returns.
var errBroken = errors.New("the key is gone")

// brokenSigner is a crypto.Signer that always fails.
type brokenSigner struct{}

// Public implements crypto.Signer. Sign never gets far enough for it to
// matter, which is the point of the fixture.
func (brokenSigner) Public() crypto.PublicKey { return nil }

// Sign implements crypto.Signer and always fails.
func (brokenSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errBroken
}

func newECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func newRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// selfSigned mints a certificate carrying the signer's public key, so Verify
// has a leaf to read it from.
func selfSigned(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certproof test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestTranscriptRejectsAnOversizedField proves the uniqueness guarantee is
// structural rather than a consequence of callers happening to pass small
// values. A field at or beyond 4 GiB would truncate the 32-bit length prefix
// and let two different inputs collide; the cap is what makes that
// unrepresentable.
func TestTranscriptRejectsAnOversizedField(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("a", certproof.MaxFieldBytes+1)

	tests := []struct {
		name                       string
		nonce                      []byte
		protocolVersion, clusterID string
	}{
		{name: "nonce", nonce: []byte(big), protocolVersion: "v1", clusterID: "prod"},
		{name: "protocol version", nonce: []byte("n"), protocolVersion: big, clusterID: "prod"},
		{name: "cluster id", nonce: []byte("n"), protocolVersion: "v1", clusterID: big},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := certproof.Transcript(tc.nonce, tc.protocolVersion, tc.clusterID)
			if !errors.Is(err, certproof.ErrFieldTooLarge) {
				t.Fatalf("error = %v, want ErrFieldTooLarge", err)
			}
			if got != nil {
				t.Error("a transcript was returned alongside an error")
			}
		})
	}
}

// TestSignAndVerifyRejectOversizedTranscriptFields proves both convenience
// operations preserve Transcript's structural bound instead of signing or
// accepting a truncated length prefix.
func TestSignAndVerifyRejectOversizedTranscriptFields(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("x", certproof.MaxFieldBytes+1)
	key := newECDSA(t)
	leaf := selfSigned(t, key)

	if sig, err := certproof.Sign(key, []byte("nonce"), "v1", oversized); !errors.Is(err, certproof.ErrFieldTooLarge) || sig != nil {
		t.Errorf("Sign() = (%x, %v), want nil and ErrFieldTooLarge", sig, err)
	}
	if err := certproof.Verify(leaf, []byte("signature"), []byte("nonce"), "v1", oversized); !errors.Is(err, certproof.ErrFieldTooLarge) {
		t.Errorf("Verify() = %v, want ErrFieldTooLarge", err)
	}
}
