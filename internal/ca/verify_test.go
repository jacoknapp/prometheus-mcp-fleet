// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"
)

// TestVerifyChain covers the explicit chain verification the WebSocket tunnel
// needs, now that no TLS stack does it on the hub's behalf.
func TestVerifyChain(t *testing.T) {
	t.Parallel()

	authority := mustCA(t, Options{TrustDomain: "fleet.test"})
	other := mustCA(t, Options{TrustDomain: "fleet.test"})

	tests := []struct {
		name        string
		chain       func(t *testing.T) []*x509.Certificate
		wantErr     error
		wantCluster string
	}{
		{
			name: "issued by this authority",
			chain: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{issuedSpokeCert(t, authority, "prod")}
			},
			wantCluster: "prod",
		},
		{
			name:    "empty chain",
			chain:   func(*testing.T) []*x509.Certificate { return nil },
			wantErr: ErrUntrustedChain,
		},
		{
			name: "issued by a different authority",
			chain: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{issuedSpokeCert(t, other, "prod")}
			},
			wantErr: ErrUntrustedChain,
		},
		{
			name: "a peer cannot promote its own issuer by appending it",
			chain: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{issuedSpokeCert(t, other, "prod"), other.Certificate()}
			},
			wantErr: ErrUntrustedChain,
		},
		{
			name: "valid signature but no spoke identity",
			chain: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{certWithoutIdentity(t, authority)}
			},
			wantErr: ErrNoIdentity,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id, err := authority.VerifyChain(tc.chain(t))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("VerifyChain() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyChain() error = %v", err)
			}
			if id.ClusterID != tc.wantCluster {
				t.Errorf("ClusterID = %q, want %q", id.ClusterID, tc.wantCluster)
			}
			if id.CertSerial == "" {
				t.Error("CertSerial is empty; the audit log has nothing to record")
			}
			if id.CertNotAfter.IsZero() {
				t.Error("CertNotAfter is zero")
			}
		})
	}
}

// TestVerifyChainOffersCertificatesAfterTheLeafAsIntermediates proves that
// VerifyChain actually populates x509.VerifyOptions.Intermediates from
// chain[1:] when len(chain) > 1, rather than merely being unreachable code.
//
// The root here has MaxPathLen 0 (see ca.go), so no chain running through an
// intermediate can ever fully verify in this fleet — but *why* it fails still
// tells them apart. If chain[1:] reaches the verifier as an intermediate, the
// verifier finds a path (leaf -> intermediate -> root) and rejects it
// specifically for exceeding the path length, x509.CertificateInvalidError
// with reason TooManyIntermediates. If the len(chain) > 1 branch is skipped
// (as it would be under a negated or boundary-widened condition, since chain
// here has length 2), no intermediate ever reaches the verifier, no path to
// any root is found at all, and the error is a plain "unknown authority"
// instead. Asserting the specific reason, not just the wrapped
// ErrUntrustedChain sentinel both errors share, is what makes the two
// mutants distinguishable.
func TestVerifyChainOffersCertificatesAfterTheLeafAsIntermediates(t *testing.T) {
	t.Parallel()

	authority := mustCA(t, Options{TrustDomain: "fleet.test"})
	leaf, intermediate := intermediateSignedSpokeCert(t, authority, "prod")

	_, err := authority.VerifyChain([]*x509.Certificate{leaf, intermediate})
	if !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("VerifyChain() error = %v, want wrapping %v", err, ErrUntrustedChain)
	}
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != x509.TooManyIntermediates {
		t.Fatalf("VerifyChain() error = %v, want a CertificateInvalidError{Reason: TooManyIntermediates}: "+
			"the intermediate certificate must have reached the verifier for the path length to be the "+
			"failure reason", err)
	}
}

// TestVerifyChainAllowingExpiry covers the renewal grace period: an expired
// leaf still verifies, but only within grace, only for expiry specifically,
// and only if the chain would otherwise be trusted.
func TestVerifyChainAllowingExpiry(t *testing.T) {
	t.Parallel()

	const grace = 30 * 24 * time.Hour

	t.Run("unexpired: wasExpired is false", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now, SpokeCertTTL: 24 * time.Hour})
		leaf := issuedSpokeCert(t, authority, "prod")

		id, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, grace)
		if err != nil {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v", err)
		}
		if expired {
			t.Error("wasExpired = true for a certificate that has not expired")
		}
		if id.ClusterID != "prod" {
			t.Errorf("ClusterID = %q, want %q", id.ClusterID, "prod")
		}
	})

	t.Run("expired within grace: wasExpired is true and the identity still comes back", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now, SpokeCertTTL: 24 * time.Hour})
		leaf := issuedSpokeCert(t, authority, "prod")

		// One day past NotAfter, well inside a 30 day grace.
		clock.Advance(25 * time.Hour)

		id, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, grace)
		if err != nil {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v", err)
		}
		if !expired {
			t.Error("wasExpired = false for a certificate that has expired within grace")
		}
		if id.ClusterID != "prod" {
			t.Errorf("ClusterID = %q, want %q", id.ClusterID, "prod")
		}
		if id.CertSerial == "" {
			t.Error("CertSerial is empty on a grace-period renewal identity")
		}
	})

	t.Run("expired beyond grace: ErrGraceExhausted", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now, SpokeCertTTL: 24 * time.Hour})
		leaf := issuedSpokeCert(t, authority, "prod")

		// One day past NotAfter, plus the full grace window: past it.
		clock.Advance(24*time.Hour + grace + time.Hour)

		_, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, grace)
		if !errors.Is(err, ErrGraceExhausted) {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v, want ErrGraceExhausted", err)
		}
		if expired {
			t.Error("wasExpired = true on a rejected renewal")
		}
	})

	t.Run("grace of zero rejects an expired certificate outright", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now, SpokeCertTTL: time.Hour})
		leaf := issuedSpokeCert(t, authority, "prod")

		clock.Advance(2 * time.Hour)

		_, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, 0)
		if err == nil {
			t.Fatal("VerifyChainAllowingExpiry() error = nil, want the certificate refused")
		}
		if errors.Is(err, ErrGraceExhausted) {
			t.Error("grace=0 must return the original expiry error, not ErrGraceExhausted: " +
				"there was never a grace window to exhaust")
		}
		if !errors.Is(err, ErrUntrustedChain) {
			t.Errorf("VerifyChainAllowingExpiry() error = %v, want it to wrap ErrUntrustedChain", err)
		}
		if expired {
			t.Error("wasExpired = true on a rejected renewal")
		}
	})

	t.Run("a non-expiry failure keeps its original error and is not forgiven", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now})
		// A perfectly unexpired, chain-valid certificate that simply carries no
		// fleet identity. VerifyChain fails here for a reason that has nothing
		// to do with expiry, so the grace path must not touch it at all.
		leaf := certWithoutIdentity(t, authority)

		_, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, grace)
		if !errors.Is(err, ErrNoIdentity) {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v, want ErrNoIdentity unchanged", err)
		}
		if expired {
			t.Error("wasExpired = true on a rejected, non-expiry failure")
		}
	})

	t.Run("an intermediate invalid at the leaf's expiry is still rejected", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now, SpokeCertTTL: time.Hour})
		// The root has MaxPathLen 0 (see ca.go), so any chain offering an
		// intermediate can never fully verify in this fleet, at any time. That
		// makes this exactly the case the doc comment calls out: the grace-path
		// re-verification must still offer chain[1:] as intermediates and be
		// rejected on their account, rather than switching to some other mode
		// that only checks the leaf. If the re-verify below regressed to
		// ignoring intermediates entirely, this would come back trusted instead
		// of rejected for exceeding the path length.
		leaf, intermediate := intermediateSignedSpokeCert(t, authority, "prod")

		clock.Advance(2 * time.Hour) // past the leaf's one-hour NotAfter

		_, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf, intermediate}, grace)
		if !errors.Is(err, ErrUntrustedChain) {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v, want it to wrap ErrUntrustedChain", err)
		}
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.TooManyIntermediates {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v, want a CertificateInvalidError{Reason: "+
				"TooManyIntermediates}: the intermediate must have reached the grace-path re-verify", err)
		}
		if expired {
			t.Error("wasExpired = true on a rejected renewal")
		}
	})

	t.Run("the grace-path re-verify can still fail after the chain is trusted", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock(testTime)
		authority := mustCA(t, Options{Clock: clock.Now})
		// A leaf with no URI SAN: chain-valid and client-auth, but carrying no
		// fleet identity. sign is called directly, rather than through
		// certWithoutIdentity, because this case needs a short TTL to expire
		// within grace; certWithoutIdentity always mints DefaultSpokeCertTTL
		// (14 days).
		_, leaf, err := authority.sign(&x509.Certificate{
			Subject:               pkix.Name{CommonName: "identity-less client"},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}, newKey(t).Public(), time.Hour)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		clock.Advance(2 * time.Hour) // past the one-hour NotAfter, inside grace

		_, expired, err := authority.VerifyChainAllowingExpiry([]*x509.Certificate{leaf}, grace)
		if !errors.Is(err, ErrNoIdentity) {
			t.Fatalf("VerifyChainAllowingExpiry() error = %v, want ErrNoIdentity: the chain re-verified "+
				"successfully as of the leaf's own expiry, so only IdentityFromCert can be what failed", err)
		}
		if expired {
			t.Error("wasExpired = true on a renewal that was ultimately rejected")
		}
	})
}
