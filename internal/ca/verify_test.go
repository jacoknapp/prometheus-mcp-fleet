// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"testing"
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
