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
