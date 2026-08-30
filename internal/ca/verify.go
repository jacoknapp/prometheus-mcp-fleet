// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// ErrUntrustedChain is returned by VerifyChain when the presented certificates
// do not chain to this authority, have expired, or are not valid for client
// authentication.
var ErrUntrustedChain = errors.New("ca: certificate chain does not verify")

// VerifyChain verifies a spoke's certificate chain against this authority and
// returns the identity the leaf carries.
//
// It exists because the WebSocket tunnel of ADR-0014 terminates TLS at the
// ingress, so crypto/tls never sees the spoke's certificate and cannot do this
// on the hub's behalf. What used to be a TLS client-certificate verification is
// therefore performed explicitly here, against exactly the same root pool and
// with the same identity rule: the cluster ID comes from the leaf's URI SAN and
// nowhere else.
//
// chain is leaf-first, as it arrives on the wire. Any certificates after the
// leaf are offered as intermediates; they are never trusted as roots, so a peer
// cannot promote its own issuer by appending it.
//
// Revocation is deliberately not checked here. It changes far more often than a
// trust anchor does and is consulted separately by the caller against the live
// denylist.
func (c *CA) VerifyChain(chain []*x509.Certificate) (tunnel.Identity, error) {
	if len(chain) == 0 {
		return tunnel.Identity{}, fmt.Errorf("%w: no certificate presented", ErrUntrustedChain)
	}
	leaf := chain[0]

	var intermediates *x509.CertPool
	if len(chain) > 1 {
		intermediates = x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.Pool(),
		Intermediates: intermediates,
		CurrentTime:   c.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return tunnel.Identity{}, fmt.Errorf("%w: %w", ErrUntrustedChain, err)
	}
	return c.IdentityFromCert(leaf)
}
