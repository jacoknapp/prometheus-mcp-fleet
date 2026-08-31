// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

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

// ErrGraceExhausted is returned by VerifyChainAllowingExpiry when the leaf
// expired longer ago than the caller's grace period allows.
var ErrGraceExhausted = errors.New("ca: certificate expired beyond the renewal grace period")

// VerifyChainAllowingExpiry is VerifyChain, except that a leaf which has
// expired within grace still verifies. It reports whether the leaf was expired.
//
// This exists for renewal, and only for renewal. A spoke renews at half its
// certificate's life, so reaching expiry means the spoke was unreachable for
// half a certificate lifetime -- a cluster switched off over a holiday, a long
// outage, a GitOps rollout paused mid-flight. Without this the spoke is locked
// out permanently: /renew refuses the expired certificate, and the enrollment
// token that would let it start over was single-use and burned at first
// install, months ago. Recovering meant a human minting a token per cluster,
// which does not exist as a step in a declarative deployment.
//
// What this deliberately does NOT relax: the chain must still reach this
// authority, the leaf must still be a client-auth certificate, the caller must
// still check revocation, and the caller must still verify proof of private-key
// possession. An expired certificate on its own proves nothing here; it is a
// claim of continuity that the possession proof then has to back up.
//
// The chain is re-verified as of the leaf's own NotAfter rather than with
// expiry checking switched off, so an intermediate that was already invalid
// when the leaf expired is still rejected.
func (c *CA) VerifyChainAllowingExpiry(chain []*x509.Certificate, grace time.Duration) (tunnel.Identity, bool, error) {
	id, err := c.VerifyChain(chain)
	if err == nil {
		return id, false, nil
	}
	// Only expiry is forgiven. Anything else -- wrong root, wrong key usage, a
	// malformed SAN -- is a real failure and keeps the original error.
	leaf := chain[0]
	now := c.now()
	if grace <= 0 || !now.After(leaf.NotAfter) {
		return tunnel.Identity{}, false, err
	}
	if now.After(leaf.NotAfter.Add(grace)) {
		return tunnel.Identity{}, false, fmt.Errorf("%w: expired at %s, grace %s",
			ErrGraceExhausted, leaf.NotAfter.UTC().Format(time.RFC3339), grace)
	}

	var intermediates *x509.CertPool
	if len(chain) > 1 {
		intermediates = x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         c.Pool(),
		Intermediates: intermediates,
		CurrentTime:   leaf.NotAfter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); verr != nil {
		return tunnel.Identity{}, false, fmt.Errorf("%w: %w", ErrUntrustedChain, verr)
	}
	id, ierr := c.IdentityFromCert(leaf)
	if ierr != nil {
		return tunnel.Identity{}, false, ierr
	}
	return id, true, nil
}
