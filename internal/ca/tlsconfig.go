// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// alpnH2 is the only application protocol the tunnel speaks. Pinning it means
// a client that negotiates anything else is rejected during the handshake
// rather than confusing the gRPC layer later.
const alpnH2 = "h2"

// ServerTLSConfig returns the TLS configuration for the hub's tunnel listener.
//
// It is TLS 1.3 only, requires and verifies a client certificate chaining to
// this CA, and negotiates only "h2". Chain construction, expiry and extended
// key usage are left to crypto/tls, which does them correctly; the
// VerifyPeerCertificate hook only adds what crypto/tls cannot know:
//
//   - the leaf must yield a valid spoke identity, so a certificate signed by
//     this CA but lacking the URI SAN cannot open a tunnel with no cluster ID;
//     and
//   - isRevoked is consulted with the leaf's lowercase hex serial on every
//     handshake, which makes revocation take effect immediately instead of
//     waiting for a CRL refresh.
//
// isRevoked may be nil, in which case nothing is treated as revoked. It is
// called on the handshake path and must be fast and safe for concurrent use.
//
// The returned config carries the CA's injected clock, so tests can drive
// certificate expiry deterministically.
func (c *CA) ServerTLSConfig(serverCert tls.Certificate, isRevoked func(serial string) bool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    c.Pool(),
		NextProtos:   []string{alpnH2},
		Time:         c.now,
		VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("%w: no verified chain", ErrNoIdentity)
			}
			leaf := verifiedChains[0][0]
			if _, err := c.IdentityFromCert(leaf); err != nil {
				return err
			}
			if isRevoked != nil && isRevoked(SerialHex(leaf.SerialNumber)) {
				return fmt.Errorf("%w: serial %s", ErrCertRevoked, SerialHex(leaf.SerialNumber))
			}
			return nil
		},
	}
}
