// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// uriScheme is the only scheme a spoke identity URI may use.
const uriScheme = "pmf"

// spokePathPrefix is the only path shape a spoke identity URI may use.
const spokePathPrefix = "/spoke/"

// IdentityFromCert extracts the authenticated spoke identity from a peer
// certificate that crypto/tls has already chain-verified against this CA.
//
// The cluster ID comes only from the certificate's single URI SAN. The Common
// Name is ignored entirely: it exists for human eyes in openssl output, and
// treating it as identity is how CN-based authentication systems get confused
// by a certificate that puts one name in the CN and another in the SAN. The
// URI must use the "pmf" scheme, its authority must equal this CA's trust
// domain exactly, its path must be exactly "/spoke/<id>", and <id> must match
// the fleet cluster ID grammar. Userinfo, query and fragment are refused
// because they carry no meaning here and their presence indicates a
// certificate built by something other than this CA.
//
// A certificate with zero URI SANs, or with more than one, has no identity: an
// ambiguous certificate must never be resolved by picking the first entry.
//
// RemoteAddr is left empty; the transport fills it in for the audit log.
func (c *CA) IdentityFromCert(cert *x509.Certificate) (tunnel.Identity, error) {
	if cert == nil {
		return tunnel.Identity{}, fmt.Errorf("%w: nil certificate", ErrNoIdentity)
	}
	if len(cert.URIs) != 1 {
		return tunnel.Identity{}, fmt.Errorf("%w: %d uri sans, want exactly 1", ErrNoIdentity, len(cert.URIs))
	}
	u := cert.URIs[0]
	if u.Scheme != uriScheme {
		return tunnel.Identity{}, fmt.Errorf("%w: uri scheme %q, want %q", ErrNoIdentity, u.Scheme, uriScheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return tunnel.Identity{}, fmt.Errorf("%w: uri carries userinfo, query or fragment", ErrNoIdentity)
	}
	if u.Host != c.opts.TrustDomain {
		return tunnel.Identity{}, fmt.Errorf("%w: uri host %q, want %q", ErrWrongTrustDomain, u.Host, c.opts.TrustDomain)
	}
	id, ok := strings.CutPrefix(u.Path, spokePathPrefix)
	if !ok {
		return tunnel.Identity{}, fmt.Errorf("%w: uri path %q, want %s<id>", ErrNoIdentity, u.Path, spokePathPrefix)
	}
	if !ValidClusterID(id) {
		return tunnel.Identity{}, fmt.Errorf("%w: %w: %q in uri path", ErrNoIdentity, ErrInvalidClusterID, id)
	}
	return tunnel.Identity{
		ClusterID:    id,
		CertSerial:   SerialHex(cert.SerialNumber),
		CertNotAfter: cert.NotAfter,
	}, nil
}
