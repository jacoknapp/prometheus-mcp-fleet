// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// RevokedEntry is one revoked certificate.
type RevokedEntry struct {
	// Serial is the certificate serial in lowercase hexadecimal, exactly as
	// SerialHex renders it and as tunnel.Identity.CertSerial carries it.
	Serial string
	// RevokedAt is when the revocation took effect.
	RevokedAt time.Time
}

// CRL builds and signs a DER certificate revocation list over revoked.
//
// thisUpdate is the CRL's issue time; a zero value means "now" according to
// the CA's clock. validity must be positive and sets NextUpdate. The CRL
// number is derived from thisUpdate in nanoseconds, which is monotonic for any
// sane issuance sequence and therefore satisfies RFC 5280's requirement that
// numbers increase.
//
// This CRL is a publication mechanism for consumers outside the hub. The hub's
// own tunnel listener does not use it: ServerTLSConfig consults a live
// predicate instead, which cannot be stale.
func (c *CA) CRL(revoked []RevokedEntry, thisUpdate time.Time, validity time.Duration) ([]byte, error) {
	if validity <= 0 {
		return nil, fmt.Errorf("%w: crl validity %s must be positive", ErrInvalidOptions, validity)
	}
	if thisUpdate.IsZero() {
		thisUpdate = c.now()
	}
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		serial, ok := new(big.Int).SetString(r.Serial, 16)
		if !ok || serial.Sign() <= 0 {
			return nil, fmt.Errorf("%w: revoked serial %q is not positive hex", ErrInvalidOptions, r.Serial)
		}
		at := r.RevokedAt
		if at.IsZero() {
			at = thisUpdate
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: at.UTC(),
		})
	}
	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(thisUpdate.UnixNano()),
		ThisUpdate:                thisUpdate.UTC(),
		NextUpdate:                thisUpdate.Add(validity).UTC(),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign crl: %w", err)
	}
	return der, nil
}
