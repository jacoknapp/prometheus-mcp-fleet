// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"
)

// ParseTrustBundlePEM decodes a PEM trust bundle into the roots it names.
//
// A bundle is one or more concatenated CERTIFICATE blocks, in the same shape
// [CA.BundlePEM] emits and a spoke's hub.caBundle accepts. Every block must
// parse and must be a certificate-signing CA: a bundle is a list of trust
// anchors, and silently accepting a leaf or a non-CA certificate there would
// hand an operator a trust store that cannot verify anything and no error
// saying why. Text between and after blocks is ignored, so a bundle carrying
// human annotations still loads.
//
// An empty bundle is an error rather than an empty slice. Every caller here is
// asking "what should be trusted", and the answer "nothing" is always a
// mistake -- a truncated file, the wrong ConfigMap key -- never an intention.
func ParseTrustBundlePEM(b []byte) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		n := len(roots) + 1
		if blk.Type != pemTypeCertificate {
			return nil, fmt.Errorf("%w: trust bundle block %d is %q, want %q", ErrInvalidCA, n, blk.Type, pemTypeCertificate)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: trust bundle block %d: %w", ErrInvalidCA, n, err)
		}
		if defect := caSigningDefect(cert); defect != "" {
			return nil, fmt.Errorf("%w: trust bundle block %d: %s", ErrInvalidCA, n, defect)
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: trust bundle holds no certificate", ErrInvalidCA)
	}
	return roots, nil
}

// Fingerprint returns the lowercase hex SHA-256 of a certificate's DER
// encoding, or "" for a nil certificate.
//
// This is the identifier a rotation is tracked by. Neither the subject nor the
// serial will do: the successor root is minted with the same subject as the
// root it replaces, so during the overlap the two are distinguishable only by
// their key material, and a fingerprint over the whole DER is the one name
// that cannot collide between them. It is not truncated, because a truncated
// fingerprint is an invitation to argue about collision bounds in exactly the
// place where the answer must be obvious.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// TrustBundle returns the roots this authority accepts when verifying, active
// signer first. The slice is a fresh copy; the certificates in it are shared
// and must be treated as read-only.
//
// Its length is the whole state of a rotation: one root is steady state, two
// is an overlap in progress.
func (c *CA) TrustBundle() []*x509.Certificate { return slices.Clone(c.current().roots) }

// IssuerFingerprint reports which root in the trust bundle signed leaf, as a
// [Fingerprint], and whether any did.
//
// This is how the tail of a rotation is measured. Step "retire the old root
// once nothing chains to it" is otherwise a guess: certificates are reissued
// on each spoke's own renewal schedule, so the only way to know the fleet has
// finished migrating is to ask, per live certificate, which root issued it.
//
// It is not an authorisation check and must never be used as one. It verifies
// a signature and nothing else -- not validity dates, not key usage, not
// revocation. [CA.VerifyChain] is the only thing that decides whether a
// certificate is acceptable.
func (c *CA) IssuerFingerprint(leaf *x509.Certificate) (string, bool) {
	if leaf == nil {
		return "", false
	}
	for _, root := range c.current().roots {
		if leaf.CheckSignatureFrom(root) == nil {
			return Fingerprint(root), true
		}
	}
	return "", false
}
