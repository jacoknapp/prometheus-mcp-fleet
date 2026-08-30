// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import "errors"

// Sentinel errors. Every error this package returns wraps exactly one of these
// with %w, so callers branch with errors.Is and never on error strings.
var (
	// ErrNoIdentity is returned when a peer certificate carries no usable
	// spoke identity: no URI SAN, more than one URI SAN, a non-"pmf" scheme,
	// a path that is not exactly "/spoke/<id>", or an <id> that fails the
	// cluster ID grammar.
	ErrNoIdentity = errors.New("ca: certificate carries no spoke identity")

	// ErrWrongTrustDomain is returned when a peer certificate's URI SAN is
	// well formed but names a different trust domain than this CA is
	// configured for. It is separate from ErrNoIdentity because it usually
	// means a spoke was pointed at the wrong hub rather than that it is
	// hostile.
	ErrWrongTrustDomain = errors.New("ca: certificate is for a different trust domain")

	// ErrCSRInvalid is returned when a certificate signing request cannot be
	// parsed, fails its own signature check, or carries a public key outside
	// the accepted profile.
	ErrCSRInvalid = errors.New("ca: invalid certificate signing request")

	// ErrCAExists is returned by Create when either the certificate or the key
	// path is already present. A CA is never overwritten: doing so would
	// orphan every enrolled spoke.
	ErrCAExists = errors.New("ca: certificate authority already exists")

	// ErrCANotFound is returned by Load when the certificate or key file does
	// not exist.
	ErrCANotFound = errors.New("ca: certificate authority not found")

	// ErrCAIncomplete is returned by LoadOrCreate when exactly one of the two
	// files exists. Regenerating in that state would silently mint a new root
	// and orphan the fleet, so it is always an operator error.
	ErrCAIncomplete = errors.New("ca: incomplete certificate authority on disk")

	// ErrInsecureKeyMode is returned when the private key file is group- or
	// world-readable.
	ErrInsecureKeyMode = errors.New("ca: private key file is group- or world-readable")

	// ErrInvalidCA is returned when the material on disk parses but is not a
	// usable CA: not a certificate, not an ECDSA P-256 key, the key does not
	// match the certificate, or the certificate is not a certificate-signing
	// CA.
	ErrInvalidCA = errors.New("ca: invalid certificate authority material")

	// ErrCAExpired is returned when the CA certificate has expired, or has so
	// little life left that the requested leaf would not be valid at all.
	ErrCAExpired = errors.New("ca: certificate authority has expired")

	// ErrInvalidClusterID is returned when a cluster ID does not match
	// ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$.
	ErrInvalidClusterID = errors.New("ca: invalid cluster id")

	// ErrInvalidOptions is returned when Options are internally inconsistent,
	// for example a malformed trust domain or a negative lifetime.
	ErrInvalidOptions = errors.New("ca: invalid options")
)
