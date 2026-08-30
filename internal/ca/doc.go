// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ca is the hub's built-in X.509 certificate authority.
//
// # Responsibility
//
// The hub is its own root of trust. This package owns a single, offline-shaped
// root keypair whose production responsibility is signing spoke client
// certificates:
//
//   - spoke client certificates, minted during enrollment, which are the only
//     thing that establishes a spoke's identity to the hub.
//
// # Trust model
//
// A spoke's cluster ID is read exclusively from the URI SAN
// "pmf://<trust-domain>/spoke/<cluster-id>" of a certificate that crypto/tls
// has already chain-verified against this CA. The Common Name is decorative:
// [CA.IdentityFromCert] never looks at it, so an operator cannot accidentally
// create an identity by naming a certificate. Nothing a spoke reports over the
// tunnel at runtime may override the certificate-derived identity.
//
// Correspondingly, [CA.IssueSpokeFromCSR] throws away every subject and SAN the
// certificate signing request asked for and mints its own from the cluster ID
// the hub already bound to the enrollment token. A CSR is a way to transport a
// public key and prove possession of the matching private key; it is not a
// request for attributes. This is why an enrollment token that leaks cannot be
// redeemed for a different cluster's identity, and why a CSR claiming
// "CN=admin" gets a certificate that says "CN=spoke:<its-cluster-id>".
//
// This package deliberately does not track which public keys it has already
// certified. Single-use enforcement lives with the enrollment token: the caller
// burns the token with one atomic conditional update before or alongside
// calling [CA.IssueSpokeFromCSR], and a second redemption is a security event
// rather than a retry.
//
// # Key loss and compromise
//
// The CA private key is the whole fleet. Losing it means every spoke must be
// re-enrolled by hand, because nothing can issue a certificate the hub will
// accept; that is why [LoadOrCreate] refuses to regenerate when only one of the
// two files is present, and why [Create] refuses to overwrite. Leaking it means
// an attacker can mint a certificate for any cluster ID and read every
// cluster's metrics through the hub, so the key is written 0600, is never
// returned by any exported method, never appears in a String method, and is
// never logged. Back it up out of band, encrypted; the hub itself has no backup
// mechanism.
//
// # Rotation
//
//   - Spoke certificates are short-lived (14 days by default) and are rotated
//     by re-enrolling or by renewing well before expiry. Because the identity
//     lives in the SAN and not in the key, a renewed certificate is
//     indistinguishable from the old one to the registry.
//   - Revocation is not CRL-driven in the WebSocket tunnel. Its application
//     handshake consults the live revocation store, which is immediate and
//     cannot be stale. [CA.CRL] exists to publish the same information to
//     consumers outside the hub.
//   - The root itself has a 10 year default lifetime and no automated rotation.
//     Rotating it is a fleet-wide re-enrollment and must be planned; the hub
//     reports readiness as false once the root is within 24h of expiry so the
//     situation is loud rather than silent.
//
// # Concurrency
//
// A [CA] is immutable after construction and every method on it is safe for
// concurrent use. [LoadOrCreate] and [Create] are safe against concurrent
// processes racing to initialise the same paths: creation reserves both paths
// with O_EXCL before writing, so exactly one racer wins and the loser observes
// [ErrCAExists].
//
// # Importers
//
// Layer 1. It may import internal/fleet and internal/tunnel and nothing else
// from this module.
package ca
