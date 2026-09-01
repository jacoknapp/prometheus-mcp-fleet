// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ca is the hub's built-in X.509 certificate authority.
//
// # Responsibility
//
// The hub is its own root of trust. This package owns one active signing
// keypair -- and, during a root rotation, a trust bundle wider than that one
// key -- whose production responsibility is signing spoke client
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
//   - The root itself has a 10 year default lifetime and rotates itself. The
//     hub runs a state machine over the primitives here -- mint a successor,
//     trust it, promote it, retire the predecessor -- spanning a couple of
//     months and needing no operator; see internal/hub and
//     docs/adr/0015-ca-rotation.md. This package supplies the pieces and holds
//     no opinion about when they are used. The hub also reports readiness as
//     false once the active signer is within 24h of expiry, so a rotation that
//     did not happen is loud rather than silent.
//
// # Rotating the root
//
// The reason a root rotation is possible at all is that issuance and
// verification do not share a list. [CA.Certificate] is the *active signer*,
// the one keypair every new certificate is signed by. [CA.TrustBundle] is the
// *trust bundle*, every root a presented certificate is allowed to chain to,
// and [CA.BundlePEM] publishes it verbatim for spokes. In steady state the
// bundle holds exactly the active signer. During a rotation it holds two roots,
// so a spoke carrying a certificate from the outgoing root and a spoke carrying
// one from the incoming root both verify against the same hub.
//
// The moving parts are [NewRootPEM], which mints a successor into memory
// without touching a filesystem, and [CA.AdoptPEM], which installs a signer and
// a trust bundle atomically. The successor is minted and trusted first; only
// once the whole fleet has had a certificate lifetime to renew onto the
// two-root bundle does it become the signer, with the outgoing root still in
// the bundle. Ordinary renewal migrates the fleet over the following
// certificate lifetime; when [CA.IssuerFingerprint] no longer reports the old
// root for any live certificate, it is dropped. Nothing is ever re-enrolled,
// and no spoke is disconnected. The order of those steps, and the evidence each
// one waits for, belongs to the hub -- see docs/adr/0015-ca-rotation.md.
//
// [Options.AdditionalRootsPEM] is the same widening applied at construction
// time, for a root an operator wants trusted regardless of any rotation.
//
// One thing this deliberately does not do: [CA.CRL] is signed by the active
// signer only. A CRL is scoped to one issuer, so during an overlap serials
// issued by the outgoing root are not covered by the published CRL. Revocation
// in the tunnel does not use the CRL (it consults the live store, keyed on
// serial, regardless of issuer), so this affects external CRL consumers only.
//
// # Concurrency
//
// Every method on a [CA] is safe for concurrent use, without a lock and
// without a rotation ever being visible half-applied. The signer, its key and
// the trust bundle are one immutable snapshot behind an atomic pointer: nothing
// in it is written after it is published, every method reads it exactly once,
// and [CA.AdoptPEM] replaces the whole snapshot in a single store. A reader
// therefore always sees a signer together with the bundle that contains it,
// whether it started before or after a rotation.
//
// [LoadOrCreate] and [Create] are safe against concurrent processes racing to
// initialise the same paths: creation reserves both paths with O_EXCL before
// writing, so exactly one racer wins and the loser observes [ErrCAExists].
//
// # Importers
//
// Layer 1. It may import internal/fleet and internal/tunnel and nothing else
// from this module.
package ca
