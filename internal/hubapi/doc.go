// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package hubapi is the hub's non-MCP HTTP surface: credential administration,
// spoke enrollment and PKI publication.
//
// # Two muxes, two listeners, two trust levels
//
// [NewAdminMux] serves /admin/v1/... and is mounted on the admin listener,
// which is ClusterIP-only and never exposed through an Ingress. Every route on
// it requires a `pmf_adm_` credential.
//
// [NewPublicMux] serves the routes that must be reachable from a cluster that
// has not been enrolled yet: /enroll (a single-use `pmf_enr_` credential),
// /renew/challenge and /renew (a certificate plus a signed challenge, and no
// bearer credential at all), the CA bundle, the CRL, and the RFC 9728
// protected-resource document. It is mounted alongside the MCP handler on the
// public listener.
//
// Both are built on the standard library's [net/http.ServeMux] method+path
// patterns. There is no router dependency, and there is no route whose path is
// derived from caller input.
//
// # Invariants this package exists to hold
//
//   - A raw credential is returned exactly once, in the response to the call
//     that minted it, and is never recoverable afterwards. The response says so
//     in a field an operator cannot miss.
//   - No response body, log line or error ever contains a stored HMAC, the
//     pepper, or a private key. Records are projected through [KeyView], which
//     has no field for any of them.
//   - Enrollment is single use. The token is burned with one atomic
//     conditional store update before the certificate leaves the process, and a
//     losing burn is answered 409 and logged as a security event, because a
//     replayed enrollment token means the install secret leaked.
//   - The hub ignores a CSR's subject and SANs entirely. The identity in the
//     issued certificate is the one the hub decided on when it minted the
//     enrollment token, so a CSR asking for "CN=admin" gets a spoke
//     certificate for its own cluster and nothing else.
//   - /renew takes the cluster identity from the URI SAN of the certificate the
//     caller proved possession of, and from nowhere else. [RenewRequest] has no
//     cluster field, so nothing in the request body can influence it.
//   - /renew reads no TLS state. Behind the Ingress of ADR-0014 there is none
//     to read, so possession is proved at the application layer with the same
//     construction the tunnel handshake uses
//     ([github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof]). A
//     handler that consulted r.TLS here would work in a lab and refuse every
//     renewal in production, which is exactly what it did once.
//
// # Revocation is enforced, not only recorded
//
// Adding a serial to the revocation list stops the next tunnel handshake. It
// does nothing to the tunnel that serial already holds, which during a
// compromise is the only one that matters, so this package closes it too.
//
// POST /admin/v1/certs/{serial}/revoke closes the sessions that certificate
// admitted on the replica serving the request ([Options.Sessions]), and
// [RevocationEnforcer] closes them on every other replica: a session is pinned
// to the hub that accepted it, there is no hub-to-hub forwarding, and the
// revocation list is the only thing the replicas share. Both record
// [EventSessionRevoked], which is the audit evidence that a spoke was
// disconnected rather than merely listed.
//
// The enforcer is the one thing here that is not an HTTP handler. It lives in
// this package because what it enforces is a credential lifecycle decision
// this package took, and because the audit record it writes has to be the same
// record the handler writes.
//
// # Importers and concurrency
//
// Layer L2. It imports internal/fleet, internal/token, internal/ca,
// internal/authn and internal/store, and declares the slice of persistence it
// needs as [AdminStore] rather than depending on a particular backend. The
// dependency on internal/store is on the interface package only, and it is
// deliberate: [RevokedCert] is an alias for the store's own record type so
// that the shipped [store.Store] satisfies [AdminStore] by identity rather
// than by shape, and so the error-classification defaults recognise the store's
// sentinels. Both are asserted at compile time in options.go.
//
// The handlers returned by the constructors are safe for concurrent use.
package hubapi
