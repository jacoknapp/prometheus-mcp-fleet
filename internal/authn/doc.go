// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package authn turns a presented `pmf_` bearer credential into an
// authenticated [fleet.Principal].
//
// # Responsibility
//
// This package answers exactly one question: "who is calling, and is the
// credential they presented still good?". It does not decide what the caller
// may then do -- cluster and tool authorization live in [fleet.Scope] and are
// evaluated by internal/promproxy and internal/mcptools -- and it does not
// mint, store or revoke anything, which belongs to internal/hubapi and the
// store.
//
// # Hot path
//
// [Verifier.Verify] runs on every MCP request, so the order of work is a
// security property, not an optimisation:
//
//  1. [token.Parse] first. Prefix, length and CRC-32C are checked before any
//     store round trip or any keyed hash, so a malformed or truncated paste
//     costs a few hundred nanoseconds rather than a lookup.
//  2. The credential class carried in the token is compared with the class the
//     listener requires. The class is public plaintext, so rejecting here
//     leaks nothing, and it keeps an agent key from ever reaching the admin
//     store.
//  3. The verified-token cache is consulted. It is keyed on SHA-256 of the
//     whole token, never on the token itself, so a heap dump of the cache does
//     not yield a usable credential.
//  4. On a miss the KID is looked up. If the lookup fails for any reason --
//     including "no such KID" -- [token.Hasher.Decoy] still performs a full
//     HMAC-SHA256 over the presented secret, so response latency is not an
//     oracle for whether a key identifier exists.
//  5. The secret is compared with hmac.Equal and nothing else.
//  6. Stored class, expiry and revocation are enforced, in that order.
//
// # Revocation latency
//
// A cache hit re-reads the store's monotonic revocation epoch. Every mutating
// store operation except "record last used" bumps that epoch, so a single
// counter read invalidates every cached entry at once and a revocation takes
// effect within one [Options.CacheTTL] at the very worst, usually immediately.
// Recording last-used deliberately does not bump the epoch: it happens on
// every authenticated request and would otherwise keep the cache permanently
// cold.
//
// # Failure modes
//
// Every failure is closed. A store that cannot be read denies the request; it
// never falls back to a stale decision. Per-source-IP failure rate limiting
// keeps an attacker from using cache misses as a work-amplification vector
// against the store.
//
// # Importers and concurrency
//
// Layer L1. It may be imported by internal/hubapi, internal/promproxy,
// internal/mcpsurface and the composition roots. It imports internal/fleet and
// internal/token from this module. A [Verifier] is safe for concurrent use by
// any number of goroutines once constructed.
package authn
