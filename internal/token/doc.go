// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package token mints, parses and verifies the hub's `pmf_` bearer
// credentials.
//
// # Responsibility
//
// This package owns exactly one thing: the on-the-wire credential format and
// the keyed hash that turns a presented secret into the value stored in the
// database. It performs no lookups, holds no state about which credentials
// exist, and makes no authorization decisions. Those belong to internal/store
// and internal/authn respectively.
//
// # Wire format
//
// Every token, of every class, has the same fixed length of 68 bytes:
//
//	pmf_agt_ 3Kf9aQ2mZx <43 base62 chars of secret> _ 9dK2mQ
//	└prefix─┘└─KID (10)┘└────── SECRET (256 bit) ──┘ └CRC(6)┘
//
// The fields are:
//
//   - Prefix is "pmf_" followed by the three-character [fleet.KeyClass] and an
//     underscore. It exists so a leaked token is greppable and so GitHub secret
//     scanning has an anchor; see [Pattern].
//   - KID is 10 base62 characters of CSPRNG output. It is public and
//     non-secret: it is the database lookup key and is safe to write to audit
//     logs. 62^10 ~= 8.4e17 makes accidental collision irrelevant.
//   - SECRET is 32 bytes (256 bits) of CSPRNG output rendered as the big-endian
//     base62 integer, left-padded with '0' to exactly 43 characters. 62^43 is
//     ~1.18e77, just above 2^256 (~1.16e77), so 43 characters is the smallest
//     fixed width that can represent every 256-bit value. Fixed width keeps the
//     whole token a constant length, which makes truncation detectable.
//   - CRC is CRC-32C (Castagnoli) over every byte before the final underscore,
//     rendered as exactly 6 base62 characters, left-padded with '0'. Its only
//     job is to reject typos and truncated pastes cheaply, before any database
//     or cryptographic work happens. It is not a security control: it is
//     public, unkeyed, and an attacker can compute it.
//
// # Storage
//
// The secret is never stored. [Hasher.Sum] reduces it to
// HMAC-SHA256(pepper, secret), where the pepper lives outside the database (see
// [LoadOrCreatePepper]). A password KDF such as Argon2id would buy nothing here
// -- the secret is 256 bits of CSPRNG output, so there is no dictionary to
// mount -- while handing an unauthenticated caller a CPU-exhaustion primitive.
//
// # Handling
//
// The raw token exists in one place, [Minted.Raw], and its type redacts itself
// through [fmt.Stringer], [slog.LogValuer] and [json.Marshaler]. Never convert
// it back to a plain string except at the exact point of delivery to the
// operator, via [RawToken.Reveal].
//
// # Importers and concurrency
//
// Layer L1. May be imported by internal/authn, internal/hubapi and the
// composition roots. Imports only the standard library and internal/fleet.
// [Hasher] is safe for concurrent use by multiple goroutines; every other
// function is stateless.
package token
