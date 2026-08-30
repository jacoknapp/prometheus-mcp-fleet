// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package store persists the hub's credentials and certificate revocation
// list. There is no database and no volume.
//
// # Responsibility
//
// The store owns durability and atomicity, nothing else. It does not hash
// secrets (internal/token), does not decide whether a credential authorizes a
// request (internal/authn), and does not issue certificates (internal/ca). Its
// one piece of security-relevant logic is [Store.BurnEnrollment], because
// "redeem this token at most once" is only expressible where the write
// boundary is.
//
// # What is persisted, and what is not
//
// Persisted: issued key records, single-use enrollment burn state, and
// revoked certificate serials. Not persisted: the cluster registry. Spokes
// dial the hub and re-publish their facts, so the registry is derivable
// within seconds of a restart and lives purely in memory in
// internal/registry. A cluster that has never reconnected simply does not
// appear, which is the truth and is better than showing an agent a stale
// entry it might query.
//
// # Backends
//
// Both shipped backends store one JSON document, [State], and differ only in
// where the bytes live:
//
//   - internal/store/secretstore is production. The document is one key of one
//     Kubernetes Secret, and every write is a read-modify-write conditional on
//     the Secret's resourceVersion. That compare-and-swap is what makes the
//     single-use enrollment burn atomic across hub replicas -- the property
//     the earlier single-writer file design got from having exactly one
//     writer, recovered without giving up horizontal scaling.
//   - internal/store/filestore is local development and tests. One 0600 file,
//     written by temp file and rename, guarded by an in-process mutex.
//
// The document and every mutation on it live here rather than in the
// backends, so the epoch rules, the ordering guarantees and the burn-once rule
// exist once. A backend is then load bytes, apply, store bytes, and
// internal/store/storetest.RunSuite proves the two behave identically.
//
// # Size
//
// A Kubernetes Secret is capped at 1 MiB. A write that would push the encoded
// document past [MaxStateBytes] is refused with [ErrStateTooLarge] naming the
// record counts, and secretstore exposes the current size so the hub can
// publish promfleet_hub_state_bytes and alert on it long beforehand.
//
// # Revocation epoch
//
// [Store.Epoch] is a monotonically increasing counter bumped by any mutation
// that can change an authorization outcome: creating, revoking, deleting or
// burning a key, and revoking a certificate. Verifiers cache credential
// lookups and discard the cache when the epoch moves, which is what makes a
// revocation take effect fleet-wide within one request rather than within one
// cache TTL. [Store.TouchKey] deliberately does not bump it: it runs on every
// authenticated request, and bumping there would invalidate every cache
// continuously and turn the cache into a pure cost.
//
// # Importers and concurrency
//
// Layer L1. May be imported by internal/authn, internal/ca, internal/hubapi
// and the hub composition root. Every [Store] method is safe for concurrent
// use by multiple goroutines, and every method returns [ErrClosed] once
// [Store.Close] has returned. [State] itself is not: it is a per-operation
// value owned by whichever backend decoded it.
package store
