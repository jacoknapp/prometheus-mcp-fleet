// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package secretstore is the production store.Store backend: the hub's whole
// credential state as one JSON document in one Kubernetes Secret.
//
// # Responsibility
//
// It owns where the bytes live and how a write is made atomic. The document
// format and every mutation belong to internal/store; the Kubernetes wire
// protocol belongs to internal/kube.
//
// # Why a Secret
//
// The state is small, it is entirely secret material, and it must be shared
// by every hub replica. A Secret is all three: replicated, encrypted at rest
// if the cluster is configured for it, and -- the part that matters most --
// carrying a resourceVersion, which is a compare-and-swap primitive.
//
// # How a write works
//
// Read the Secret, decode the document, apply the mutation, encode, and PUT
// with the resourceVersion the read returned. The API server accepts exactly
// one write per resource version, so two hub replicas redeeming the same
// single-use enrollment token cannot both win: the loser gets a 409, re-reads,
// sees the token already burned and returns store.ErrEnrollmentUsed. That is
// the property the earlier single-writer embedded database got from having
// exactly one writer, recovered without giving up horizontal scaling.
//
// A 409 is retried with jittered exponential backoff, at most
// [Options.MaxAttempts] times. The cap is deliberate: sustained conflict means
// something is wrong -- a write loop, far more replicas than intended -- and
// retrying forever would turn that into an invisible latency problem rather
// than a reported one.
//
// # Caching
//
// Reads are served from a short in-process cache keyed on resourceVersion, so
// that a burst of authentications does not become a burst of API server
// calls. The cache is refreshed after every write this replica makes and
// dropped on every conflict, so it can only ever be stale by another
// replica's write within [Options.CacheTTL]. That is acceptable for reads --
// a credential that another replica revoked a moment ago is caught on the
// next refresh -- and irrelevant for writes, which are validated by the
// compare-and-swap regardless of what the cache said.
//
// # Size
//
// A Secret is hard-capped at 1 MiB by the API server. A write that would push
// the document past [Options.MaxBytes] (default store.MaxStateBytes) is
// refused with store.ErrStateTooLarge naming the record counts, and
// [Store.Size] exposes the current size so the hub can publish
// promfleet_hub_state_bytes and alert long before a write actually fails.
//
// # RBAC
//
// The hub's ServiceAccount needs get, create and update on Secrets,
// restricted by resourceNames to the state Secret. A missing Role surfaces as
// kube.ErrForbidden, whose message names the exact rule.
//
// # Importers and concurrency
//
// Layer L1. May be imported by the hub composition root and by tests. A
// [Store] is safe for concurrent use by multiple goroutines; correctness
// across replicas comes from the compare-and-swap, not from any local lock.
package secretstore
