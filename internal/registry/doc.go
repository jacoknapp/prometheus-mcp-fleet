// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package registry is the hub's live view of the fleet: which clusters hold a
// tunnel right now, and what facts each spoke last published.
//
// # Responsibility
//
// The registry is the only place that decides which [tunnel.Session] pool
// serves a cluster. A cluster runs one spoke pod by convention, but every
// operation a spoke serves is a read-only, idempotent Prometheus query, so a
// cluster may run several pods for its own availability and their sessions
// are interchangeable. The registry holds one pool per cluster keyed by pod
// identity rather than a single session, so siblings coexist instead of
// continually evicting each other. There is deliberately no leader election
// among them: nothing they serve needs serialising, and an election would add
// split-brain risk, lease RBAC and failover latency for no benefit.
//
// What has not changed is reconnect resolution *within* a pod's own slot.
// Spokes reconnect constantly — rollouts, node drains, network blips — and two
// sessions for the same pod can be in flight at once. The registry resolves
// that with a generation compare-and-swap keyed on the spoke's process start
// time, so a stale reconnect racing a fresh one always loses, and it loses the
// same way every time.
//
// It is also the boundary at which self-reported data stops being trusted for
// identity: a cluster's ID comes from the verified client certificate and
// nothing a spoke says at runtime can change it. The pod identity used to pick
// a slot ([tunnel.Identity.InstanceID], falling back to CertSerial) is also
// self-reported, but it authenticates nothing — it only decides which slot a
// session occupies inside a cluster it is already authorized for by
// certificate. A spoke that lied about it could at worst displace its own
// sibling's session.
//
// # No persistence, by design
//
// The registry is self-registering and lives purely in memory. There is no
// store, no database and no PVC behind it. Spokes reconnect on a bounded
// backoff and re-publish their facts, so the whole registry is derivable and
// is rebuilt within one reconnect backoff of a hub restart. A cluster that has
// never connected simply does not appear, which is the truth and is better
// than showing a stale entry an agent would then try to query.
//
// A cluster whose last live session has just dropped is *not* forgotten
// immediately — the grace window is scoped to the cluster's whole pool, not to
// any one pod, so a cluster with even one remaining sibling is never treated
// as disconnected. Only once every pod is gone does it linger, as
// [fleet.StateDisconnected] with its last known facts and
// [fleet.Cluster.LastSeen], for [Options.DisconnectGrace] (default
// [DefaultDisconnectGrace]), so that an agent asking about a cluster that fell
// over thirty seconds ago is told "disconnected, last seen 30s ago" rather
// than "no such cluster". Once the grace window elapses the entry is dropped
// and the cluster is genuinely unknown again. Set DisconnectGrace to a
// negative value to disable the window and forget on disconnect.
//
// # Revocation
//
// The registry is also where a revoked certificate stops being served.
// Revocation is checked at the tunnel handshake, which only ever stops the
// *next* connection: a session that is already up would keep answering
// queries until its certificate expired. [Registry.CloseRevoked] closes the
// live sessions a set of serials admitted, and [Registry.CloseRevokedBy] does
// the same for whatever a predicate calls revoked, which is how a hub replica
// enforces a revocation performed on a different replica -- sessions are
// pinned to one replica and there is no hub-to-hub forwarding, so each one
// polls the shared revocation list it already consults at handshake time.
//
// Both remove the slot from its cluster's pool before closing anything, under
// the same write lock [Registry.OnSession] and the release function take, so
// no further query is routed to a revoked spoke even if the transport is slow
// to hang up. A session that was displaced or released while the predicate ran
// is left alone: the slot identity is re-checked under the lock, so a
// revocation sweep can never close the session that replaced its target.
//
// # Facts polling
//
// Each live session gets one goroutine that polls [tunnel.Session.Describe] on
// [Options.FactsPollInterval], passing the fingerprint the registry already
// holds so an unchanged spoke replies with Changed=false and only refreshes
// LastSeen.
//
// Goroutine-per-session is chosen over a shared ticker with a worker pool
// deliberately. The fleet is bounded at a few hundred spokes by
// PMF_MAX_SPOKES, so this is a few hundred goroutines parked in a select —
// cheaper than the bookkeeping a shared scheduler needs. More importantly it
// isolates failure: a spoke whose Describe hangs until its timeout consumes
// only its own goroutine, where a shared pool of size N would let N slow
// spokes stall polling for every other cluster. It also gives each session a
// natural cancellation point (the session's own Done channel) instead of a
// central map of per-cluster cancel functions.
//
// # Allowed importers
//
// L2 and above: internal/promproxy, internal/hubapi, internal/mcptools,
// internal/hub. The registry itself imports only internal/fleet and
// internal/tunnel, so it can be exercised against any transport.
//
// It deliberately does not import internal/obs or internal/store. It takes a
// stdlib [*log/slog.Logger] and the narrow [Metrics] interface declared here,
// which the hub's composition root adapts to its Prometheus collectors. That
// keeps this package testable without a metrics registry or any I/O.
//
// # Concurrency
//
// [Registry] is safe for concurrent use by any number of goroutines. Read
// methods ([Registry.List], [Registry.Visible], [Registry.Session],
// [Registry.Cluster], [Registry.Nearest], [Registry.ConnectedCount]) are on
// the hot path of every MCP request and take a read lock only; they return
// deep copies, so a caller can never observe or mutate registry state through
// a returned value.
package registry
