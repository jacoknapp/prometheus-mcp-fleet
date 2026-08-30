// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package registry is the hub's live view of the fleet: which clusters hold a
// tunnel right now, and what facts each spoke last published.
//
// # Responsibility
//
// The registry is the only place that decides which [tunnel.Session] is the
// live one for a cluster. Spokes reconnect constantly — rollouts, node drains,
// network blips — and two sessions for the same cluster can be in flight at
// once. The registry resolves that with a generation compare-and-swap keyed on
// the spoke's process start time, so a stale reconnect racing a fresh one
// always loses, and it loses the same way every time.
//
// It is also the boundary at which self-reported data stops being trusted for
// identity: a cluster's ID comes from the verified client certificate and
// nothing a spoke says at runtime can change it.
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
// A cluster whose tunnel has just dropped is *not* forgotten immediately. It
// lingers as [fleet.StateDisconnected] with its last known facts and
// [fleet.Cluster.LastSeen] for [Options.DisconnectGrace] (default
// [DefaultDisconnectGrace]), so that an agent asking about a cluster that fell
// over thirty seconds ago is told "disconnected, last seen 30s ago" rather
// than "no such cluster". Once the grace window elapses the entry is dropped
// and the cluster is genuinely unknown again. Set DisconnectGrace to a
// negative value to disable the window and forget on disconnect.
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
