// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package promproxy is the hub side of one Prometheus call: authorize, build,
// budget, route, cap, and map the failure.
//
// # Responsibility
//
// Everything between "an MCP tool decided what it wants" and "bytes came back
// from a cluster" happens here, in that order:
//
//  1. Authorize the principal against the target cluster.
//  2. Build the upstream path and validate the parameters with
//     internal/promapi. A caller-supplied path is never accepted; there is no
//     field in [Call] that could carry one.
//  3. Clamp the timeout and the byte cap, taking the more restrictive of the
//     hub's configuration and the principal's [fleet.Limits].
//  4. Acquire the per-cluster in-flight slot and the global response-byte
//     budget.
//  5. Perform the call over the tunnel and read the body under a hard cap,
//     inflating gzip as it goes.
//  6. Map the outcome onto [ErrForbidden], [ErrTooLarge], [ErrBusy] or
//     [ErrUpstream].
//
// It does not parse the response. The body is opaque bytes all the way to
// internal/mcptools, which owns JSON shaping, the redaction of scrape URLs in
// /api/v1/targets, and prompt-injection sanitisation. Keeping the proxy
// byte-oriented is what lets the same code path serve Thanos and Mimir.
//
// # Denial does not confirm existence
//
// Authorization runs before the registry lookup is allowed to influence the
// answer. When [fleet.Scope.AllowsCluster] rejects the cluster the result is
// [ErrForbidden], whether or not that cluster exists — the check is run
// against the registry entry's labels when it exists and against no labels
// when it does not, and both paths produce the identical error. Only a
// principal that *would* have been allowed to reach the cluster learns that it
// is unknown, via [registry.ErrUnknownCluster]. Without that, an agent could
// enumerate the fleet by timing or by comparing error strings, which is a real
// disclosure across a multi-tenant hub.
//
// # Budgets
//
// Two semaphores guard the hub's memory. The per-cluster in-flight semaphore
// refuses rather than queues: an overloaded cluster returns [ErrBusy] with a
// retry hint immediately, because an unbounded queue in front of a slow
// Prometheus converts one slow cluster into hub-wide latency. The global
// response-byte semaphore is acquired for the call's *maximum* size before the
// request is made, and it does wait, bounded by the request's own deadline —
// admitting a request whose worst case does not fit is how a hundred
// concurrent 32 MiB responses become an OOM.
//
// # Fan-out
//
// [Proxy.Fanout] runs the same call across many clusters at a bounded
// concurrency and returns one [FanoutResult] per cluster, in the input order.
// Failure is per cluster: a forbidden, unknown, disconnected or busy cluster
// occupies its own slot and costs the caller nothing else. The concurrency
// bound is not politeness — every in-flight call reserves its worst-case size
// against the hub-wide byte budget, so an unbounded fan-out would exhaust that
// budget and start refusing unrelated callers.
//
// # Allowed importers
//
// L3 and above: internal/mcptools, internal/hubapi, internal/hub. This package
// imports internal/fleet, internal/promapi, internal/registry and
// internal/tunnel only; like the registry it takes a stdlib [*log/slog.Logger]
// and its own [Metrics] interface rather than importing internal/obs.
//
// # Concurrency
//
// [Proxy] is safe for concurrent use by any number of goroutines and is
// expected to be shared by every MCP request. [Result] is owned by its caller.
package promproxy
