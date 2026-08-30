// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package promclient is the spoke's HTTP client to the Prometheus-compatible
// server running beside it in its own cluster. It is the spoke half of
// [tunnel.Handler].
//
// It is deliberately dumb. It does not parse Prometheus result JSON for tunnel
// traffic: it re-validates the requested path against [promapi], performs the
// call, and streams opaque bytes back to the hub. That keeps the spoke small
// and forward-compatible with Thanos, Mimir, Cortex and VictoriaMetrics, whose
// response bodies differ in ways a parsing spoke would have to track.
//
// Security: the hub has already checked the request against the allow-list
// before sending it. This package checks it again with [promapi.Lookup] and
// [promapi.Validate]. That duplication is the point — BUILD_SPEC section 9
// requires that the hub's check is never the only one, so a compromised or
// buggy hub still cannot reach /api/v1/admin/tsdb/delete_series, /-/reload or
// /debug/pprof through a spoke.
//
// Who may import it: internal/clusterfacts and internal/spoke. It sits at L1
// and must not import any L2 or higher package.
//
// Concurrency: a [Client] is safe for concurrent use by many goroutines and is
// intended to be shared; it holds one pooled [net/http.Client].
package promclient
