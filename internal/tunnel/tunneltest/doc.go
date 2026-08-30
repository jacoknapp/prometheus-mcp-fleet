// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package tunneltest is the single conformance suite that every implementation
// of the hub<->spoke tunnel must pass.
//
// There are two implementations. internal/tunnel/grpctun is the real one: a
// spoke dials the hub over mTLS and then, roles reversed, runs the gRPC server
// on the connection it opened while the hub runs the client over the socket it
// accepted. internal/tunnel/memtun is the in-process one, with the wire
// removed. The point of running one suite against both is that swapping them
// has to be a decision about speed, never about semantics: if memtun were
// allowed to be more forgiving than grpctun, every hub test written against it
// would be measuring a fiction.
//
//	             RunConformance(t, factory)
//	                       │
//	       ┌───────────────┴───────────────┐
//	       ▼                               ▼
//	memtun.Pair(...)              grpctun listener + dialer
//	direct calls                  real TCP, real TLS, real HTTP/2
//	       │                               │
//	       └───────────────┬───────────────┘
//	                       ▼
//	                tunnel.Session
//
// # Who may import this
//
// Tests, anywhere in the module.
//
// # Concurrency
//
// EchoHandler is safe for concurrent use; the suite depends on that, because
// proving that two streams interleave on one session is the reason the
// transport is shaped the way it is.
package tunneltest
