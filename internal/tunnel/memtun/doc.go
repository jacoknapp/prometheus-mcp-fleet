// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package memtun is an in-process implementation of the hub<->spoke tunnel: no
// network, no TLS, no gRPC, no goroutine-per-connection accept loop. It exists
// so the hub's registry, proxy and MCP layers can be tested against a real
// tunnel.Session in microseconds.
//
// # Role reversal, collapsed
//
// The real transport (internal/tunnel/grpctun) inverts roles: the spoke dials
// the hub and then serves gRPC over the connection it opened, so the hub is the
// gRPC client. memtun keeps the same shape with the wire removed:
//
//	   real transport                          memtun
//	┌────────────────┐                    ┌────────────────┐
//	│ tunnel.Handler │                    │ tunnel.Handler │
//	└───────┬────────┘                    └───────┬────────┘
//	  grpc.Server (spoke)                   direct call
//	        │                                     │
//	  TCP + mTLS socket                     io.Pipe per request
//	        │                                     │
//	  grpc.ClientConn (hub)                 direct call
//	┌───────┴────────┐                    ┌───────┴────────┐
//	│ tunnel.Session │                    │ tunnel.Session │
//	└────────────────┘                    └────────────────┘
//
// # Fidelity is the whole point
//
// A fake that is easier than reality hides the bugs reality would have found,
// so memtun reproduces every observable rule the real transport obeys:
//
//   - Do returns as soon as the head is available; the body is streamed, not
//     buffered, through an io.Pipe whose blocking writer stands in for HTTP/2
//     flow control.
//   - Cancelling the request context aborts the handler mid-body.
//   - Deadlines reach the handler, exactly as grpc-timeout would deliver them.
//   - MaxResponseBytes delivers precisely that many bytes and then reports
//     tunnel.ErrResponseTooLarge, with Trailer().Truncated set.
//   - A handler-reported trailer error terminates the body with that error
//     rather than io.EOF, because an incomplete response must not look
//     complete. Like the real transport, the error crosses as a message
//     string, so the caller cannot errors.Is it back to the handler's sentinel.
//   - Trailer() is the zero value until the body is fully read or closed.
//   - After Close, Do returns tunnel.ErrSessionClosed and Done() is closed.
//   - Generation() is 0 until the first Describe reports changed facts.
//
// # Who may import this
//
// Tests, anywhere in the module. It is a test double that happens to live
// outside _test.go so any package can use it.
//
// # Concurrency
//
// The returned Session is safe for concurrent use, including concurrent Do
// calls whose bodies interleave.
package memtun
