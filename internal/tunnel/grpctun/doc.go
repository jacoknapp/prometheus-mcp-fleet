// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package grpctun implements the hub<->spoke tunnel from
// [github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel] on top of a
// reversed-role gRPC connection.
//
// # Role reversal
//
// The spoke dials the hub, because asking a hundred cluster operators to open
// an inbound firewall hole is not a plan. Once the peer has been authenticated
// the transport roles invert: the side that dialled runs the gRPC *server* and
// the side that accepted runs the gRPC *client*.
//
//	        spoke process                                 hub process
//	┌───────────────────────────┐              ┌───────────────────────────┐
//	│ grpc.Server               │              │ grpc.ClientConn           │
//	│   SpokeServiceServer      │              │   SpokeServiceClient      │
//	│   (bridges tunnel.Handler)│              │   (implements tunnel.     │
//	│                           │              │    Session)               │
//	└────────────┬──────────────┘              └─────────────┬─────────────┘
//	             │ ServeConn(c)                              │ NewClient(
//	             │                                           │  "passthrough:///spoke",
//	             │                                           │  WithContextDialer(->c))
//	             │        ┌──────────────────────────┐       │
//	             └───────►│  one authenticated conn  │◄──────┘
//	               dial   │  HTTP/2, multiplexed     │  ConnSource.Accept
//	                      └──────────────────────────┘
//
// # Where the connection comes from
//
// This package does not dial, listen, or authenticate. Both halves take a
// net.Conn whose peer identity is already settled: the hub through
// [ConnSource], the spoke by handing one to [ServeConn]. Transports plug in at
// that seam, which is why the WebSocket transport of ADR-0014
// (internal/tunnel/wstun) replaced raw mTLS on its own port without a second
// copy of anything below.
//
// Everything that makes this transport pleasant falls out of that inversion for
// free, because it is all standard HTTP/2 machinery: many concurrent Proxy
// streams over one socket, per-stream flow control so a 40 MiB query_range
// cannot starve a 2 KiB label lookup, RST_STREAM when the hub cancels a
// request, grpc-timeout for deadline propagation, and keepalive PINGs for
// liveness. None of it is implemented here.
//
// # Who may import this
//
// Only composition roots (internal/hub, internal/spoke) and tests. Everything
// else depends on the transport-agnostic interfaces in internal/tunnel.
//
// # Streaming
//
// A session's Do method returns as soon as the response head arrives. The
// returned body pulls further chunks lazily, one gRPC message at a time, so a
// large response is never materialised in a single message or a single buffer.
// The per-call receive limit is deliberately kept at 1 MiB: if you ever find
// yourself raising it, the streaming has been broken somewhere.
//
// # Concurrency
//
// Every exported type is safe for concurrent use. A single Session may carry
// any number of simultaneous Do calls; each becomes its own HTTP/2 stream.
package grpctun
