// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package wstun carries the hub<->spoke tunnel over a WebSocket, so that it
// reaches the hub through a standard Kubernetes Ingress rather than needing TCP
// passthrough, a LoadBalancer or a NodePort.
//
// The transport above the WebSocket is unchanged: the frame stream is adapted
// to a net.Conn and the reversed-role gRPC of ADR-0002 runs over it exactly as
// it ran over a TLS connection. What changes is authentication. An Ingress
// terminates TLS, so the hub can never see a client certificate, and mutual
// authentication therefore happens inside the connection:
//
//	hub   -> spoke  ServerHello{nonce, protocolVersion}
//	spoke -> hub    ClientAuth{certificate chain, signature over the transcript}
//	hub             verify chain, revocation, signature; derive identity
//	hub   -> spoke  Accepted{} or close
//
// That is TLS's own CertificateVerify step performed one layer up. The private
// key never leaves the spoke and identity still comes only from the
// certificate. See docs/adr/0014-websocket-tunnel-through-standard-ingress.md
// for what this costs, in particular that the terminating Ingress is inside the
// trust boundary.
//
// # Layout
//
// [Server] is the hub half: an [net/http.Handler] mounted on the hub's
// ordinary HTTP listener, plus a [github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel.Listener]
// that hands authenticated connections to
// [github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun]. [Dial]
// is the spoke half. handshake.go holds the wire messages and the framing both
// sides share; the transcript they sign and verify lives in
// [github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof], because the
// hub's certificate renewal endpoint proves possession of the same certificates
// with the same construction and must not have a second copy of it.
//
// Nothing above the transport knows any of this exists: the reversed-role gRPC,
// the registry, the proxy and the session semantics are untouched.
package wstun
