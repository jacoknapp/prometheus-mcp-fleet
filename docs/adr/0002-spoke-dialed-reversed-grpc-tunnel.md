# 0002. Spoke-dialed tunnel with reversed gRPC roles

* Status: Accepted
* Date: 2026-08-29
* Amended by [ADR-0014](0014-websocket-tunnel-through-standard-ingress.md): the
  connection is now a WebSocket through a standard Ingress rather than a raw
  mTLS socket, and mutual authentication moved into the connection. The
  reversed-role gRPC design recorded here is unchanged and runs over the
  WebSocket's `net.Conn` exactly as it ran over a TLS one.

## Context

The hub must issue Prometheus API calls into roughly 100 Kubernetes clusters
that it does not own, run by teams it does not control, mostly on private
networks with no inbound path.

Two questions follow: who dials, and what runs on the wire.

**Who dials.** Hub-dials-spoke needs, per cluster, a firewall exception, a
publicly resolvable name, an inbound TLS certificate and an IP allowlist that
somebody maintains. Times 100, that is not an architecture, it is a permanent
ticket queue. It also inverts the trust story: the hub would hold a credential
*for* every cluster, so a hub compromise is a fleet compromise.

**What runs on the wire.** Once a single long-lived connection carries many
concurrent Prometheus queries, we need request multiplexing, per-request
cancellation, deadline propagation, flow control and backpressure. Those are
exactly the problems HTTP/2 already solves — but gRPC expects the party that
*accepts* the connection to be the server, and here the party that must accept
requests is the one that *dialed*.

## Decision

**The spoke dials the hub.** One public endpoint to secure; ordinary egress on
443 works in private EKS/GKE and behind corporate proxies; the spoke asserts its
own identity with a client certificate rather than the hub assuming it.

**Then the roles reverse.** After the mTLS handshake completes, the spoke runs
the *gRPC server* on the connection it opened, and the hub runs the *gRPC
client* over the socket it accepted. Mechanically the spoke wraps its
`net.Conn` in a single-shot `net.Listener` and calls `grpc.Server.Serve`; the
hub builds a `grpc.ClientConn` with a context dialer that returns the accepted
connection once and errors on any redial.

The service has two methods: a unary `Describe` for cluster facts, and a
server-streaming `Proxy` that carries one Prometheus response back in bounded
chunks.

Liveness is HTTP/2 keepalive PINGs, not an application heartbeat.

## Consequences

**What we get for free, and would otherwise have hand-written:** one HTTP/2
stream per query with independent flow control; `RST_STREAM` cancellation, so an
agent abandoning a query aborts the evaluation inside the remote cluster within
one round trip; `grpc-timeout` deadline propagation; interceptors for tracing
and metrics; and a dead-spoke detection time of about 15 seconds with zero
payload and zero application code.

That cancellation property is worth the whole design on its own. A fleet of AI
agents *will* fire range queries and abandon them, and without end-to-end
cancellation those keep evaluating in a production TSDB.

**What it costs.** The role reversal is genuinely surprising, and a reader who
knows gRPC will assume it is a mistake. It is confined to two small packages
behind the transport-agnostic interfaces in `internal/tunnel`, and both those
packages open with an explanation. The one-shot dialer also has to fight
grpc-go's instinct to redial: it must fail every call after the first so the
connection goes permanently down and the session can be torn down, rather than
hanging.

**What it forecloses.** A spoke cannot be reached by a hub replica it did not
connect to. See [ADR-0013](0013-no-hub-peer-forwarding.md).

## Alternatives considered

* **One bidirectional stream with application-level multiplexing.** The trap
  most reverse-tunnel designs fall into. Request IDs, cancellation, deadlines
  and chunk interleaving all become ours to write, and one slow reader
  head-of-line-blocks every other query on that spoke.
* **yamux over TLS.** A multiplexing layer with weaker flow control underneath a
  protocol that already has one — two windows fighting. No deadline or
  cancellation semantics; you rebuild them.
* **WebSocket.** No multiplexing at all, so you end up writing yamux anyway.
  Retained only as a possible future fallback for clusters whose L7 proxy
  mangles HTTP/2.
* **HTTP/3 / QUIC.** Genuinely removes TCP head-of-line blocking, but `quic-go`
  is a heavy dependency and UDP/443 egress is blocked or unaccelerated in many
  enterprise networks. At the concurrency we expect per spoke, TCP head-of-line
  blocking is not the bottleneck. Revisit at a far larger fleet.
* **A message broker between hub and spokes.** Adds an operational dependency
  bigger than the product, and turns a request/response problem into a
  correlation problem.
