# 0014. Tunnel over WebSocket through a standard Ingress

* Status: Accepted
* Date: 2026-08-30
* Amends [ADR-0002](0002-spoke-dialed-reversed-grpc-tunnel.md) (transport
  exposure only; the reversed-role gRPC design it records is unchanged) and
  supersedes the tunnel-exposure part of
  [ADR-0013](0013-no-hub-peer-forwarding.md).

## Context

The original design gave the tunnel its own listener on port 8443 speaking raw
mutually authenticated TLS, exposed with a `Service` of type LoadBalancer,
because an HTTP Ingress terminates TLS and therefore cannot pass a client
certificate through to the hub.

That assumption does not survive contact with the deployment target. The
requirement is now explicit: **standard `networking.k8s.io/v1` Ingress only. No
TCP passthrough, no LoadBalancer, no NodePort.** Everything reaches the hub as
HTTP.

This is a common and reasonable constraint. Plenty of platforms hand a team a
shared Ingress and nothing else; `ssl-passthrough` is an nginx-specific
annotation rather than part of the Ingress API, and several controllers do not
implement it at all.

It removes the mechanism the entire identity model rested on. mTLS was not
decoration: a spoke's cluster ID comes from the URI SAN of its verified client
certificate, and nothing it says at runtime may override that
([ADR-0004](0004-built-in-ca-for-spoke-identity.md)). If the Ingress terminates
TLS, the hub sees the Ingress, not the spoke.

## Decision

**The tunnel runs over a WebSocket on the hub's ordinary HTTP listener, and
mutual authentication moves from the TLS layer into the connection.**

Three parts.

**1. Transport.** The spoke sends an HTTP `Upgrade` to `wss://<hub>/tunnel`. Any
Ingress controller proxies `Connection: Upgrade` natively — it is how every
WebSocket application on Kubernetes works — so no annotation and no special
Service type is required. The resulting frame stream is adapted to a `net.Conn`.

**2. Everything above the transport is unchanged.** The reversed-role gRPC of
ADR-0002 runs over that `net.Conn` exactly as it ran over a TLS conn: the spoke
serves, the hub is the client, and stream multiplexing, per-request
cancellation, `grpc-timeout` deadline propagation and flow control all still
come from HTTP/2. `internal/tunnel`'s interfaces, the registry, the proxy and
the session semantics did not change at all. This is the payoff of having kept
the transport behind an interface with a conformance suite.

**3. Identity moves into the connection.** Immediately after the upgrade, before
any gRPC byte:

```
hub   -> spoke : ServerHello{nonce: 32 random bytes, protocolVersion}
spoke -> hub   : ClientAuth{certificate chain (DER), signature over the transcript}
hub            : verify chain against the internal CA, check the revocation
                 denylist, verify the signature with the leaf public key,
                 derive clusterID from the URI SAN
hub   -> spoke : Accepted{} | rejected, connection closed
```

The signature covers a transcript binding the nonce, the protocol version and
the requested cluster ID, so a captured `ClientAuth` cannot be replayed against
a different nonce or re-scoped to another cluster.

This is deliberately the same construction as TLS's own `CertificateVerify`
step, performed one layer up. The private key still never leaves the spoke, the
certificate is still the sole source of identity, and the CA, issuance,
renewal and revocation machinery is untouched.

## Consequences

**Better.** The hub needs exactly one HTTP port. Onboarding a cluster now
requires only outbound HTTPS to a hostname, which is the most universally
available thing there is — no LoadBalancer quota, no NodePort range, no
passthrough annotation, no second DNS name, no second certificate. The
multi-replica story from ADR-0013 also gets simpler: per-replica addressing is
ordinary HTTP routing rather than per-replica TLS endpoints.

The tunnel and the MCP endpoint now share a listener, which means one Ingress
rule and one certificate for the whole product.

**Worse, and this is the real cost: the Ingress is inside the trust boundary.**
It terminates TLS, so it sees the WebSocket frames, including the
`ClientAuth` message. It cannot *forge* a spoke — it never holds a spoke's
private key, and the signature is over a nonce the hub chose — but it can
observe traffic and, if compromised, it could relay a live connection.

We accept this, for three reasons. It is the operator's own infrastructure, in
the operator's own cluster, on the path to the hub regardless. Any product
deployed behind an Ingress makes the same concession. And the alternative —
demanding passthrough — is precisely the requirement we were told does not hold.

It is nonetheless a genuine reduction against end-to-end mTLS, and
[docs/security.md](../security.md) says so rather than implying the property
survived intact.

**No channel binding.** With TLS terminated at the edge, spoke and hub share no
TLS session, so the `ClientAuth` cannot be bound to one the way RFC 5929 channel
binding would. The nonce is single-use and short-lived, which prevents replay
but not relay by the terminating proxy. Stated, not hidden.

**A new dependency.** `github.com/coder/websocket`, which has **zero transitive
dependencies** and provides the `net.Conn` adapter this design needs. Under
[ADR-0010](0010-dependency-budget.md) that requires this record. Hand-rolling
RFC 6455 — framing, masking, close semantics, ping/pong — is several hundred
lines of exactly the code that should not be homemade.

**Idle timeouts become an operational concern.** Ingress controllers close idle
upgraded connections; nginx defaults to 60 seconds. HTTP/2 keepalive pings
inside the tunnel keep it busy at a 10-second interval, which is well inside
every default we found, and the deployment docs name the annotation to raise
where a controller is stricter.

**What we gave up.** Raw TLS was slightly cheaper: WebSocket framing adds a few
bytes per message and one masking pass on the client side. At our message sizes
this is not measurable next to a Prometheus query.

## Alternatives considered

* **Keep raw mTLS on a LoadBalancer.** Rejected: it is the constraint we were
  given. It also asks every operator for a load balancer per hub, which is a
  real cost in some environments and impossible in others.
* **`ssl-passthrough` on the Ingress.** Preserves true end-to-end mTLS, and we
  document it as an option for operators who have it. Rejected as the default:
  it is an nginx annotation, not part of the Ingress API, and several
  controllers do not support it — so a design that requires it is a design that
  does not deploy.
* **HTTP/2 `CONNECT` tunnelling.** Elegant, and avoids WebSocket framing
  entirely. Rejected: Ingress controller support for extended CONNECT is
  patchy and much less predictable than `Upgrade: websocket`.
* **Long-poll or SSE plus a POST channel.** Works through anything, and gives up
  the bidirectional stream that makes the reversed-role gRPC design possible.
  We would be back to hand-rolling multiplexing, cancellation and deadlines —
  the exact trap ADR-0002 exists to avoid.
* **Bearer token instead of a certificate.** Simpler, and strictly weaker: a
  bearer token is replayable by anything that observes it, including the very
  proxy we just admitted is in the path. The signed nonce is what makes
  observation insufficient.
* **Mutual TLS *inside* the WebSocket.** Genuinely restores end-to-end mutual
  authentication and channel binding, by running a second TLS session over the
  frame stream. Rejected for this release as disproportionate: it doubles the
  handshake cost and the failure modes to close a gap whose remaining risk is a
  compromised in-cluster Ingress. Recorded here as the obvious future step if
  that threat becomes material.
