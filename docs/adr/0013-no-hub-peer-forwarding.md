# 0013. No hub-to-hub forwarding

* Status: Accepted
* Date: 2026-08-29

## Context

A spoke's tunnel terminates on exactly one hub pod. Behind a single Service, a
tool call that lands on replica B for a spoke attached to replica A has nowhere
to go. This is inherent to any reverse-tunnel design and it has to be answered,
not glossed.

Since [ADR-0005](0005-no-database-state-in-secrets.md) moved credentials into a
shared Secret, replicas already agree about *authentication*. The open question
is only about *routing*.

There are three usual answers.

**Peer forwarding.** Replica B discovers which replica owns the spoke and
proxies the request. Needs ownership discovery, an extra network hop on every
query, loop prevention, and a cache whose invalidation is a distributed-systems
problem — for a control plane serving 100 endpoints.

**Single replica.** Simple and correct, but every hub restart is a fleet-wide
outage for as long as reconnection takes, and a rolling upgrade becomes an event.

**Fan-out dialing.** Each spoke holds a tunnel to every hub replica, so every
replica can reach every spoke directly.

## Decision

**No peer forwarding, and no shared tunnel registry.** Every spoke holds a
tunnel to every hub replica, so every replica reaches every spoke directly: no
ownership state, no extra hop, no leader election, no split brain. That part of
this record still holds unchanged.

What changed since this record was written is how a spoke finds "every
replica" behind a single Ingress hostname, where individual pods are not
separately addressable. The hub resolves a headless Service to count its own
replicas and advertises that count, with a per-replica `ServerID`, in the
tunnel handshake; the spoke dials the one hostname repeatedly until it has seen
every distinct `ServerID`. No hub-to-hub forwarding is involved — this is
discovery, not routing, and each replica still reaches only the spokes tunneled
directly to it. See [docs/operations/high-availability.md](../operations/high-availability.md)
for the full mechanism.

That mechanism is now the default: both charts default to `replicaCount: 3`
behind one Ingress hostname, with `peerDiscovery.enabled: true` rendering the
headless Service. Explicitly addressing each replica — configuring
`hub.endpoints` on every spoke with one URL per replica — remains supported and
is the more predictable choice behind a load balancer whose session affinity
cannot be disabled, since affinity defeats discovery the same way it always
would have defeated fan-out dialing.

## Consequences

**Better.** The routing path is a map lookup. There is no consensus, no gossip,
no cache invalidation and no second hop on a latency-sensitive call. A rolling
upgrade is transparent when spokes dial every replica, because the survivors
still hold live tunnels.

**Worse, and this is the real cost.** A spoke cannot know it has reached every
replica without being told how many there are, so headless-Service DNS
resolution and the `ServerID`/replica-count fields in the handshake are now load
bearing for the default deployment. The Ingress in front of the hub must not
apply session affinity, or a spoke dialing the shared hostname can get pinned
to one replica and never complete coverage — the one genuine new operational
constraint this adds. Explicit per-replica addressing sidesteps that constraint
entirely, at the cost of the ingress plumbing this record originally described:
a name per replica, routed individually, and every spoke configured with the
full list.

Connection count is O(spokes × replicas). At 100 spokes and 3 replicas that is
300 connections and roughly 10 MiB per replica — trivial. The design stops being
right somewhere around a few thousand spokes or ten replicas, at which point
consistent-hash ownership with a peer proxy becomes worth its complexity. That
is a future ADR, not a present one.

**A hub running as a single replica is a fleet-wide single point of failure for
agent queries**, whether that is the chosen `replicaCount: 1` or a transient
state during a rolling update. It is not a single point of failure for
monitoring itself: Prometheus and Alertmanager in each cluster are untouched by
the hub being down. An agent loses visibility; an on-call human does not. That
asymmetry is what makes accepting a few seconds of reduced coverage during a
rollout — rather than engineering it away — a reasonable trade.

## Alternatives considered

* **Consistent-hash ownership with peer proxy.** Rejected for this fleet size:
  it adds a distributed cache, a second hop and a class of bug that only shows up
  under partition, to solve a problem that fan-out dialing solves with a config
  list.
* **Sticky sessions at the load balancer.** Does not help. The stickiness would
  have to be keyed on the *target cluster*, which the load balancer cannot see
  without parsing the MCP request body.
* **Pushing tunnel ownership into the shared Secret.** Rejected: tunnel liveness
  changes on a timescale of seconds, and writing it to etcd turns a fast local
  fact into a slow shared one.
