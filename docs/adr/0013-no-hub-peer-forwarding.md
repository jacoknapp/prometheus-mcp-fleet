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

**No peer forwarding, and no shared tunnel registry.** The default deployment is
a single hub replica.

Operators who want redundancy configure `PMF_HUB_ENDPOINTS` on each spoke with
one address per hub replica, and each spoke maintains a tunnel to all of them.
Every replica then reaches every spoke directly: no ownership state, no extra
hop, no leader election, no split brain.

The chart does not pretend otherwise. `replicas: 3` behind one Service is not a
supported configuration, and the chart README says so rather than letting an
operator discover it as intermittent "cluster not connected" errors.

## Consequences

**Better.** The routing path is a map lookup. There is no consensus, no gossip,
no cache invalidation and no second hop on a latency-sensitive call. A rolling
upgrade is transparent when spokes dial every replica, because the survivors
still hold live tunnels.

**Worse, and this is the real cost.** Multi-replica HA requires each hub replica
to be *individually addressable from outside the cluster* — a per-pod Service, a
DNS name each, and those names in the tunnel certificate's SANs. That is genuine
ingress plumbing, and it is why the default is one replica: a single-replica hub
that restarts in a few seconds is honestly better than a three-replica hub whose
addressing was set up wrong.

Connection count is O(spokes × replicas). At 100 spokes and 3 replicas that is
300 connections and roughly 10 MiB per replica — trivial. The design stops being
right somewhere around a few thousand spokes or ten replicas, at which point
consistent-hash ownership with a peer proxy becomes worth its complexity. That
is a future ADR, not a present one.

**A single-replica hub is a fleet-wide single point of failure for agent
queries.** It is not a single point of failure for monitoring itself: Prometheus
and Alertmanager in each cluster are untouched by the hub being down. An agent
loses visibility; an on-call human does not. That asymmetry is what makes the
default acceptable.

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
