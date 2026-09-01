<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# High availability

The short version: **the hub defaults to three replicas behind a single Ingress
hostname, and a cluster may run several spoke pods.** Neither needs per-replica
ingress work.

A hub replica set works behind a **single Ingress hostname**: the hub counts its
own replicas and tells each spoke how many to expect, and the spoke dials that
one hostname until it has reached them all. A cluster may also run **several
spoke pods**, which the hub pools.

> **Upgrading from an earlier release?** This used to require a distinct
> external hostname per hub replica, configured into every spoke, and it
> refused more than one spoke pod outright. Both restrictions are gone. The
> per-hostname setup still works and is still the most predictable option if
> you already have it.

## What is and is not shared

Since credential state moved out of a volume and into a Kubernetes Secret
([ADR-0005](../adr/0005-no-database-state-in-secrets.md)), hub replicas already
agree about most things.

| State | Shared across replicas? |
|---|---|
| CA, HMAC pepper, issued keys, enrollment burn state, revoked serials | **Yes** — one Secret, read-through with a short cache |
| Cluster registry | No, but it is derived: each replica rebuilds it from the spokes connected to *it* |
| Live tunnel sessions | **No.** A tunnel terminates on exactly one pod |

That last row is the whole problem. A tool call that lands on replica B for a
spoke whose tunnel terminates on replica A has nowhere to go, and there is
deliberately no hub-to-hub forwarding
([ADR-0013](../adr/0013-no-hub-peer-forwarding.md)).

That last row is why a spoke must hold a tunnel to **every** replica. If it
holds two of three, a third of tool calls for that cluster find no session.

**This is now handled automatically.** The hub resolves a headless Service to
count its own replicas and advertises that number in the tunnel handshake, along
with a `ServerID` naming the replica that answered. The spoke keeps dialing the
same hostname until it has seen every distinct `ServerID`, then maintains one
tunnel per replica. No per-replica DNS, no forwarding hop, no leader election.

```yaml
# hub values — this is the default, shown for clarity
replicaCount: 3
peerDiscovery:
  enabled: true      # renders the headless Service the hub resolves
podDisruptionBudget:
  enabled: true
  maxUnavailable: 50%
  # A pod that is not Ready does NOT consume the budget. Without this a node
  # carrying a crashlooping hub cannot be drained until somebody fixes the pod,
  # which is backwards for a workload whose whole point is replaceability.
  unhealthyPodEvictionPolicy: AlwaysAllow
```

**The one requirement: your Ingress must not use session affinity.** A load
balancer that pins a client to one backend prevents a spoke from ever reaching
the others, and the spoke would dial forever without completing coverage. Watch
`promfleet_spoke_tunnels_covered` against `promfleet_spoke_hub_replicas`; if
coverage never reaches the replica count, affinity is the first thing to check.

## The single-replica case

No longer the default, but still a legitimate choice, and the reason is worth stating.

**When the hub is down, monitoring is not.** Prometheus and Alertmanager in
every monitored cluster carry on exactly as before. What is lost is *AI agent
access*. A human on call is unaffected; a model investigating an incident has to
wait. That asymmetry is what makes a few seconds of downtime during a rolling
update acceptable.

Recovery is fast because there is nothing to restore: no volume to reattach, no
database to replay. The hub starts, reads two Secrets, and spokes reconnect on
their own jittered backoff. Expect the fleet view to be complete within a few
seconds of readiness.

```yaml
replicaCount: 1      # not the default; the default is 3
```

Choose it for a lab, or where the Ingress cannot have session affinity
disabled.

## Multi-replica, done properly

The supported pattern is **each spoke dials every hub replica**. Every replica
then holds a direct tunnel to every spoke: no ownership table, no forwarding
hop, no leader election, no split brain.

```mermaid
flowchart LR
    subgraph hub ["Hub cluster"]
        H0["hub-0"]
        H1["hub-1"]
        H2["hub-2"]
        SEC[["Secret<br/>CA · pepper · keys"]]
        H0 --- SEC
        H1 --- SEC
        H2 --- SEC
    end
    S["spoke<br/>(each of ~100 clusters)"]
    S -.->|tunnel| H0
    S -.->|tunnel| H1
    S -.->|tunnel| H2
    LB(["MCP load balancer"]) --> H0
    LB --> H1
    LB --> H2
```

### Addressing each replica explicitly

Automatic discovery is the default and needs none of this. Per-replica
addressing remains supported and is the more predictable option behind a load
balancer you do not control — notably one whose affinity you cannot disable. To
use it, list every replica in `hub.endpoints`; the spoke keeps one tunnel per
configured endpoint and discovery has nothing left to find. You need:

1. A distinct external hostname per replica, each routed by the Ingress to that
   replica's pod. Since the tunnel is now ordinary HTTP
   ([ADR-0014](../adr/0014-websocket-tunnel-through-standard-ingress.md)) this is
   plain Ingress routing rather than per-replica TLS endpoints — considerably
   less work than it used to be, though still work.
2. A certificate covering those names, which your existing Ingress TLS already
   handles.
3. Every spoke configured with all of them:

   ```yaml
   hub:
     endpoints:
       - wss://pmf-hub-0.example.com/tunnel
       - wss://pmf-hub-1.example.com/tunnel
       - wss://pmf-hub-2.example.com/tunnel
   ```

   The spoke opens one tunnel per endpoint and maintains each independently
   with its own backoff.
4. The MCP HTTP port behind an ordinary load balancer. **No session affinity is
   needed** — the MCP transport is stateless (protocol revision 2026-07-28
   removed sessions), and credentials come from the shared Secret.

### What it costs

Connections scale as spokes × replicas. At 100 spokes and 3 replicas that is
300 tunnels fleet-wide, roughly 10 MiB per replica — negligible. Facts polling
triples, to a few requests per second.

The design stops being right somewhere around a couple of thousand spokes or ten
replicas, at which point consistent-hash ownership with a peer proxy starts to
earn its complexity. That is a future ADR, not a present one.

### Rolling upgrades

With every spoke dialling every replica, a rolling update is transparent: the
surviving replicas still hold live tunnels throughout. This is the main
operational reason to go multi-replica, more so than availability.

## Spoke-side availability

A cluster may run more than one spoke pod. Every operation a spoke serves is a
read-only, idempotent Prometheus query, so sibling pods are interchangeable: the
hub keeps a pool of sessions per cluster and any of them can answer. Losing one
is invisible, and a rolling spoke upgrade never drops the cluster out of the
fleet view.

There is deliberately **no leader election**. Nothing a spoke does needs
serialising, so an election would buy split-brain risk, lease RBAC and failover
latency in exchange for nothing.

```yaml
# spoke values — this is the default
replicaCount: 3
identity:
  backend: secret     # required above 1; the pods share one certificate
```

The pods **share one certificate**, held in the cluster's identity Secret. That
is what `identity.backend: secret` means and why it is the only backend that
supports more than one pod:

- **At startup** every pod reads the Secret. Pods that come up together on a
  fresh cluster all find it empty and all enrol, so the last writer wins — and
  the others then re-read and adopt what is there, so the pool settles on one
  certificate immediately rather than at the first renewal.
- **At renewal** they all reach the threshold within a jitter window of each
  other. Before renewing, a pod re-reads the Secret; if a sibling has already
  renewed, it adopts that certificate and reconnects instead of minting a
  competing one. A pod that loses the write race does the same.

`memory` and `file` are refused above one replica because they give every pod
its own identity: enrollments multiply by pod count and the pool renews several
certificates instead of rotating one. `file` is worse than it looks —
`config.dataDir` is an emptyDir, so it behaves like `memory` while appearing
durable.

Rolling updates are ordinary `RollingUpdate` with `maxUnavailable: 0`, so the
old pod keeps serving until the new one has connected. This used to be
`Recreate`, because two pods sharing a cluster ID fought; they no longer do.

Pods are told apart by an `InstanceID` (the pod hostname) sent in the handshake.
It authenticates nothing — the certificate still decides what a session may
serve — it only decides which slot a session occupies within its own cluster.

`promfleet_hub_spoke_sessions{cluster}` on the hub is the count of live
sessions it currently holds for one cluster. Scale a spoke to three pods and
this should read 3; it is the way to confirm sibling pods really did come up
and reconnect, rather than one of them silently failing to enrol.

## Choosing

| You want | Do this |
|---|---|
| Simplicity, and can tolerate seconds of agent downtime on upgrade | `replicaCount: 1` on the hub. A deliberate downgrade from the default |
| Transparent rolling hub upgrades, no single point of failure for agent access | `replicaCount: 3` on the hub with `peerDiscovery.enabled`, behind one hostname, affinity off |
| A monitored cluster that must not lose agent visibility when one pod restarts | `replicaCount: 2+` on that spoke with `identity.backend: memory` and a reusable token |
| Multi-replica behind a load balancer whose affinity you cannot disable | Per-replica hostnames in `hub.endpoints`, as above |

If you are unsure, take one replica. A single hub that restarts in a few seconds
is honestly better than three whose addressing was set up incorrectly.

## Verifying a multi-replica setup

Check that every spoke really is connected to every replica, rather than
accidentally to one:

```promql
# Should equal the number of enrolled clusters, on every replica
promfleet_hub_spokes_connected

# Should equal promfleet_spoke_hub_replicas, per endpoint, on every spoke
promfleet_spoke_tunnels_covered
promfleet_spoke_hub_replicas
```

`promfleet_spoke_tunnels_covered < promfleet_spoke_hub_replicas` on the same
`endpoint` label means that spoke has not reached every replica behind that
hostname — almost always a session-affinity setting on the Ingress that keeps
pinning it back to replicas it already holds. Alert on it; a partially
connected fleet fails intermittently and is far harder to diagnose after the
fact.

`promfleet_spoke_tunnel_up` is 1 while at least one tunnel to a configured
endpoint is up; it does not by itself distinguish "connected to one replica"
from "connected to all of them" behind a single discovered hostname. It is
most useful under [explicit per-replica addressing](#addressing-each-replica-explicitly),
where each replica is its own `endpoint` label value and `tunnel_up` really is
one series per replica — there, a spoke showing `tunnel_up` for two of three
configured endpoints has a third tunnel that is failing, almost always a
missing SAN or a DNS record that does not resolve from that cluster.
