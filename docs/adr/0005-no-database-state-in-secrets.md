# 0005. No database: state lives in Kubernetes Secrets

* Status: Accepted
* Date: 2026-08-29
* Supersedes an earlier unrecorded decision to embed bbolt on a PersistentVolumeClaim.

## Context

The hub was originally designed around an embedded key/value store on a
PersistentVolumeClaim, holding four things: the CA keypair, the HMAC pepper, the
issued credential records, and the cluster registry.

Three of those are small and secret. The fourth is not state at all.

**The cluster registry is derived.** Spokes dial the hub on a jittered backoff
and re-publish their facts on connect. Everything the registry knows — which
clusters exist, what they run, whether Prometheus is reachable — is re-asserted
by its authoritative source within one reconnect interval. Persisting it buys
nothing except the ability to show an agent a stale entry it will then fail to
query.

The remainder is roughly a kilobyte per credential. For a fleet of 100 clusters
and a few dozen agent keys that is tens of kilobytes.

Meanwhile the PVC cost real things: a StorageClass dependency in every
environment the hub is installed into, a backup and restore procedure for
material whose loss orphans 100 spokes, a single-writer constraint that forced a
StatefulSet and made a second replica a data-corruption risk, and a `fsGroup`
interaction that is a recurring source of permission bugs on hardened clusters.

## Decision

There is no database and no PersistentVolumeClaim.

* The cluster registry lives **purely in memory** and is rebuilt from spoke
  reconnects. A hub restart costs one backoff interval of visibility, not a
  restore.
* Durable credential state — CA certificate and key, HMAC pepper, issued key
  records (KID, HMAC, scope, expiry; never a raw secret), enrollment burn state,
  revoked serials — is a single JSON document in a single **Kubernetes Secret**
  that the hub reads and writes itself through the API server.
* Every mutation is a read-modify-write against the Secret's current
  `resourceVersion`, retried with jittered backoff on a 409.
* A local file backend exists for development and for running outside
  Kubernetes.

The hub therefore needs a `Role` granting `get`, `create` and `update` on
`secrets`, restricted by `resourceNames` to exactly the Secrets it owns.

## Consequences

**Better.** No StorageClass dependency, so the chart installs anywhere. No
backup procedure to get wrong — the Secret is covered by whatever already backs
up etcd, and can be copied with `kubectl get secret -o yaml`. The hub becomes a
Deployment. Credential state is shared across replicas, so a second replica sees
the same keys immediately.

**The unexpected win.** `resourceVersion` is a compare-and-swap. Single-use
enrollment — "burn this token exactly once" — was the one operation that
genuinely needed a transaction, and the single-writer bbolt design got that from
being single-writer. Optimistic concurrency on a Secret gives the same guarantee
*across replicas*, which the PVC design could never have offered.

**Worse.** The hub now talks to the Kubernetes API, which is a dependency it did
not have, and it needs RBAC, which is a reviewable surface it did not have. A
403 from a missing Role is now a startup failure mode, so the client maps it to
an error naming the exact rule that is missing.

**The hard limit.** A Secret caps at 1 MiB. We refuse writes past 700 KiB with an
error naming how many records are stored, and publish
`promfleet_hub_state_bytes` so it is alertable long before it bites. At roughly
a kilobyte per credential that is several hundred keys — far past any plausible
fleet — but it is a ceiling, and a ceiling that is not measured is a ceiling you
discover at 3am.

**Registry visibility after a restart.** An agent that queries in the seconds
after a hub restart sees a partially populated fleet. We considered this
carefully and prefer it to the alternative: a persisted registry would show
clusters whose spokes have not reconnected, and an agent would confidently query
them and get an error. Returning "this cluster is not currently connected" is
honest; returning stale facts is not. The registry keeps a short grace window so
a recently-departed cluster reports `lastSeen` rather than vanishing.

## Alternatives considered

* **Keep bbolt on a PVC.** Rejected: the storage dependency and the
  single-writer constraint were pure cost for state that is mostly derived.
* **A CustomResourceDefinition per credential.** More idiomatic Kubernetes, and
  gives `kubectl get agentkeys`. Rejected: it requires cluster-scoped CRD
  installation rights, puts credential HMACs into an object with much looser
  default RBAC than a Secret, and adds a controller-runtime-shaped dependency to
  a project with a deliberately closed dependency budget.
* **An external database.** Rejected outright: an operational dependency an
  order of magnitude heavier than the thing it stores.
* **ConfigMap for records, Secret only for the CA.** Rejected: an issued key's
  HMAC and scope are security-relevant, and splitting the document across two
  objects loses the single atomic compare-and-swap that makes enrollment safe.
* **In-memory only, re-mint on restart.** Rejected: agent keys are handed to
  humans and to other systems. Invalidating every one of them on a pod restart
  is not a credential system.
