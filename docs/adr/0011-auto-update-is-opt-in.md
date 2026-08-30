# 0011. Fleet auto-update is opt-in, verified and staggered

* Status: Accepted
* Date: 2026-08-29

## Context

The product requirement is that deployed pods update weekly. The mechanism that
satisfies it most directly — a moving tag plus something in-cluster that
restarts the workload — is also a fleet-wide outage delivery mechanism.

State the failure honestly. A regression that survives CI is published on Monday
morning. Within minutes it is running in 100 production clusters. A bad *spoke*
blinds fleet-wide monitoring visibility; a bad *hub* removes agent access
entirely. There is no canary, no soak, and no way to stop it once it starts,
because the thing that would stop it is the thing that is broken.

Meanwhile the requirement behind the requirement is real: base images accumulate
CVEs, and a fleet pinned to an image from six months ago is its own problem.

## Decision

Separate **publishing** from **promoting**, and make the in-cluster half opt-in.

1. **Digest-pinned defaults.** The chart ships `image.digest`, set by the
   release workflow. Tags are for humans.
2. **A weekly rebuild publishes; it does not promote.** Every Monday the latest
   release tag is rebuilt from unchanged source onto fresh base images and
   published as `X.Y.Z-build.N`, re-attested and re-signed. Nothing that is
   deployed changes.
3. **`stable` moves only through a human-approved promotion**, gated on a
   protected GitHub Environment. This is the fleet-wide kill switch: stop
   approving and the entire fleet freezes, with no code change and no incident
   call.
4. **The recommended path is not the chart's CronJob.** It is Renovate or Flux
   against the operator's own GitOps repository, for which we publish a preset.
   That gives a reviewable pull request per release. Most platform teams running
   100 clusters already have this and should use it.
5. **`autoUpdate.enabled: false` by default.** When an operator does enable it,
   the CronJob resolves `stable` to a digest, runs `cosign verify` against this
   repository's OIDC identity **and** `cosign verify-attestation` for SLSA
   provenance, refuses to proceed if either fails, patches the workload to the
   **digest**, waits on `rollout status`, and runs `rollout undo` on failure. Its
   ServiceAccount holds `get,patch` on exactly one Deployment by
   `resourceNames` — no cluster scope, no ability to restart anything else.
6. **Staggering is automatic, not configured.** The schedule is derived from a
   hash of the cluster identity: `minute = h % 60`, `hour = 2 + h % 4`,
   `weekday = h % 7`. A hundred clusters spread across a whole week without
   anyone coordinating. `autoUpdate.cohort: canary | early | stable` adds a
   promotion-age gate on top, so a handful of canary clusters take the change
   days before the bulk.
7. **Opting out is pinning `image.digest`.** The CronJob refuses to patch when
   `autoUpdate.pinned` is set.

The hub's own auto-update is discouraged in the documentation. It is a single
point of failure for the whole fleet, and if it is enabled its window is forced
after the canary cohort's.

## Consequences

**Better.** CVE fixes are published weekly and are verifiable. Nothing reaches a
production cluster without a human approving a promotion. A bad release reaches
a few canary clusters days before it could reach the rest, and the signature and
provenance checks mean a compromised registry cannot substitute an image.

**Worse.** The literal reading of "automatically update the pods weekly" is not
the default behaviour, and an operator who wants it must opt in per cluster. We
think that is the right call and would rather argue it than ship the version that
cannot be stopped — but it is a deviation, and this record exists so it is a
stated one rather than a quiet one.

**Operational cost.** Someone has to approve promotions. If nobody does, the
fleet silently stops updating, which is the safe failure but is still a failure.
The `PrometheusMCPAutoUpdateStale` alert fires when the running digest falls too
far behind `stable`, so "nobody approved anything for two months" is visible.

## Alternatives considered

* **Moving tag plus in-cluster restart.** Simplest, and unpinnable,
  unverifiable and instant across 100 clusters. Rejected.
* **Keel.** A cluster-wide controller with broad RBAC in 100 clusters, to solve
  a problem a CronJob with one `resourceNames` entry solves. Rejected.
* **Flux or Argo image automation only.** Correct and auditable, and what we
  recommend — but it assumes every one of the 100 clusters runs GitOps we do not
  control, so it cannot be the only answer.
* **Renovate pull requests only.** Safest, and genuinely the best option for
  most operators, but it is not "automatic" and does not satisfy the
  requirement on its own. It is layer 4 above, not a replacement for layer 5.
