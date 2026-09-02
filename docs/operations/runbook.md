<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# Runbook

Alert-driven procedures. Each section is written to be read at 3am by someone
who did not build this.

**Before anything else, know the blast radius.** When the hub is down, AI agents
lose visibility. Prometheus and Alertmanager in every monitored cluster are
untouched — your own alerting still works, and a human on-call is unaffected.
This is a convenience-tier outage, not a monitoring outage. Do not page harder
than that warrants.

**Read this before you're paged, not during.** A hub-side root cause pages you
once. It also independently pages every spoke's own on-call, once per cluster.
See [Alert topology](#alert-topology-one-root-cause-many-pages) below — the
fix (correlating those pages) has to be set up ahead of time; there is nothing
to do about it mid-incident except recognize the pattern.

## Contents

- [Alert topology: one root cause, many pages](#alert-topology-one-root-cause-many-pages)
- [Quick triage](#quick-triage)
- [PrometheusMCPHubDown](#prometheusmcphubdown)
- [PrometheusMCPSpokesDisconnected](#prometheusmcpspokesdisconnected)
- [PrometheusMCPSpokeTunnelDown](#prometheusmcpspoketunneldown)
- [PrometheusMCPHubCACertExpiringSoon](#prometheusmcphubcacertexpiringsoon)
- [PrometheusMCPHubCARotationStalled](#prometheusmcphubcarotationstalled)
- [PrometheusMCPSpokeCertExpiringSoon](#prometheusmcpspokecertexpiringsoon)
- [PrometheusMCPHubProxyErrorRatioHigh](#prometheusmcphubproxyerrorratiohigh)
- [PrometheusMCPHubRestartLoop](#prometheusmcphubrestartloop)
- [PrometheusMCPHubStateSecretLarge](#prometheusmcphubstatesecretlarge)
- [PrometheusMCPHubRevocationStale](#prometheusmcphubrevocationstale)
- [PrometheusMCPHubPeerDiscoveryBroken](#prometheusmcphubpeerdiscoverybroken)
- [PrometheusMCPHubSpokeCertExpiringSoon](#prometheusmcphubspokecertexpiringsoon)
- [PrometheusMCPSpokeDown](#prometheusmcpspokedown)
- [PrometheusMCPSpokePrometheusDown](#prometheusmcpspokeprometheusdown)
- [PrometheusMCPSpokePromErrorRatioHigh](#prometheusmcpspokepromerrorratiohigh)
- [PrometheusMCPSpokeTunnelFlapping](#prometheusmcpspoketunnelflapping)
- [PrometheusMCPSpokePartialCoverage](#prometheusmcpspokepartialcoverage)
- [PrometheusMCPSpokeFactsRefreshFailing](#prometheusmcpspokefactsrefreshfailing)
- [Security events](#security-events)
- [Disaster recovery](#disaster-recovery)

## Alert topology: one root cause, many pages

**This alone is not obvious from the alert names, so read it before the fleet
is 100 clusters and you're finding it out live.**

Every spoke's `PrometheusRule` is deployed *inside that monitored cluster* and
evaluated by *that cluster's own Prometheus*, firing into *that cluster's own
Alertmanager* — the chart puts it there on purpose, since that is the only
Prometheus that has both `promfleet_spoke_tunnel_up` and an on-call already
configured for that cluster. The hub's own `PrometheusRule`
(`PrometheusMCPHubDown`, `PrometheusMCPSpokesDisconnected`, and the cert/proxy
alerts) is deployed once, centrally, next to the hub.

Nothing ties these together. So when the fault is on the hub side — the
Ingress stops routing `/tunnel`, a certificate rotation goes wrong, a
LoadBalancer loses its address — here is what actually happens across a
hundred-cluster fleet:

1. Within 5 minutes, up to 100 independent Alertmanagers each fire their own
   `PrometheusMCPSpokeTunnelDown`, because each spoke genuinely has lost its
   tunnel. Each one pages whoever is on call for *that* cluster.
2. Five minutes after that, the hub's own Alertmanager fires exactly one
   `PrometheusMCPSpokesDisconnected` — the fleet-wide summary — into whatever
   receiver the hub's chart is configured with.
3. Nothing links 2 back to 1. Every spoke on-call sees a cluster-specific
   tunnel alert with no indication it is one of ninety-nine identical pages
   firing at the same moment for an unrelated reason.

**What to expect, so you recognize it fast:** a sudden burst of
`PrometheusMCPSpokeTunnelDown` pages landing within the same couple of minutes,
across clusters that share nothing operationally, is *itself* the signature of
a hub-side fault — and it shows up *before* `PrometheusMCPSpokesDisconnected`
does, since the per-spoke alert's `for: 5m` is shorter than the fleet alert's
`for: 10m`. Don't wait for the hub alert to confirm what a five-minute burst of
unrelated tunnel alerts has already told you. Go straight to
[PrometheusMCPSpokesDisconnected](#prometheusmcpspokesdisconnected).

**What fixes this is set up ahead of time, not during the incident** — this
repo ships the per-cluster and hub-side rules, but not a correlation layer,
because that layer has to live somewhere that can see every cluster's alerts
at once, which no single component here is:

- **Federate alerts into one shared Alertmanager.** Add a second target to
  every spoke Prometheus's `alerting.alertmanagers` list — the cluster's own
  Alertmanager stays first (so local on-call keeps working unchanged), and a
  fleet-wide Alertmanager is added alongside it. The hub's Prometheus should
  point at the same shared instance. Inhibition rules only apply within a
  single Alertmanager's alert set, so this step is what makes inhibition
  possible at all:
  ```yaml
  inhibit_rules:
    - source_matchers:
        - alertname = "PrometheusMCPSpokesDisconnected"
      target_matchers:
        - alertname = "PrometheusMCPSpokeTunnelDown"
      equal: []   # deliberately no shared label: one fleet-wide cause
                  # suppresses N per-cluster symptoms with no cluster in common
  ```
- **If a shared Alertmanager isn't reachable from every cluster** (independent
  network paths, no shared egress), a dashboard that lists every cluster's
  Alertmanager side by side — Karma is the common choice — at least turns a
  hundred pages into one screen. It does not suppress anything; it only saves
  you the tab-switching while you triage.

Either way, this has to exist *before* the fleet-wide fault happens. There is
no way to retrofit correlation onto a hundred pages that have already fired.

## Quick triage

```bash
HUB_NS=prometheus-mcp-hub

kubectl -n $HUB_NS get pods
kubectl -n $HUB_NS logs deploy/pmf-hub --tail=100
kubectl -n $HUB_NS port-forward deploy/pmf-hub 9090:9090 &
curl -s localhost:9090/readyz | jq      # names exactly what is blocking
curl -s localhost:9090/metrics | grep promfleet_hub_spokes_connected
```

`/readyz` returns JSON listing each not-ready component and why. Read it before
guessing. The `store` component is re-probed every 15 seconds after startup:
it reports `the state document cannot be read: ...` when the state Secret is
unreadable (a schema from a newer build, a corrupt document, an API server
that stopped answering), and readiness returns on its own once a read
succeeds. Fix the document or the API server; nothing needs a restart.

## PrometheusMCPHubDown

**Means:** the hub is not being scraped, or has no ready replica. All agent
access is gone.

1. `kubectl -n $HUB_NS get pods` — is it `CrashLoopBackOff`, `Pending`, or gone?
2. `kubectl -n $HUB_NS logs deploy/pmf-hub --previous` for the crash reason.

The three failures that account for most of these:

| Log line | Cause | Fix |
|---|---|---|
| `cannot create the CA secret … the hub needs a Role granting create on secrets` | RBAC is missing or its `resourceNames` do not match the configured Secret names | Reconcile `PMF_STATE_SECRET_NAME` / `PMF_CA_SECRET_NAME` against the Role's `resourceNames` |
| `load or create the CA: ca: incomplete certificate authority on disk: … present but … missing` | The CA Secret was partially restored or hand-edited | Restore both `ca.crt` and `ca.key` together, or see [disaster recovery](#disaster-recovery) |
| `bind: address already in use` | A port collides with something else in the pod | Check the three listener addresses |

If the pod is `Pending`, it is a scheduling problem, not a hub problem. There is
no PVC to be stuck on — the hub has no volume claim at all — so look at
resources, taints and node capacity.

**Recovery is just a restart.** The registry is in memory and self-registering:
spokes reconnect on their own backoff and the fleet view rebuilds within
seconds. There is nothing to restore and no consistency to worry about.

## PrometheusMCPSpokesDisconnected

**Means:** more than 10% of enrolled clusters have no live tunnel for 10
minutes. A fleet-wide symptom, not a per-cluster one — and, unless you've set
up the correlation in [Alert topology](#alert-topology-one-root-cause-many-pages),
you likely already saw this coming as a burst of unrelated
`PrometheusMCPSpokeTunnelDown` pages five minutes earlier.

```promql
promfleet_hub_spokes_connected
count(promfleet_hub_spoke_connected == 0)
```

Work outward from the common cause:

1. **Did the hub just restart?** Expected and self-healing. Confirm the count is
   climbing back and wait one backoff cycle.
2. **Is the tunnel endpoint reachable from outside?** This is the usual culprit
   after an infrastructure change. A LoadBalancer that lost its address, a DNS
   record that moved, or a firewall change affects every spoke at once.
   ```bash
   # The tunnel is a WebSocket on the hub's ordinary Ingress path.
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
     -H 'Sec-WebSocket-Version: 13' \
     -H 'Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==' \
     https://pmf.example.com/tunnel
   ```
   Expect `101`, or a `4xx` from the hub itself. **`404` means the Ingress is not
   routing `/tunnel`**, which is the single most common cause of a fleet-wide
   disconnect after an Ingress change.
3. **Did the Ingress idle timeout drop?** Controllers close idle upgraded
   connections; the tunnel's HTTP/2 pings run every 10 seconds, so anything above
   about 30 seconds is safe. A timeout below that disconnects the whole fleet on
   a rolling basis.
4. **Are the spokes' certificates expiring en masse?** A fleet enrolled on the
   same afternoon expires on the same afternoon. Check
   `promfleet_hub_spoke_cert_expiry_seconds`.

If it is a subset rather than the fleet, treat it as many instances of the next
alert.

## PrometheusMCPSpokeTunnelDown

**Means:** one cluster has no tunnel for 5 minutes.

Work in the **spoke's** cluster — this is almost always a network problem there,
not a hub problem.

```bash
kubectl -n prometheus-mcp logs deploy/pmf-spoke --tail=50
```

| Log line | Cause | Fix |
|---|---|---|
| `dial tcp: i/o timeout` | Egress to the hub is blocked | Check the NetworkPolicy and the cluster's egress firewall |
| `x509: certificate signed by unknown authority` | The spoke does not trust the certificate the hub's **Ingress** presents | Public issuer: leave `hub.caBundle` empty (system roots). Private issuer: supply that issuer's CA as `hub.caBundle` / `hub.existingCASecret`. Never the hub's `/pki/bundle`, which signs spoke identities and cannot verify the Ingress |
| `x509: certificate has expired` | The spoke's own certificate lapsed | Nothing, usually: `/renew` accepts an expired certificate within `--renew-grace` (default 30 days), and the spoke's own renewal loop keeps retrying it automatically. Past that grace period `/renew` refuses it and the cluster needs a fresh enrollment token |
| `auth-rejected` | The hub refused the handshake — usually a revoked certificate | Check the hub's audit log for the serial |
| `upgrade-rejected` / `404` | The Ingress is not routing `/tunnel` | Fix the Ingress path |
| `no such host` | DNS in that cluster cannot resolve the hub | Check the cluster's DNS and the NetworkPolicy's DNS egress rule |

The spoke retries with full jitter forever, so there is nothing to restart once
the underlying cause is fixed.

## PrometheusMCPHubCACertExpiringSoon

**Means:** the CA certificate expires within 14 days, and the hub has not
rotated it. When the CA expires, every spoke certificate becomes unverifiable
and the entire fleet disconnects.

**The hub normally rotates its own CA, and this alert means it has not.** It is
therefore a question about the rotation controller, not an instruction to
rotate by hand.

### What the hub does on its own

The rotation is a four-state machine persisted in the CA Secret, advanced by
whichever replica wins a compare-and-swap on it and adopted by the rest. The
default trigger is the last fifth of the signing root's life, with a floor of
`2 × spoke-cert-ttl + renew-grace` underneath it so a rotation is never started
that could not finish before the signer expires.

| Phase | Signs | Trusted | Leaves when |
|---|---|---|---|
| `steady` | the one root | that root | the signer enters its last fifth, or you force it |
| `publishing` | the **old** root | old + new | one full `--spoke-cert-ttl` has passed, so every spoke has renewed onto the two-root bundle and every replica has seen the successor; or immediately if the signing root has already expired, since past that point no spoke can renew onto the outgoing bundle and waiting protects nothing |
| `signing` | the **new** root | old + new | one `--spoke-cert-ttl` **plus** `--renew-grace`, padded by two poll intervals (a replica that lost the promotion race keeps signing with the old root until its next poll), has passed since promotion, measured against the values in force **when the successor was promoted** (recorded in Secret key `ca-rotation.retire-after`) or the current values if those are longer, **and** no replica has seen a live session on the outgoing root recently |
| `steady` | the new root | that root | — |
| `unknown` | whatever the Secret says | **everything present** — signer, successor, outgoing | never on its own: this build cannot interpret the recorded phase (usually a rollback mid-rotation, or a hand edit) and freezes rather than guessing. Roll forward to a build that knows the phase, or fix the `phase` key by hand |

The trust bundle is the same set across the promotion — `{old, new}` before and
after — so no spoke can be disconnected by it. Only the last step narrows what
is trusted, and it is the only one gated on evidence rather than a clock.

At the defaults (14-day certificates, 30-day renewal grace) a whole rotation
takes about two months. That is not slowness to be fixed: it is one certificate
lifetime for the fleet to pick up the new root, and a lifetime plus the grace
window before the old one can be taken away without stranding a cluster that
was switched off.

### What to look at

```bash
# The phase, and how long it has been in it.
promfleet_hub_ca_rotation_phase                              # 1 on one phase label
time() - promfleet_hub_ca_rotation_phase_start_timestamp_seconds
sum(promfleet_hub_ca_outgoing_root_sessions)                 # spokes still on the old root
promfleet_hub_ca_trust_roots                                 # 1 steady, 2 mid-rotation
promfleet_hub_ca_cert_expiry_seconds                         # the SIGNER's remaining life
```

```bash
# The same thing from the Secret, which is the source of truth.
kubectl -n $HUB_NS get secret pmf-hub-ca \
  -o jsonpath='{.data.ca-rotation\.phase}' | base64 -d; echo
kubectl -n $HUB_NS get secret pmf-hub-ca \
  -o jsonpath='{.data.ca-rotation\.since}' | base64 -d; echo
kubectl -n $HUB_NS logs deploy/pmf-hub | grep -E 'CA rotation|adopted rotated CA'
```

`promfleet_hub_ca_cert_expiry_seconds` tracks the **active signer** only, so it
keeps falling through `publishing` — nothing has been fixed until the signer
moves — and jumps to the successor's ten years at the promotion into `signing`.
That is the correct reading and this alert clears there, not earlier.

### Why it might not be rotating

| Log line at startup | Meaning |
|---|---|
| `the CA will not rotate itself ... file state backend` | `state.backend` is `file`. There is no compare-and-swap and no shared state, so rotation is off. Move to the secret backend |
| `the CA will not rotate itself ... disabled by --ca-rotation-enabled=false` | Somebody turned it off. Set `config.caRotationEnabled: true` |
| `the CA will not rotate itself ... belongs to whatever supplies it` | You supplied the CA through `bootstrap.existingSecret`. That mount is read-only and the hub will not rotate material it was handed. Rotate it wherever it comes from, or hand the CA over to the hub |
| `CA rotation poll failed` | The hub cannot read or write the CA Secret. Check the Role — it needs `get` and `update` on this object — and the API server |

If none of those appear and the phase is `steady` with the signer inside its
last fifth, the trigger is misconfigured: check
`config.caRotateAtRemainingFraction`.

### Forcing a rotation

For a suspected key compromise, or to start one now for any other reason:

```bash
kubectl -n $HUB_NS annotate secret pmf-hub-ca \
  promfleet.io/rotate-now="suspected key compromise" --overwrite
```

The next poll — within `config.caRotationPollInterval`, five minutes by default
— mints the successor, enters `publishing`, and consumes the annotation,
recording `promfleet.io/rotate-accepted` in its place. If the Secret still
carries leftovers from an interrupted rotation, the first poll discards those
and the next one starts the rotation; the annotation survives the tidy-up. It
is edge triggered:
re-annotating starts nothing while a rotation is already under way, and the
annotation is cleared rather than left to fire again months later.

**Forcing does not make the rotation faster.** The gates are unchanged, because
the thing they are waiting for — the fleet renewing — has not got any quicker.
If a key is genuinely compromised, the annotation starts the clock; revoking
the credentials issued under it (`hub keys revoke --kid` for agent and admin
keys, `hub certs revoke --serial` for spoke certificates) is the part that
acts immediately.

### What you should not do

Do not edit `ca.crt`/`ca.key` in the Secret by hand. Replacing the CA in place
disconnects the fleet instantly and requires re-enrolling every cluster. If you
must intervene, the supported hand controls are: the `promfleet.io/rotate-now`
annotation, `config.caRotationEnabled: false` to stop the machine where it
stands (both roots stay trusted), and a restore from your CA Secret backup.
Everything else is the controller's.

Back the Secret up before you touch anything, without exception:

```bash
kubectl -n $HUB_NS get secret pmf-hub-ca -o yaml > ca-backup.yaml
```

## PrometheusMCPHubCARotationStalled

**Means:** a CA rotation has been in `publishing` or `signing` for longer than
`metrics.prometheusRule.thresholds.caRotationStalledSeconds` (75 days by
default, against an expected ~58).

**Nothing is broken.** Both roots are trusted for as long as this lasts, every
spoke verifies, and issuance continues. This is an alert about a job that has
stopped finishing, not about an outage.

Work through it in this order:

1. **Which phase, and for how long.**
   ```bash
   promfleet_hub_ca_rotation_phase
   time() - promfleet_hub_ca_rotation_phase_start_timestamp_seconds
   ```
2. **Is a spoke still holding a certificate from the outgoing root?** This is
   the usual answer in `signing`, and the gate is doing exactly what it is for
   — dropping the root while that spoke depends on it disconnects it.
   ```bash
   sum(promfleet_hub_ca_outgoing_root_sessions)      # fleet-wide; sum, not max
   ```
   A cluster whose spoke cannot renew shows up in
   [PrometheusMCPHubSpokeCertExpiringSoon](#prometheusmcphubspokecertexpiringsoon)
   as well. Fix the renewal and the rotation finishes on its own.
3. **Is the controller running at all?** Check for `CA rotation poll failed` in
   the hub log; an RBAC or API-server problem stalls every phase equally.
4. **Is the clock being restarted?** A replica that keeps repairing the phase
   start logs `CA rotation state recorded ... restarting the phase clock`,
   which means something is rewriting `ca-rotation.since` in the Secret.

The controller never advances on its own past a gate that has not opened, and
it never gives up: once the blockage clears, the next poll moves it on. There
is no "resume" to run.

## PrometheusMCPSpokeCertExpiringSoon

**Means:** an issued spoke certificate expires within 3 days (the default
threshold, against a 14-day certificate lifetime) and renewal is not
succeeding.

Spokes renew at half their lifetime, so reaching this alert means renewal has
been failing for days. Look at the spoke's logs for the renewal error — the most
common causes are the hub's enrollment listener being unreachable from that
cluster, or the spoke's certificate having been revoked.

If it does expire, nothing needs to happen by hand yet: `/renew` accepts a
certificate that has already expired, as long as it is within
`--renew-grace` (default 30 days), and the spoke's own renewal loop keeps
retrying on its normal schedule. That is exactly the case this alert should
usually resolve on its own once the underlying renewal problem — enrollment
listener unreachable, certificate revoked — is fixed. Only once the outage
outlasts the grace period does `/renew` start refusing it, at which point the
cluster needs a fresh enrollment token. Enrollment tokens are reusable by
default (`--single-use` opts out), so minting one does not by itself require
tracking down and burning a one-shot credential.

## PrometheusMCPHubProxyErrorRatioHigh

**Means:** a meaningful fraction of proxied queries are failing.

```promql
sum by (cluster, code) (rate(promfleet_hub_proxy_requests_total{code!~"2.."}[5m]))
```

Read the `code` label first; it tells you which layer is at fault.

| Code | Layer | Likely cause |
|---|---|---|
| `forbidden` | Hub | The agent key's scope does not cover that cluster or tool. The call never left the hub. A steady trickle is an agent probing its limits; a spike after a key rotation means the new key was minted too narrow |
| `invalid` | Hub | A parameter or endpoint the proxy refused before forwarding: a bad `step`, a malformed label name, an endpoint that is gated off or does not exist. Never reaches Prometheus |
| `busy` | Hub | The per-cluster in-flight limit is saturated. An agent is fanning out too hard, or `--max-inflight-per-cluster` is too low for your workload |
| `too_large` | Hub | Results exceed the byte budget. Usually an unbounded range query; the agent should get a hint telling it to raise `step` |
| `timeout` | Hub or tunnel | The call hit `--query-timeout` / `--range-query-timeout`, or the agent went away first. Steady on one cluster points at a slow Prometheus there or a saturated tunnel; fleet-wide points at the hub's deadlines being too short for the workload |
| `unavailable` | Tunnel | That spoke is disconnected — see the tunnel alert. **Or it holds a tunnel to only SOME hub replicas**, which is indistinguishable from here: check [PrometheusMCPSpokePartialCoverage](#prometheusmcpspokepartialcoverage) before concluding the cluster is down |
| `upstream` | Tunnel or spoke | The tunnel was up but the round trip failed for a reason other than a status code: the tunnel dropped mid-call, the spoke could not reach its Prometheus, or the reply could not be decoded. Check the spoke's logs and `describe_cluster` for that cluster |
| `4xx` | Prometheus | Bad PromQL from the agent. Expected at some rate; a spike suggests a model looping |
| `5xx` | Prometheus | The upstream is unhealthy or overloaded. **Check whether your agents caused it** |

That last row deserves attention. The hub bounds response size, not evaluation
cost — we deliberately do not parse PromQL
([ADR-0006](../adr/0006-no-promql-parsing-in-process.md)). If agents are driving
a Prometheus into the ground, the fix is `--query.max-samples` and a query
timeout on the Prometheus itself, plus tighter `limits` on the offending agent
key's scope.

## PrometheusMCPHubRestartLoop

Check `kubectl -n $HUB_NS logs deploy/pmf-hub --previous`. A liveness probe
should not be able to cause this: `/healthz` never checks a dependency, by
design. If the hub is restarting, it is failing at startup — see
[PrometheusMCPHubDown](#prometheusmcphubdown).

If it is OOMKilled, raise the memory limit and check
`promfleet_hub_proxy_response_bytes`. A hundred idle spokes cost about 40 MiB;
concurrent bulk transfer is what drives memory; the global byte budget only
bounds bytes actively in transfer, not the decoded and rendered copies a call
retains after the proxy returns — size the memory limit to several times the
budget (roughly 4x here: a 1Gi limit against a 256Mi budget), not to the budget
itself.

## PrometheusMCPHubStateSecretLarge

Ships in the chart (`rules.stateSecretLarge`, threshold
`thresholds.stateBytes`, default 500 KiB) and fires while there is still a
200 KiB margin under the hub's write ceiling.

**Means:** `promfleet_hub_state_bytes` is approaching the 700 KiB write ceiling.
A Kubernetes Secret caps at 1 MiB, and the hub refuses writes past 700 KiB
rather than discovering the limit during an enrollment.

At roughly a kilobyte per credential this means several hundred records, which
is far past any plausible fleet — so it almost always means accumulated cruft.

**The hub prunes itself, so reaching this alert means something is unusual.**
Every replica sweeps the state document on `--state-prune-interval` (6h by
default, jittered ±20% so replicas started together do not stay in lockstep),
dropping expired credentials and revocations for certificates that have
expired anyway, each kept `--renew-grace` + `--state-retention` (30d + 30d)
past its expiry — the grace because `/renew` still honours an expired
certificate for that long, the retention as a forensics window. A cluster's
newest enrollment record is never dropped, however old: it carries the
operator's labels for that cluster. Running one pruner per replica is deliberate and needs no
leader: the sweep is a compare-and-swap like every other write, so one
replica wins and the rest re-read, find the work done and write nothing. Check that it is actually running before you prune by hand:

```bash
# Should climb. If it is absent, no prune has ever removed anything.
promfleet_hub_state_pruned_total
kubectl -n $HUB_NS logs deploy/pmf-hub | grep -E "pruned state records|state prune did not run|pruning is disabled"
```

Three reasons the alert fires anyway, in order of likelihood:

1. **Pruning is disabled** (`--state-prune-interval=0`). The startup log says
   so explicitly.
2. **The records are not prunable.** Live credentials, revoked-but-unexpired
   ones, and anything minted with `--no-expiry` are all kept on purpose — a
   revoked no-expiry key's record is the only thing refusing it. A fleet with
   hundreds of live agent keys is a fleet that needs a bigger conversation
   than a prune.
3. **Genuine scale.** A hundred clusters rebuilt often enough leaves more
   live enrollment records than the ceiling allows.

For 2 and 3, the manual route below is still the tool.

Look at what is actually stored. Every administrative command runs inside the
pod, against the loopback admin listener, so nothing has to be exposed:

```bash
X="kubectl -n $HUB_NS exec deploy/pmf-hub -- hub"
$X keys list   --admin-token-file /var/run/pmf/admin-token
$X enroll list --admin-token-file /var/run/pmf/admin-token
$X certs list  --admin-token-file /var/run/pmf/admin-token
```

Then withdraw what should not be there — revoking rather than purging, so the
audit trail survives:

```bash
$X keys revoke   --kid <kid>    --reason "..." --admin-token-file /var/run/pmf/admin-token
$X enroll revoke --kid <kid>    --reason "..." --admin-token-file /var/run/pmf/admin-token
$X certs revoke  --serial <hex> --reason "..." --admin-token-file /var/run/pmf/admin-token
```

The token file is mounted by `adminToken.existingSecret` (see the quickstart).
The admin API is the same data if you prefer curl — port-forward 9090 and the
CLI's own default URL is already `http://127.0.0.1:9090`.

Prune expired agent keys and burned enrollment records, and revoked certificate
serials whose `notAfter` has passed. If you genuinely need more records than
that, the state backend needs to change — open an issue rather than raising the
ceiling.



## PrometheusMCPHubRevocationStale

**Means:** this hub replica has not successfully refreshed its revoked-serial
list for `thresholds.revocationStaleSeconds` (default 300s — ten refresh
intervals). The replica is healthy and serving, deliberately: a credential
store outage must not disconnect the fleet. What it is NOT doing is learning
about new revocations, so a spoke certificate revoked since the last refresh
is still admitted by this replica for as long as the alert is firing.

**Check the hub's access to its state Secret.** The refresh is a read of the
same Secret every credential operation uses, so this alert rarely comes alone:

```bash
kubectl -n $HUB_NS logs deploy/pmf-hub | grep -i "revocation\|state"
kubectl -n $HUB_NS auth can-i get secrets --as system:serviceaccount:$HUB_NS:pmf-hub
```

Usual causes, in order: the kube-apiserver is degraded (the alert fires on
every replica at once), the hub's RBAC was changed (fires on every replica,
starting at the next rollout), or one node's network is broken (fires on one).

**While it fires,** a revocation you commit still lands in the store and is
enforced by every replica that can read it; only the affected replica keeps
serving its last good list. If you must sever a specific compromised spoke NOW
and this alert is firing on the replica holding its tunnel, delete that hub
pod: the spoke's reconnect lands on a healthy replica, which checks the store.

## PrometheusMCPHubPeerDiscoveryBroken

**Means:** this hub replica's headless-Service lookup resolves fewer replicas
than the chart deployed. The number it resolves is the number every spoke is
told in the tunnel handshake, and spokes size their tunnel pools from it — so
while it is low, spokes hold too few tunnels and a share of tool calls answer
"cluster not connected". The spokes' own `PartialCoverage` alert cannot catch
this case: they never learn a count to fall short of.

**Check, in order:**

```bash
# Does the headless Service exist and select every hub pod?
kubectl -n $HUB_NS get endpoints pmf-hub-peers -o wide
# Can a hub pod resolve it? (DNS egress is the usual culprit)
kubectl -n $HUB_NS exec deploy/pmf-hub -- getent hosts pmf-hub-peers.$HUB_NS.svc
# The hub logs every failed lookup at WARN:
kubectl -n $HUB_NS logs deploy/pmf-hub | grep "peer discovery failed"
```

Usual causes: a NetworkPolicy that blocks DNS from the hub pods, the headless
Service deleted or renamed out from under `--peer-discovery-domain`, or a
selector drift so the Service matches no pods. Fixing the lookup is the whole
fix — spokes pick the new count up within about a minute through their
coverage probes.

## PrometheusMCPHubSpokeCertExpiringSoon

The **hub's** view of a spoke certificate nearing expiry
(`promfleet_hub_spoke_cert_expiry_seconds`), as distinct from
[PrometheusMCPSpokeCertExpiringSoon](#prometheusmcpspokecertexpiringsoon),
which is the spoke's own view of its own certificate. The hub sees every
cluster, so this is the one that catches a spoke too broken to alert for itself.

A spoke renews at half its certificate's life, so this firing means renewal has
been failing for days.

```bash
kubectl -n <ns> logs deploy/<hub> | grep -E 'renewal|cert.renewed'
```

Renewal needs no enrollment token, so a spoke that can reach the hub fixes
itself. If the certificate has already expired, it still can: `/renew` accepts
an expired certificate for `--renew-grace` (30 days by default) given proof the
spoke holds the private key. Past that window the spoke must enrol again.

## PrometheusMCPSpokeDown

The spoke is not being scraped at all (`absent(up == 1)`). This says nothing
about the tunnel: a spoke can be serving the fleet perfectly while its own
metrics endpoint is unreachable, and it can be scraped fine while its tunnel is
down. Check the hub's view before assuming this cluster has lost agent access:

```bash
# What does the hub think? This is the question that matters.
kubectl -n <hub-ns> port-forward deploy/<hub> 9090:9090
curl -s localhost:9090/metrics | grep promfleet_hub_spoke_connected
```

If the hub still shows the cluster connected, this is *probably* a monitoring
problem rather than an availability one — usually a ServiceMonitor selector or a
NetworkPolicy.

**One trap before you conclude that.** `promfleet_hub_spoke_connected` is 1 on
any replica holding a tunnel, so it reads 1 even when the spoke reaches only
SOME replicas and a share of tool calls are failing. If agents are reporting
intermittent "cluster not connected", check
[PrometheusMCPSpokePartialCoverage](#prometheusmcpspokepartialcoverage) before
treating this as cosmetic.

## PrometheusMCPSpokePrometheusDown

`promfleet_spoke_prom_up == 0`: the spoke is healthy and connected, but the
Prometheus it proxies to is unreachable. The cluster stays in the fleet and is
reported **degraded** rather than disappearing, deliberately — an agent gets an
explicit error naming the reason, which is more useful than a cluster silently
missing from `list_clusters`.

```bash
kubectl -n <ns> logs deploy/<spoke> | grep -i prometheus
kubectl -n <ns> exec deploy/<spoke> -- wget -qO- $PMF_PROMETHEUS_URL/-/ready
```

Almost always the local Prometheus, not the spoke: check it is up, that
`prometheus.url` is right, and that a NetworkPolicy permits the spoke to reach
it.

## PrometheusMCPSpokePromErrorRatioHigh

The local Prometheus is answering, but returning 5xx to the spoke. Distinguish
this from the alert above: the path works, the server is failing.

Common causes, in the order worth checking: the query load from agents is
heavier than that Prometheus can serve; a query is hitting
`--query.max-samples`; the server is under memory pressure and OOM-killing
queries. Tighten the agent key's scope limits if a single agent is responsible —
that is what they are for.

## PrometheusMCPSpokeTunnelFlapping

The tunnel is reconnecting repeatedly rather than staying down, which is worse
than being cleanly down: each reconnect re-registers the cluster and re-publishes
facts, and agents see intermittent failures rather than a clear one.

```bash
kubectl -n <ns> logs deploy/<spoke> | grep -E 'tunnel closed|reason='
```

The reason label is a closed set and names the cause directly. One reason is
excluded from the alert itself: `redundant-replica` is the spoke's own
coverage machinery working as designed — the once-a-minute probe cycle, and
deliberate redials during a coverage search — so it never counts as flapping.
If you are staring at raw counter increases rather than the alert, subtract
that reason first. An Ingress with
an idle timeout shorter than the 10-second keepalive is the classic one: the
proxy closes a quiet tunnel, the spoke redials, and the cycle repeats. Raise
the proxy's timeout rather than lowering the keepalive.

## PrometheusMCPSpokeFactsRefreshFailing

The tunnel is up, but the spoke's periodic refresh of cluster facts is failing,
so what the hub reports about this cluster is going stale.

This is quieter than it sounds and worth understanding before you chase it. The
facts are what an agent reads from `list_clusters` and `describe_cluster` —
Prometheus version, retention, scrape interval, series and job counts. Queries
keep working throughout; the routing table is unaffected. What degrades is the
agent's *picture* of the cluster, which is exactly the input it uses to decide
what to query. Stale retention or a stale series count leads a model to plan
against a cluster that no longer exists in that shape.

```bash
kubectl -n <ns> logs deploy/<spoke> | grep -i facts
```

Usually the same cause as
[PrometheusMCPSpokePromErrorRatioHigh](#prometheusmcpspokepromerrorratiohigh):
the queries behind the facts (`kubernetes_build_info`, `kube_node_info`, TSDB
status) are failing or timing out. A cluster that does not scrape
kube-state-metrics cannot supply some of them at all — set
`cluster.k8sVersion`, `cluster.k8sUid` and `cluster.k8sNodes` in the spoke's
values instead, which take precedence over anything derived.

## PrometheusMCPSpokePartialCoverage

`promfleet_spoke_tunnels_covered < promfleet_spoke_hub_replicas`: this spoke has
a tunnel to some hub replicas but not all of them.

**Read this section before you trust `promfleet_hub_spoke_connected`.** A tunnel
terminates on exactly one replica and the hub does not forward between replicas.
Reach two of three and the cluster looks *connected* — because two replicas do
have it — while roughly a third of tool calls land on the replica that does not
and fail with `cluster not connected`, the same error a completely dead cluster
returns. `PrometheusMCPSpokeTunnelDown` will not fire: that needs EVERY endpoint
down.

This is the failure that sends people hunting through PromQL, agent scopes and
the local Prometheus while the actual cause is one line of Ingress config.

```bash
# From the spoke's own metrics: how many replicas does it see, how many has it reached?
promfleet_spoke_hub_replicas
promfleet_spoke_tunnels_covered

# The spoke logs which replica answered each dial.
kubectl -n <ns> logs deploy/<spoke> | grep -E 'hub replica covered|redundant tunnel'
```

| Cause | Why it does this | Fix |
|---|---|---|
| **Session affinity on the hub's Ingress** | The load balancer pins this spoke to one backend, so redialing can never reach the others. This is the usual cause | Turn affinity off. Coverage is achieved by redialing the same hostname |
| A hub replica is not Ready | It is out of the Service, so nothing can dial it, but its peers still count it | Fix the replica; coverage recovers by itself |
| Hub scaled up recently | The spoke learns the new count on its next handshake and dials the difference | Wait one coverage interval (10s); if it persists, suspect affinity |
| Per-replica hostnames configured, one is wrong | With explicit `hub.endpoints` there is no discovery to fall back on | Check DNS and the certificate SANs for each endpoint |

If you deliberately run one hub replica behind a load balancer you do not
control, set `metrics.prometheusRule.rules.partialCoverage: false` rather than
leaving it firing.

## Security events

These are logged on a separate stream and should be routed to your SIEM, not
just to a dashboard.

| Event | Severity | Response |
|---|---|---|
| `enrollment token replay` (409) | **High**, unless the token was minted `--single-use` or with `--max-redemptions` on purpose. Enrollment tokens are reusable with no cap by default, and ordinary reinstalls or sibling pods enrolling together never trigger this against a default token | Check what the token was minted with (`GET /admin/v1/enrollments`). If it was single-use or capped and still got replayed, the install secret leaked — find out where it was stored and who could read it. The burn/cap check is atomic, so no extra certificate was issued beyond the limit |
| `cluster ID mismatch` | Medium | A spoke reported an ID different from its certificate. The hub used the certificate. Investigate that spoke |
| Repeated `authn failure` from one source | Medium | Credential stuffing or a misconfigured client. Rate limiting is already applied |
| `key revoked` / `scope changed` unexpectedly | **High** | An admin credential may be compromised. Rotate it |
| Certificate presented after revocation | Medium | Expected briefly after revoking; persistent means a compromised spoke is retrying |

## Disaster recovery

### The hub is gone entirely

The hub is stateless apart from two Secrets. Reinstall the chart into a
namespace containing them and it comes back with the same CA, the same pepper
and the same issued keys. Spokes reconnect on their own.

### The CA Secret is lost

This is the scenario worth rehearsing, because it is the only one with a real
cost.

- Existing spokes **keep working** until their certificates expire — at most 14
  days.
- No renewal succeeds in the meantime.
- Without a backup: generate a new CA, roll the new trust bundle to all hundred
  clusters, mint a hundred fresh enrollment tokens, and re-enroll.

Self-service rotation does not help here and cannot: the whole state machine
lives in this Secret, so losing it loses the rotation as well as the root.
Restoring a backup taken mid-rotation is safe — the phase, its start time and
both roots come back together, and the controller carries on from whichever
phase the backup recorded.

```bash
# Do this now, not during the incident. The Secret is <release fullname>-ca
# under the chart (pmf-hub-ca with the quickstart's values); the unprefixed
# prometheus-mcp-fleet-ca default applies only outside the chart.
kubectl -n $HUB_NS get secret pmf-hub-ca -o yaml > ca-backup.yaml
```

Test the restore quarterly. An untested backup is not a backup.

### The state Secret is lost

Less severe: the CA survives, so spokes keep working and keep renewing. What is
lost is the issued **agent keys** and enrollment records. Re-mint agent keys and
redistribute them. Nothing about the fleet's connectivity is affected.

### Everything is on fire and you need agents cut off now

Revoking every agent key is one loop over `hub keys list` and
`hub keys revoke`, and it takes effect within one cache TTL (60 seconds by
default) because the revocation epoch invalidates every cached entry. Use
`keys list --json` rather than parsing the table: key names may contain
spaces, so a column count is not a safe way to find the status. Select on
`revoked` (a key that has merely expired is harmless to revoke again); the
admin token file is the one the chart mounts from `adminToken.existingSecret`:

```bash
kubectl -n $HUB_NS exec deploy/pmf-hub -- \
  hub keys list --class agent --json --admin-token-file /var/run/pmf/admin-token |
  jq -r '.keys[] | select(.revoked | not) | .kid' |
  while read -r kid; do
    kubectl -n $HUB_NS exec deploy/pmf-hub -- \
      hub keys revoke --kid "$kid" --reason incident \
        --admin-token-file /var/run/pmf/admin-token
  done
```

The same data is on the admin API (`GET /admin/v1/keys?class=agt`, `DELETE
/admin/v1/keys/<kid>?reason=...`) if you would rather port-forward and `curl`.

This revokes **agent keys** (MCP access), not spoke certificates. Revoking a
spoke's certificate is checked at handshake only — it does not tear down a
tunnel that is already up, so it will not immediately disconnect a spoke that
is already connected. If the thing on fire is a compromised spoke rather than
a compromised agent, cut its tunnel by scaling that spoke down or blocking its
egress in its own cluster; revoking its certificate only stops it from
reconnecting or renewing afterward.

Scaling the hub to zero also works and is faster, but it is a blunter instrument
— it stops enrollment and renewal too.
