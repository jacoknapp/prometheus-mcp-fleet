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

## Contents

- [Quick triage](#quick-triage)
- [PrometheusMCPHubDown](#prometheusmcphubdown)
- [PrometheusMCPSpokesDisconnected](#prometheusmcpspokesdisconnected)
- [PrometheusMCPSpokeTunnelDown](#prometheusmcpspoketunneldown)
- [PrometheusMCPHubCACertExpiringSoon](#prometheusmcphubcacertexpiringsoon)
- [PrometheusMCPSpokeCertExpiringSoon](#prometheusmcpspokecertexpiringsoon)
- [PrometheusMCPProxyErrorRatioHigh](#prometheusmcpproxyerrorratiohigh)
- [PrometheusMCPHubRestartLoop](#prometheusmcphubrestartloop)
- [PrometheusMCPHubStateSecretLarge](#prometheusmcphubstatesecretlarge)
- [PrometheusMCPAutoUpdateFailed](#prometheusmcpautoupdatefailed)
- [Security events](#security-events)
- [Disaster recovery](#disaster-recovery)

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
guessing.

## PrometheusMCPHubDown

**Means:** the hub is not being scraped, or has no ready replica. All agent
access is gone.

1. `kubectl -n $HUB_NS get pods` — is it `CrashLoopBackOff`, `Pending`, or gone?
2. `kubectl -n $HUB_NS logs deploy/pmf-hub --previous` for the crash reason.

The three failures that account for most of these:

| Log line | Cause | Fix |
|---|---|---|
| `cannot create the CA secret … the hub needs a Role granting create on secrets` | RBAC is missing or its `resourceNames` do not match the configured Secret names | Reconcile `PMF_STATE_SECRET_NAME` / `PMF_CA_SECRET_NAME` against the Role's `resourceNames` |
| `load or create the CA: … exists but the key does not` | The CA Secret was partially restored or hand-edited | Restore both `ca.crt` and `ca.key` together, or see [disaster recovery](#disaster-recovery) |
| `bind: address already in use` | A port collides with something else in the pod | Check the three listener addresses |

If the pod is `Pending`, it is a scheduling problem, not a hub problem. There is
no PVC to be stuck on — the hub has no volume claim at all — so look at
resources, taints and node capacity.

**Recovery is just a restart.** The registry is in memory and self-registering:
spokes reconnect on their own backoff and the fleet view rebuilds within
seconds. There is nothing to restore and no consistency to worry about.

## PrometheusMCPSpokesDisconnected

**Means:** more than 10% of enrolled clusters have no live tunnel for 10
minutes. A fleet-wide symptom, not a per-cluster one.

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
   kubectl -n $HUB_NS get svc pmf-hub-tunnel
   openssl s_client -connect pmf-tunnel.example.com:8443 -alpn h2 </dev/null | head -20
   ```
3. **Did the tunnel server certificate change?** If the hub re-issued it with
   different SANs, every spoke will now fail verification. Check
   `PMF_TUNNEL_SERVER_NAMES` matches the name spokes actually dial.
4. **Are the spokes' certificates expiring en masse?** A fleet enrolled on the
   same afternoon expires on the same afternoon. Check
   `promfleet_hub_spoke_cert_expiry_seconds`.

If it is a subset rather than the fleet, treat it as many instances of the next
alert.

## PrometheusMCPSpokeTunnelDown

**Means:** one cluster has no tunnel for 15 minutes.

Work in the **spoke's** cluster — this is almost always a network problem there,
not a hub problem.

```bash
kubectl -n prometheus-mcp logs deploy/pmf-spoke --tail=50
```

| Log line | Cause | Fix |
|---|---|---|
| `dial tcp: i/o timeout` | Egress to the hub is blocked | Check the NetworkPolicy and the cluster's egress firewall |
| `x509: certificate signed by unknown authority` | The spoke does not trust the hub's CA | Re-supply `hub.caBundle`; fetch it from `GET /pki/bundle` |
| `x509: certificate has expired` | The spoke's own certificate lapsed | Mint a fresh enrollment token and re-enroll |
| `remote error: tls: bad certificate` | The hub rejected it — usually revoked | Check the hub's audit log for the serial |
| `no such host` | DNS in that cluster cannot resolve the hub | Check the cluster's DNS and the NetworkPolicy's DNS egress rule |

The spoke retries with full jitter forever, so there is nothing to restart once
the underlying cause is fixed.

## PrometheusMCPHubCACertExpiringSoon

**Means:** the CA certificate expires within 14 days. **This is the most serious
alert in this document.** When the CA expires, every spoke certificate becomes
unverifiable and the entire fleet disconnects.

Rotation is not yet a single command. The procedure is:

1. Back up the current CA Secret first, without exception:
   ```bash
   kubectl -n $HUB_NS get secret prometheus-mcp-fleet-ca -o yaml > ca-backup.yaml
   ```
2. Issue a new CA and serve **both** in the trust bundle so spokes accept either
   during the overlap.
3. Roll the bundle to every spoke (`hub.caBundle`), and confirm each has picked
   it up before proceeding.
4. Once every spoke trusts the new CA, let renewals migrate them onto
   certificates signed by it. At a 14-day certificate lifetime, full migration
   takes a fortnight.
5. Retire the old CA only after `promfleet_hub_spoke_cert_expiry_seconds` shows
   no certificate still chained to it.

Do not shortcut this by replacing the CA in place. That disconnects the fleet
instantly and requires re-enrolling all hundred clusters by hand.

## PrometheusMCPSpokeCertExpiringSoon

**Means:** an issued spoke certificate expires within 7 days and renewal is not
succeeding.

Spokes renew at half their lifetime, so reaching this alert means renewal has
been failing for days. Look at the spoke's logs for the renewal error — the most
common causes are the hub's enrollment listener being unreachable from that
cluster, or the spoke's certificate having been revoked.

If it does expire, that cluster needs a fresh single-use enrollment token. That
is deliberate: an expired identity should require a deliberate act.

## PrometheusMCPProxyErrorRatioHigh

**Means:** a meaningful fraction of proxied queries are failing.

```promql
sum by (cluster, code) (rate(promfleet_hub_proxy_requests_total{code!~"2.."}[5m]))
```

Read the `code` label first; it tells you which layer is at fault.

| Code | Layer | Likely cause |
|---|---|---|
| `busy` | Hub | The per-cluster in-flight limit is saturated. An agent is fanning out too hard, or `--max-inflight-per-cluster` is too low for your workload |
| `too_large` | Hub | Results exceed the byte budget. Usually an unbounded range query; the agent should get a hint telling it to raise `step` |
| `unavailable` | Tunnel | That spoke is disconnected — see the tunnel alert |
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
concurrent bulk transfer is what consumes memory, and the global byte budget is
what bounds it.

## PrometheusMCPHubStateSecretLarge

**Means:** `promfleet_hub_state_bytes` is approaching the 700 KiB write ceiling.
A Kubernetes Secret caps at 1 MiB, and the hub refuses writes past 700 KiB
rather than discovering the limit during an enrollment.

At roughly a kilobyte per credential this means several hundred records, which
is far past any plausible fleet — so it almost always means accumulated cruft.

```bash
kubectl exec -n $HUB_NS deploy/pmf-hub -- hub keys list --class agt
kubectl exec -n $HUB_NS deploy/pmf-hub -- hub enroll list
```

Prune expired agent keys and burned enrollment records, and revoked certificate
serials whose `notAfter` has passed. If you genuinely need more records than
that, the state backend needs to change — open an issue rather than raising the
ceiling.

## PrometheusMCPAutoUpdateFailed

The in-cluster updater refused to proceed or rolled back. This alert firing is
the system **working**: it verifies a cosign signature and SLSA provenance
before patching, and refuses on failure.

```bash
kubectl -n <ns> logs job/<release>-autoupdate-<id>
```

| Message | Meaning | Action |
|---|---|---|
| `cosign verify` failed | The image is unsigned or not signed by this repository's identity | **Do not bypass.** Verify what is in the registry |
| `verify-attestation` failed | No SLSA provenance | Same |
| `rollout status` timed out, `rollout undo` ran | The new image is bad | The cluster is back on the previous digest. Stop promoting, investigate |

If several clusters report this at once, the release is bad. **Stop approving
promotions** — that freezes the whole fleet with no code change, and is the
intended kill switch ([ADR-0011](../adr/0011-auto-update-is-opt-in.md)).

## Security events

These are logged on a separate stream and should be routed to your SIEM, not
just to a dashboard.

| Event | Severity | Response |
|---|---|---|
| `enrollment token replay` (409) | **High** | The install secret leaked. Find out where the token was stored and who could read it. The burn is atomic, so no second certificate was issued |
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

```bash
# Do this now, not during the incident
kubectl -n $HUB_NS get secret prometheus-mcp-fleet-ca -o yaml > ca-backup.yaml
```

Test the restore quarterly. An untested backup is not a backup.

### The state Secret is lost

Less severe: the CA survives, so spokes keep working and keep renewing. What is
lost is the issued **agent keys** and enrollment records. Re-mint agent keys and
redistribute them. Nothing about the fleet's connectivity is affected.

### Everything is on fire and you need agents cut off now

Revoking every agent key is a single loop, and it takes effect within one cache
TTL (60 seconds by default) because the revocation epoch invalidates every
cached entry:

```bash
kubectl exec -n $HUB_NS deploy/pmf-hub -- hub keys list --class agt --quiet |
  xargs -n1 -I{} kubectl exec -n $HUB_NS deploy/pmf-hub -- \
    hub keys revoke {} --reason "incident"
```

Scaling the hub to zero also works and is faster, but it is a blunter instrument
— it stops enrollment and renewal too.
