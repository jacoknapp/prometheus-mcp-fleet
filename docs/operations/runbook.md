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
- [PrometheusMCPHubProxyErrorRatioHigh](#prometheusmcphubproxyerrorratiohigh)
- [PrometheusMCPHubRestartLoop](#prometheusmcphubrestartloop)
- [PrometheusMCPHubStateSecretLarge](#prometheusmcphubstatesecretlarge)
- [PrometheusMCPHubSpokeCertExpiringSoon](#prometheusmcphubspokecertexpiringsoon)
- [PrometheusMCPSpokeDown](#prometheusmcpspokedown)
- [PrometheusMCPSpokePrometheusDown](#prometheusmcpspokeprometheusdown)
- [PrometheusMCPSpokePromErrorRatioHigh](#prometheusmcpspokepromerrorratiohigh)
- [PrometheusMCPSpokeTunnelFlapping](#prometheusmcpspoketunnelflapping)
- [PrometheusMCPSpokePartialCoverage](#prometheusmcpspokepartialcoverage)
- [PrometheusMCPSpokeFactsRefreshFailing](#prometheusmcpspokefactsrefreshfailing)
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
| `x509: certificate signed by unknown authority` | The spoke does not trust the hub's CA | Re-supply `hub.caBundle`; fetch it from `GET /pki/bundle` |
| `x509: certificate has expired` | The spoke's own certificate lapsed | Nothing, usually: `/renew` accepts an expired certificate within `--renew-grace` (default 30 days), and the spoke's own renewal loop keeps retrying it automatically. Past that grace period `/renew` refuses it and the cluster needs a fresh enrollment token |
| `auth-rejected` | The hub refused the handshake — usually a revoked certificate | Check the hub's audit log for the serial |
| `upgrade-rejected` / `404` | The Ingress is not routing `/tunnel` | Fix the Ingress path |
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
| `busy` | Hub | The per-cluster in-flight limit is saturated. An agent is fanning out too hard, or `--max-inflight-per-cluster` is too low for your workload |
| `too_large` | Hub | Results exceed the byte budget. Usually an unbounded range query; the agent should get a hint telling it to raise `step` |
| `unavailable` | Tunnel | That spoke is disconnected — see the tunnel alert. **Or it holds a tunnel to only SOME hub replicas**, which is indistinguishable from here: check [PrometheusMCPSpokePartialCoverage](#prometheusmcpspokepartialcoverage) before concluding the cluster is down |
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

No PrometheusRule ships for this today — `promfleet_hub_state_bytes` exists but
nothing alerts on it yet, so this section is here for when you wire that alert
yourself, or when someone notices the metric climbing during triage for
something else.

**Means:** `promfleet_hub_state_bytes` is approaching the 700 KiB write ceiling.
A Kubernetes Secret caps at 1 MiB, and the hub refuses writes past 700 KiB
rather than discovering the limit during an enrollment.

At roughly a kilobyte per credential this means several hundred records, which
is far past any plausible fleet — so it almost always means accumulated cruft.

There is no `hub keys list` or `hub enroll list` CLI subcommand — the hub
binary's only administrative subcommands are `enroll create` and `keys create`
(`internal/hubcli`). List and prune through the admin REST API directly:

```bash
kubectl -n $HUB_NS port-forward deploy/pmf-hub 9090:9090 &
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  'localhost:9090/admin/v1/keys?class=agt' | jq
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  localhost:9090/admin/v1/enrollments | jq
```

`$ADMIN_TOKEN` is the `pmf_adm_…` credential you saved at install time (see the
quickstart) or a replacement minted since. The admin API listens on the same
loopback port as `/metrics`, `/readyz` and `/healthz`, so the same
port-forward from Quick triage above already reaches it.

Prune expired agent keys and burned enrollment records, and revoked certificate
serials whose `notAfter` has passed. If you genuinely need more records than
that, the state backend needs to change — open an issue rather than raising the
ceiling.



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

The reason label is a closed set and names the cause directly. An Ingress with
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

Revoking every agent key is a single loop against the admin API (there is no
`hub keys list` or `hub keys revoke` CLI subcommand — only `enroll create` and
`keys create` exist), and it takes effect within one cache TTL (60 seconds by
default) because the revocation epoch invalidates every cached entry:

```bash
kubectl -n $HUB_NS port-forward deploy/pmf-hub 9090:9090 &
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  'localhost:9090/admin/v1/keys?class=agt' |
  jq -r '.keys[].kid' |
  xargs -n1 -I{} curl -s -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
    "localhost:9090/admin/v1/keys/{}?reason=incident"
```

This revokes **agent keys** (MCP access), not spoke certificates. Revoking a
spoke's certificate is checked at handshake only — it does not tear down a
tunnel that is already up, so it will not immediately disconnect a spoke that
is already connected. If the thing on fire is a compromised spoke rather than
a compromised agent, cut its tunnel by scaling that spoke down or blocking its
egress in its own cluster; revoking its certificate only stops it from
reconnecting or renewing afterward.

Scaling the hub to zero also works and is faster, but it is a blunter instrument
— it stops enrollment and renewal too.
