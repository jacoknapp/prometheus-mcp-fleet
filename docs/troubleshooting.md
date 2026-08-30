<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

Symptom first, ordered by how often each actually happens. For alert-driven
procedures see the [runbook](operations/runbook.md).

## Start here

```bash
# Hub
kubectl -n prometheus-mcp-hub logs deploy/pmf-hub --tail=100
kubectl -n prometheus-mcp-hub port-forward deploy/pmf-hub 9090:9090 &
curl -s localhost:9090/readyz | jq     # names exactly what is blocking

# Spoke (in its own cluster)
kubectl -n prometheus-mcp logs deploy/pmf-spoke --tail=100
```

`/readyz` returns JSON listing each not-ready component with a reason. Read it
before guessing — it is right more often than intuition.

## The agent cannot connect

**`401 Unauthorized` from `/mcp`**

The key is wrong, expired, revoked, or of the wrong class. An *admin* key
presented to the MCP endpoint is rejected on purpose — the classes are separated
so that a leaked agent key can never administer the hub, and vice versa.

```bash
kubectl exec -n prometheus-mcp-hub deploy/pmf-hub -- hub keys list --class agt
```

The hub never echoes the offending token, in the response or in the log. That is
deliberate; identify the key by its KID, which is the ten characters after the
`pmf_agt_` prefix and is safe to share.

**`403` or an empty `list_clusters`**

The key authenticated but its scope permits nothing. An empty scope authorizes
nothing by design. Check what it was minted with:

```bash
kubectl exec -n prometheus-mcp-hub deploy/pmf-hub -- hub keys get <kid>
```

The most common cause is a scope with `matchLabels: {env: prod}` against
clusters that were enrolled without labels. Labels are set at enrollment; a
cluster enrolled without them is a cluster no scoped key can see.

**The client reports a protocol or version error**

The hub speaks MCP revision `2026-07-28`. That revision removed protocol
sessions, the GET stream and resumability. A client pinned to an older revision
that insists on `Mcp-Session-Id` will not work — the hub does not mint one.
Update the client.

**The client tries an OAuth flow and fails**

The hub is not an OAuth authorization server. It authenticates with a static
bearer key and says so in its RFC 9728 document at
`/.well-known/oauth-protected-resource/mcp`, which advertises
`authorization_servers: []` and `x-pmf-auth: ["static-bearer"]`. Configure the
client with a bearer header instead. See
[ADR-0003](adr/0003-mcp-streamable-http-stateless.md) for why.

## A cluster is missing or disconnected

**It never appears in `list_clusters`**

The registry is in memory and self-registering: a cluster appears when its spoke
connects and not before. There is no enrolled-but-never-seen state to inspect,
which is intentional — showing a cluster an agent then cannot query is worse
than not showing it.

Work in the spoke's cluster. See
[spoke-enrollment.md](spoke-enrollment.md#when-it-goes-wrong) for the full
table; the three that account for most cases are an expired enrollment token
(15 minutes, single use), blocked egress to the hub, and a missing hub CA
bundle.

**It shows `degraded`**

The tunnel is up but the spoke cannot reach its own Prometheus. `describe_cluster`
carries the reason. Check `prometheus.url` from inside the spoke pod's network,
not from your laptop.

**It flaps between connected and disconnected**

Two clusters were enrolled with the same `cluster.id`. Identity is bound to the
certificate, and the generation compare-and-swap means the newer session always
evicts the older — so two spokes claiming one ID take turns evicting each other,
forever. Give one a new ID and re-enroll.

**It disappeared right after a hub restart**

Expected, briefly. Spokes reconnect on a jittered backoff and the fleet view
rebuilds within seconds. If it does not come back, the spoke's logs will say
why.

## Queries fail or return odd results

**`busy` / "retry shortly"**

The per-cluster in-flight limit is saturated. Either an agent is fanning out too
aggressively, or `--max-inflight-per-cluster` (default 8) is too low for your
workload. The hub refuses rather than queueing unboundedly, on purpose: an
unbounded queue converts a load problem into a latency problem you cannot see.

**`too_large` / truncated results**

The response exceeded the byte budget, which is enforced *during* the read and
applies to the decompressed size. The error carries a hint — usually to raise
`step` or narrow the selector. This is working as intended; an agent that could
pull 32 MiB into its context has already lost.

**The numbers look smoothed or wrong**

Check the `downsampled` object in the response. The hub auto-selects `step` to
stay within a point budget and **always reports when it has done so**
(`requestedStep`, `appliedStep`, `reason`). If a model is reasoning about a
spike, it needs to know it is looking at averaged data. If you need the raw
resolution, narrow the time range rather than raising `maxPoints`.

**`truncated` with `selection: "top_20_by_max"`**

Series truncation keeps the top N by maximum value. This will sometimes discard
the series that mattered — a flatlined series that *should* have been spiking is
exactly the one a max-based selection drops. Select the series you care about
with a matcher rather than hoping it survives.

**PromQL errors**

These are Prometheus' own parse errors, passed through with a caret and a hint.
The hub deliberately does not parse PromQL
([ADR-0006](adr/0006-no-promql-parsing-in-process.md)). Use the
`explain_promql` tool to validate without executing — it costs a few hundred
tokens instead of a failed range query.

**Queries are slow, or Prometheus is struggling**

The hub bounds *response size*, not *evaluation cost*. Set
`--query.max-samples` and a query timeout on the Prometheus servers themselves;
that is the backstop that actually bounds work. Then tighten `limits` on the
offending agent key's scope.

## The hub will not start

| Log line | Cause | Fix |
|---|---|---|
| `cannot create the CA secret … needs a Role granting create on secrets` | RBAC missing, or `resourceNames` does not match the configured Secret names | Reconcile the Role against `PMF_STATE_SECRET_NAME` and `PMF_CA_SECRET_NAME` |
| `exists but the key does not` | The CA Secret was partially restored or hand-edited | Restore `ca.crt` and `ca.key` together |
| `another replica created the CA secret first` | Two replicas started simultaneously on first boot | Informational. The loser adopts the winner's material and continues |
| `state exceeds the write ceiling` | The state Secret is approaching 700 KiB | Prune expired keys and burned enrollments; see the runbook |
| `403` on any Secret operation | The projected token lacks a verb | The error names the exact rule you are missing |

There is no PVC, so a pod stuck in `Pending` is a scheduling problem — resources,
taints, node capacity — not a storage one.

## Certificates

**`x509: certificate signed by unknown authority`** — the spoke does not trust
the hub's CA. Fetch it from `GET /pki/bundle` and supply it as `hub.caBundle`.

**`remote error: tls: bad certificate`** — the hub rejected the spoke. Usually
revoked; check the hub's audit log for the serial.

**`certificate has expired`** — renewal has been failing for at least half the
certificate's lifetime. The spoke's logs have the renewal error. An expired
identity needs a fresh single-use enrollment token, deliberately.

**The whole fleet fails verification at once** — the hub's tunnel certificate
changed and its SANs no longer match the name spokes dial. Check
`PMF_TUNNEL_SERVER_NAMES`.

## Nothing here matches

Turn up the logs and watch one request end to end:

```bash
kubectl -n prometheus-mcp-hub set env deploy/pmf-hub PMF_LOG_LEVEL=debug
```

Debug logs one line per request with a `request_id` that also appears in the
spoke's logs for the same call, so you can follow it across the tunnel. Secrets
are wrapped in a redacting type, so debug output is safe to paste into an issue
— but read it first anyway.

If you are still stuck, open an issue with: the hub and spoke versions
(`hub version`), the output of `/readyz`, the relevant log lines including the
`request_id`, and what you expected instead. For anything with a security
dimension, use [SECURITY.md](../SECURITY.md) rather than the issue tracker.
