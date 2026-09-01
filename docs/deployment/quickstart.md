<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# Quickstart

From nothing to an AI agent querying two clusters. Budget about twenty minutes.

**The shape of it:** you install the hub **once**, in a cluster you control. Then
you install the spoke **once per monitored cluster** — a separate Helm release,
from a separate chart, in a different cluster each time. The spoke chart contains
no hub templates and references no hub resource; all it knows is an address, a
trust bundle and an enrollment token (reusable when minted by `hub enroll create`; see
[spoke-enrollment.md](../spoke-enrollment.md#tokens-are-reusable-by-default)).

## Prerequisites

- A cluster for the hub with a standard Ingress controller. No LoadBalancer, no
  NodePort and no TCP passthrough are needed.
- One or more clusters to monitor, each running Prometheus, each with **egress**
  to the hub. No inbound access to them is needed — that is the point.
- `helm` 3.19+, `kubectl`.
- One DNS name pointing at the hub cluster (`pmf.example.com`).

One name, because the tunnel is a WebSocket on the same HTTP listener as the
MCP endpoint. Mutual authentication happens inside the connection rather than at
the TLS layer, which is what lets it traverse an ordinary Ingress
([ADR-0014](../adr/0014-websocket-tunnel-through-standard-ingress.md)).

## 1. Install the hub

```bash
kubectl create namespace prometheus-mcp-hub

helm install pmf-hub oci://ghcr.io/jacoknapp/charts/prometheus-mcp-hub \
  --namespace prometheus-mcp-hub \
  --set fullnameOverride=pmf-hub \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.host=pmf.example.com \
  --set ingress.tls.enabled=true \
  --set ingress.tls.secretName=pmf-tls \
  --set config.publicURL=https://pmf.example.com/mcp \
  --set config.trustDomain=fleet.example.com
```

`fullnameOverride=pmf-hub` matters beyond cosmetics: the chart's default name
is `<release>-<chart>` whenever the release name doesn't already contain the
chart name (`prometheus-mcp-hub`), which would render the Deployment as
`pmf-hub-prometheus-mcp-hub` instead of `pmf-hub` and break every
`deploy/pmf-hub` command below, along with the CA Secret name the spoke
install further down points at (`pmf-hub-ca`).

On first boot the hub generates its own CA and HMAC pepper into a Secret it
owns, using a Role scoped by `resourceNames` to exactly that object. There is no
volume to provision and nothing sensitive in `values.yaml`.

One hostname carries everything: the MCP endpoint at `/mcp` and the spoke
tunnel at `/tunnel`, both plain HTTP through the Ingress. There is no second
Service and no passthrough to arrange.

Confirm it is up:

```bash
kubectl -n prometheus-mcp-hub rollout status deploy/pmf-hub
kubectl -n prometheus-mcp-hub logs deploy/pmf-hub | head -20
```

## 2. Capture the bootstrap admin token

The hub prints an admin token **once**, on first start. Save it now.

```bash
kubectl -n prometheus-mcp-hub logs deploy/pmf-hub | grep pmf_adm_
export PMF_ADMIN_TOKEN='pmf_adm_...'
```

Every admin route, including the one that mints keys, requires a valid admin
bearer token — there is no bypass for `kubectl exec`. So losing this token
**before** minting a replacement with it is not casually recoverable: without
any usable admin credential you cannot authenticate a call to mint another
one. Recovery then means waiting for this bootstrap credential to expire (tied
to `--agent-key-ttl`, 30 days by default) and restarting the hub, which mints
a fresh one only once none of the stored admin keys are still usable. Keep
this one, and mint a properly scoped replacement with it soon after — see
[step 4](#4-mint-an-agent-key) for the `hub keys create` invocation and pass
`--class admin`.

## 3. Export the CA bundle

Each spoke is in a different cluster and different trust domain, so it needs the
hub's CA out of band for its first connection.

There is no `hub ca` subcommand (the hub binary only implements `hub enroll
create` and `hub keys create`). The bundle is served unauthenticated at
`/pki/bundle` on the same public hostname as the MCP endpoint, so no `exec` is
needed at all:

```bash
curl -fsS https://pmf.example.com/pki/bundle > hub-ca.crt
```

## 4. Mint an agent key

```bash
kubectl exec -n prometheus-mcp-hub deploy/pmf-hub -- \
  hub keys create \
    --admin-token-file /var/run/pmf/admin-token \
    --class agent \
    --name sre-oncall-bot \
    --clusters 'env=prod' \
    --tools list_clusters,describe_cluster,query,query_range,alerts,targets
# pmf_agt_3Kf9aQ2mZx…   shown once
```

**Scope it narrowly.** This is the control that holds when everything else
fails: an agent that is successfully prompt-injected still cannot exceed its
scope. `--clusters '*' --tools '*'` is for a demo, not for production.

Note `--clusters 'env=prod'` selects by **label**, which means the clusters must
be enrolled with that label in the next step.

## 5. Enroll each cluster

Repeat this pair of steps once per cluster.

**On the hub — mint a token bound to one cluster ID:**

```bash
kubectl exec -n prometheus-mcp-hub deploy/pmf-hub -- \
  hub enroll create \
    --admin-token-file /var/run/pmf/admin-token \
    --cluster prod-us-east-1 \
    --labels env=prod,region=us-east-1
# pmf_enr_9dK2mQ4pLz…   valid 15 minutes, reusable
```

**In the target cluster — install the spoke:**

```bash
kubectl create namespace prometheus-mcp

kubectl create secret generic pmf-enrollment -n prometheus-mcp \
  --from-literal=token='pmf_enr_9dK2mQ4pLz…'

kubectl create secret generic pmf-hub-ca -n prometheus-mcp \
  --from-file=ca.crt=hub-ca.crt

helm install pmf-spoke oci://ghcr.io/jacoknapp/charts/prometheus-mcp-spoke \
  --namespace prometheus-mcp \
  --set fullnameOverride=pmf-spoke \
  --set cluster.id=prod-us-east-1 \
  --set cluster.sdlc=prod \
  --set cluster.labels[0].name=env --set cluster.labels[0].value=prod \
  --set cluster.labels[1].name=region --set cluster.labels[1].value=us-east-1 \
  --set hub.endpoints[0]=wss://pmf.example.com/tunnel \
  --set hub.apiUrl=https://pmf.example.com \
  --set hub.existingCASecret=pmf-hub-ca \
  --set enrollment.existingSecret=pmf-enrollment \
  --set prometheus.url=http://prometheus-operated.monitoring.svc:9090
```

`fullnameOverride=pmf-spoke` is the same fix as for the hub above — without it
the Deployment renders as `pmf-spoke-prometheus-mcp-spoke`, not `pmf-spoke`,
breaking the `deploy/pmf-spoke` command below. `cluster.labels` is a **list**
of `{name, value}` entries, not a map. Every one of `cluster.id`,
`cluster.sdlc`, `hub.endpoints`, `hub.apiUrl` and `prometheus.url` differs per
cluster and has **no default**. A default that happened to work in one place
would be a trap in the other ninety-nine.

Verify:

```bash
kubectl -n prometheus-mcp logs deploy/pmf-spoke | grep -E 'certificate|tunnel'
# obtained client certificate  cluster_id=prod-us-east-1 not_after=…
# tunnel established           endpoint=wss://pmf.example.com/tunnel
```

Now repeat for `prod-eu-west-1`, and so on.

## 6. Point your agent at it

```json
{
  "mcpServers": {
    "prometheus-fleet": {
      "type": "http",
      "url": "https://pmf.example.com/mcp",
      "headers": { "Authorization": "Bearer pmf_agt_3Kf9aQ2mZx…" }
    }
  }
}
```

Ask it *"which prod clusters have firing alerts?"* It should call
`list_clusters`, then `alerts`, and answer.

## 7. Before you call it production

- [ ] **Scope every agent key** to the clusters and tools it actually needs.
- [ ] **Back up the hub's CA Secret**, and test the restore. Losing it means
      re-enrolling every cluster. The chart names it `<release>-ca`
      (`state.caSecretName` overrides it) — with `fullnameOverride=pmf-hub` set
      above, that's `pmf-hub-ca`, not the binary's own unprefixed default of
      `prometheus-mcp-fleet-ca`, which only applies outside this chart.
      ```bash
      kubectl -n prometheus-mcp-hub get secret pmf-hub-ca -o yaml > ca-backup.yaml
      ```
- [ ] Set `--query.max-samples` and a query timeout on every Prometheus. The hub
      bounds response size, not evaluation cost.
- [ ] Run Prometheus with `--web.enable-admin-api=false` and
      `--web.enable-lifecycle=false`.
- [ ] Enable etcd encryption at rest — credential material lives in Secrets now.
- [ ] Install the shipped `PrometheusRule`, or copy its alerts.
- [ ] Add the token regex `pmf_(adm|agt|enr)_[0-9A-Za-z]{53}_[0-9A-Za-z]{6}` to
      your secret scanner and log scrubber.
- [ ] Read the [hardening checklist](../security.md#hardening-checklist).

## Onboarding at scale

Do not paste a hundred tokens by hand. Mint them as part of the rollout — they
are short-lived on purpose — and feed your existing secret delivery. See
[spoke-enrollment.md](../spoke-enrollment.md#onboarding-a-hundred-clusters).

## Where next

| | |
|---|---|
| [Configuration](../configuration.md) | Every flag and environment variable |
| [MCP tools](../mcp-tools.md) | What the agent can actually do |
| [Security](../security.md) | Threat model and hardening |
| [High availability](../operations/high-availability.md) | How multi-replica HA works (both charts default to `replicaCount: 3`) |
| [Runbook](../operations/runbook.md) | Alert-driven procedures |
| [Troubleshooting](../troubleshooting.md) | Symptom → cause → fix |
