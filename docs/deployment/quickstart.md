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
`deploy/pmf-hub` command below, along with the name of the CA Secret the hub
writes (`pmf-hub-ca`) that the backup step further down reads.

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
one. Recovery then means waiting for this bootstrap credential to expire
(`--admin-key-ttl`, 90 days by default) and restarting the hub, which mints
a fresh one only once none of the stored admin keys are still usable. Keep
this one, and mint a properly scoped replacement with it soon after — see
[step 4](#4-mint-an-agent-key) for the `hub keys create` invocation and pass
`--class admin`.

**Now put it where the hub can read it.** Every admin command below passes
`--admin-token-file`, and that file only exists in the pod when the chart is
told which Secret holds it. Passing the token as a `kubectl exec` argument
instead would put a live admin credential in the node's process table, which
is why the file is the documented path:

```bash
kubectl -n prometheus-mcp-hub create secret generic pmf-admin \
  --from-literal=admin-token="$PMF_ADMIN_TOKEN"

helm upgrade pmf-hub oci://ghcr.io/jacoknapp/charts/prometheus-mcp-hub \
  --namespace prometheus-mcp-hub --reuse-values \
  --set adminToken.existingSecret=pmf-admin
```

The chart mounts it at `/var/run/pmf/admin-token`
(`adminToken.key` and `adminToken.mountPath` move it). Wait for the rollout to
finish before step 4, or the exec lands on a pod that predates the mount:

```bash
kubectl -n prometheus-mcp-hub rollout status deploy/pmf-hub
```

## 3. Decide how the spoke will trust the hub

The spoke verifies the certificate the hub's **Ingress** presents on
`wss://pmf.example.com/tunnel` and `https://pmf.example.com`. That is ordinary
server-certificate trust, exactly like a browser's, and it has nothing to do
with the hub's own CA:

- **Ingress certificate from a public issuer** (Let's Encrypt, a commercial CA):
  nothing to do. The spoke's image ships the system roots and
  `hub.caBundle` stays empty. This is the common case and the one the
  install in step 5 assumes.
- **Ingress certificate from a private issuer** (an internal PKI, a
  cert-manager `ClusterIssuer` backed by your own root): supply **that
  issuer's** CA certificate to the spoke as `hub.caBundle` or
  `hub.existingCASecret`. It is public material, so a Secret is a convenience,
  not a requirement.

Do **not** supply the bundle the hub serves at `/pki/bundle`. That is the
internal CA the hub uses to sign **spoke identities**; it has never signed the
Ingress certificate and cannot verify it, so a spoke told to trust it fails
every dial with `x509: certificate signed by unknown authority`. The spoke
receives that bundle on its own at enrollment; nothing in this quickstart needs
to fetch it.

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

**Lifetime.** An agent key lasts 90 days by default (`--agent-key-ttl`). Nothing
rotates it: the holder is an AI agent's configuration file, not a process that
can re-enrol itself, so a lapsed key is an outage on a timer rather than a
credential that quietly renews. Where that trade is not worth making, mint the
key with no expiry:

```bash
hub keys create --class agent --name sre-oncall-bot --no-expiry ...
```

`--no-expiry` is refused for admin keys and enrollment tokens: an admin key
mints other credentials and drives CA rotation, and an enrollment token admits
new clusters, so neither should be able to outlive the operator who created it.
It is also refused alongside `--ttl`, rather than one silently winning.

A key with no expiry is still withdrawable: every MCP call authenticates
independently, so a revocation blocks the very next call within the hub's
60-second key cache. It is a key that outlives the calendar, not one that
outlives your control.

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

helm install pmf-spoke oci://ghcr.io/jacoknapp/charts/prometheus-mcp-spoke \
  --namespace prometheus-mcp \
  --set fullnameOverride=pmf-spoke \
  --set cluster.id=prod-us-east-1 \
  --set cluster.sdlc=prod \
  --set cluster.labels[0].name=env --set cluster.labels[0].value=prod \
  --set cluster.labels[1].name=region --set cluster.labels[1].value=us-east-1 \
  --set hub.endpoints[0]=wss://pmf.example.com/tunnel \
  --set hub.apiUrl=https://pmf.example.com \
  --set enrollment.existingSecret=pmf-enrollment \
  --set prometheus.url=http://prometheus-operated.monitoring.svc:9090
```

If the hub's Ingress certificate comes from a private issuer (step 3), put that
issuer's CA in a Secret and add it to the install:

```bash
kubectl create secret generic pmf-hub-ingress-ca -n prometheus-mcp \
  --from-file=ca.crt=ingress-issuer-ca.crt
# ... and on the helm install above:
#   --set hub.existingCASecret=pmf-hub-ingress-ca
```

`fullnameOverride=pmf-spoke` is the same fix as for the hub above — without it
the Deployment renders as `pmf-spoke-prometheus-mcp-spoke`, not `pmf-spoke`,
breaking the `deploy/pmf-spoke` command below. `cluster.labels` is a **list**
of `{name, value}` entries, not a map. `cluster.id`, `cluster.sdlc`,
`hub.endpoints` and `hub.apiUrl` differ per cluster and have **no default** —
a default that happened to work in one place would be a trap in the other
ninety-nine. `prometheus.url` does default, to
`http://prometheus-operated.monitoring.svc:9090`, which is where the
Prometheus Operator puts it; set it anyway if yours lives elsewhere.

Verify:

```bash
kubectl -n prometheus-mcp logs deploy/pmf-spoke | grep -E 'certificate|tunnel'
# obtained client certificate  cluster_id=prod-us-east-1 serial=… not_after=…
# tunnel connected             hub_server_id=pmf-hub-… hub_replicas=3
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
      re-enrolling every cluster. The chart names it `<fullname>-ca`, where
      the fullname is what `fullnameOverride` sets (`state.caSecretName`
      overrides the whole thing) — with `fullnameOverride=pmf-hub` set above,
      that's `pmf-hub-ca`, not the binary's own unprefixed default of
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
