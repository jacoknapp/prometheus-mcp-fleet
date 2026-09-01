<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# prometheus-mcp-fleet

**Give an AI agent one endpoint and let it query Prometheus across your entire fleet.**

[![CI](https://github.com/jacoknapp/prometheus-mcp-fleet/actions/workflows/ci.yml/badge.svg)](https://github.com/jacoknapp/prometheus-mcp-fleet/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/jacoknapp/prometheus-mcp-fleet.svg)](https://pkg.go.dev/github.com/jacoknapp/prometheus-mcp-fleet)
[![Go Report Card](https://goreportcard.com/badge/github.com/jacoknapp/prometheus-mcp-fleet)](https://goreportcard.com/report/github.com/jacoknapp/prometheus-mcp-fleet)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/jacoknapp/prometheus-mcp-fleet/badge)](https://scorecard.dev/viewer/?uri=github.com/jacoknapp/prometheus-mcp-fleet)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`prometheus-mcp-fleet` is a [Model Context Protocol](https://modelcontextprotocol.io)
server for fleets of Prometheus servers. You point your agent at **one hub**; a
small **spoke** runs in each cluster and dials out to that hub over a mutually
authenticated tunnel. The agent gets the full Prometheus query surface across
every cluster, with the hub handling routing, discovery, authorization and the
budget enforcement that keeps a curious model from melting a production TSDB or
its own context window.

It is built for roughly 100 clusters. The spoke idles at about 20 MiB, and
**there is no database and no PersistentVolumeClaim anywhere** — the fleet is
self-registering, so the only durable state is a little credential material in a
Kubernetes Secret.

---

## Why hub and spoke

The obvious design — point the agent at each Prometheus directly — falls over
at fleet scale for three reasons, and this project is shaped by all three.

1. **Reachability.** 100 clusters means 100 firewall exceptions, 100 ingress
   objects and 100 certificates maintained by 100 teams. The spoke dials *out*
   over ordinary egress instead, so onboarding a cluster is `helm install` plus
   one enrollment token.
2. **Discovery.** An agent asked "why is checkout latency bad in eu-west?" must
   first work out *where to look*. Each spoke publishes cluster facts — labels,
   Prometheus version, retention, job names, metric-name prefixes, alert counts
   — so the hub can answer "which clusters even have this metric?" without
   fanning a query out to all of them.
3. **Context economy.** Prometheus' native JSON will bury a model. A six-hour
   range query over 84 series is roughly 4.1 MB of JSON, which fits in no
   context window that exists. The hub re-encodes it columnar, auto-selects the
   step, caps series, and marks every truncation explicitly — the same query
   comes back at about 15 KB — a 272-fold reduction, measured by a regression
   test rather than asserted here.

### No database

The cluster registry is *derived*, not stored. Spokes reconnect on a backoff and
re-publish their facts, so the hub rebuilds its whole view of the fleet within
seconds of a restart. The only state that genuinely must survive is credential
material — the CA key, the HMAC pepper, the issued key records and the revoked
serials — and that is small, and secret, so it lives in a Kubernetes Secret the
hub owns.

That removes a PVC, a StorageClass dependency, a backup story and a single-writer
constraint. It also means every hub replica sees the same credentials: a Secret's
`resourceVersion` gives optimistic concurrency, which is what makes single-use
enrollment atomic across replicas without a lock service.

---

## Architecture

```mermaid
flowchart LR
    subgraph agents ["AI agents"]
        A1["Claude / any MCP client"]
    end

    subgraph hubns ["Hub cluster"]
        H["hub<br/>MCP server · registry · CA · admin API"]
        SEC[["Secret<br/>CA key · pepper · issued keys"]]
        H --- SEC
    end

    subgraph c1 ["Cluster: prod-us-east-1"]
        S1["spoke"] --> P1[("Prometheus")]
    end
    subgraph c2 ["Cluster: prod-eu-west-1"]
        S2["spoke"] --> P2[("Prometheus")]
    end
    subgraph cN ["… 98 more clusters"]
        SN["spoke"] --> PN[("Prometheus")]
    end

    A1 -->|"HTTPS + Bearer pmf_agt_…<br/>MCP Streamable HTTP"| H
    S1 -.->|"dials out · wss:// · gRPC"| H
    S2 -.->|"dials out · wss:// · gRPC"| H
    SN -.->|"dials out · wss:// · gRPC"| H
```

Every arrow from a spoke points *at* the hub: spokes always initiate, over
ordinary outbound HTTPS. The tunnel is a **WebSocket on the hub's normal HTTP
port**, so it reaches the hub through a standard Ingress — no TCP passthrough,
no LoadBalancer, no NodePort, no second hostname
([ADR-0014](docs/adr/0014-websocket-tunnel-through-standard-ingress.md)).

Once the WebSocket is up the roles invert and the spoke serves gRPC over the
connection it opened, so the hub still gets HTTP/2 stream multiplexing,
per-request cancellation and deadline propagation without any bespoke framing
([ADR-0002](docs/adr/0002-spoke-dialed-reversed-grpc-tunnel.md)).

Because an Ingress terminates TLS, the hub cannot see a client certificate, so
mutual authentication happens **inside** the connection: the hub sends a
single-use nonce and the spoke returns its certificate plus a signature over it.
That is TLS's own `CertificateVerify` step performed one layer up — the private
key never leaves the spoke, and identity still comes only from the certificate.

### Request path

```mermaid
sequenceDiagram
    participant Agent
    participant Hub
    participant Spoke
    participant Prom as Prometheus

    Agent->>Hub: tools/call query {cluster, promql}
    Hub->>Hub: verify pmf_agt_ key, evaluate scope
    Hub->>Hub: map tool → allow-listed endpoint, validate params
    Hub->>Hub: acquire per-cluster + global budget
    Hub->>Spoke: Proxy(path, form) over existing tunnel
    Spoke->>Spoke: re-validate path against its own allow-list
    Spoke->>Prom: POST /api/v1/query
    Prom-->>Spoke: JSON (gzip)
    Spoke-->>Hub: streamed 64 KiB chunks
    Hub->>Hub: decode, cap, downsample, sanitize, encode compact
    Hub-->>Agent: structured result + explicit truncation markers
```

---

## Quickstart

### 1. Install the hub

```bash
helm install pmf-hub oci://ghcr.io/jacoknapp/charts/prometheus-mcp-hub \
  --namespace prometheus-mcp --create-namespace \
  --set ingress.enabled=true \
  --set ingress.host=pmf.example.com \
  --set ingress.tls.enabled=true
```

The hub generates its own CA and HMAC pepper on first boot and writes them to a
Secret it owns, using a Role scoped by `resourceNames` to exactly that Secret.
Nothing sensitive goes in `values.yaml`, and there is no volume to provision.

Everything — the MCP endpoint and the spoke tunnel alike — is served on one HTTP
port behind one standard `networking.k8s.io/v1` Ingress. There is no second
Service, no LoadBalancer and no passthrough annotation to arrange.

### 2. Mint an agent key

```bash
kubectl exec -n prometheus-mcp deploy/pmf-hub -- \
  hub keys create --class agent --name sre-oncall-bot \
    --clusters 'env=prod' --tools query,query_range,alerts,list_clusters
# pmf_agt_3Kf9aQ2mZx…  (shown once — store it now)
```

### 3. Enroll a cluster

Mint an enrollment token bound to one cluster ID. Tokens are reusable by
default — so one token can enroll several spoke pods that start together, or
survive a cluster rebuild — pass `--single-use` to burn it on first
redemption instead:

```bash
kubectl exec -n prometheus-mcp deploy/pmf-hub -- \
  hub enroll create --cluster prod-us-east-1 --labels env=prod,region=us-east-1
# pmf_enr_9dK2mQ4pLz…  (valid 15 minutes, reusable)
```

Then, **in the target cluster**:

```bash
kubectl create namespace prometheus-mcp
kubectl create secret generic pmf-enrollment -n prometheus-mcp \
  --from-literal=token='pmf_enr_9dK2mQ4pLz…'

helm install pmf-spoke oci://ghcr.io/jacoknapp/charts/prometheus-mcp-spoke \
  --namespace prometheus-mcp \
  --set cluster.id=prod-us-east-1 \
  --set cluster.sdlc=prod \
  --set hub.endpoints[0]=wss://pmf.example.com/tunnel \
  --set hub.apiUrl=https://pmf.example.com \
  --set enrollment.existingSecret=pmf-enrollment \
  --set prometheus.url=http://prometheus-operated.monitoring.svc:9090
```

The spoke generates a P-256 key, exchanges a CSR for a 14-day client
certificate, redeems the enrollment token, and dials the hub. Since the token
above wasn't minted with `--single-use`, it survives that redemption and can
enroll more spoke pods for the same cluster — useful for a rebuild, or for
several pods started together. The key never crosses the network — it is
written only to a Secret in the spoke's own namespace so a restart does not
need a fresh enrollment token. Repeat for each cluster.

### 4. Point your agent at it

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

Ask it *"which prod clusters have firing alerts right now?"* and it will call
`list_clusters`, then `alerts`, and answer.

Full walkthrough: [docs/deployment/quickstart.md](docs/deployment/quickstart.md).

---

## What the agent can do

Sixteen tools covering the Prometheus surface, all read-only:

| | |
|---|---|
| **Discover** | `list_clusters` · `describe_cluster` · `search_metrics` · `metric_metadata` |
| **Query** | `query` · `query_range` · `series` · `label_names` · `label_values` |
| **Operate** | `targets` · `rules` · `alerts` · `tsdb_stats` · `runtime_info` |
| **Fleet** | `fanout_query` — one PromQL across many clusters, partial failure reported explicitly |
| **Assist** | `explain_promql` — validate a query without executing it |

Plus MCP resources (`fleet://clusters`, `fleet://alerts/firing`) and five prompt
templates for common SRE tasks. Every tool's JSON schema, defaults, caps and
error codes: [docs/mcp-tools.md](docs/mcp-tools.md).

---

## Security model in brief

| Credential | Prefix | Lifetime | Can |
|---|---|---|---|
| Admin | `pmf_adm_` | 90d | Administer the hub, on a separate listener |
| Agent | `pmf_agt_` | 30d | Call the MCP tools its scope permits |
| Enrollment | `pmf_enr_` | 15m, reusable by default | Exchange a CSR for one or more spoke certificates |
| Spoke identity | X.509 | 14d, auto-renewed | Serve one cluster, and only that cluster |

- **An agent never supplies a URL.** It names a tool; the tool maps to a
  hard-coded path. SSRF and path traversal are removed structurally, not filtered.
- **The spoke re-validates every request** against its own copy of the
  allow-list, so a compromised hub still cannot reach a destructive endpoint.
- **Identity is certificate-bound.** A spoke's cluster ID comes only from its
  certificate's URI SAN; nothing it reports at runtime can override it.
- **Keys are stored as HMAC-SHA256 with an out-of-database pepper**, compared in
  constant time. A database leak alone yields nothing usable.
- **The Ingress is inside the trust boundary.** It terminates TLS, so it can
  observe tunnel traffic. It cannot impersonate a spoke — it never holds a
  spoke's private key and the signature covers a nonce the hub chose — but this
  is a real reduction against end-to-end mTLS, and
  [ADR-0014](docs/adr/0014-websocket-tunnel-through-standard-ingress.md) states
  it rather than glossing it.
- **The spoke's RBAC is one Secret.** It needs `get,create,update` on exactly the
  one Secret holding its own client key and certificate, restricted by
  `resourceNames` — nothing cluster-scoped, nothing else in the namespace. It
  runs with `readOnlyRootFilesystem`, non-root, all capabilities dropped, and an
  egress-only NetworkPolicy. An RBAC-free mode is available at the cost of
  re-enrolling on every restart.
- **Prompt injection is assumed to succeed.** Metric labels and alert
  annotations are attacker-influenced text; we frame them as data, strip control
  and bidirectional characters, clip lengths, and never render links. The control
  that actually holds is the scope document on the agent's key.

Full threat model: [docs/security.md](docs/security.md). Reporting:
[SECURITY.md](SECURITY.md).

---

## Operating a fleet

- **Updating is yours to drive.** The charts do not ship an in-cluster updater.
  Images are rebuilt weekly against fresh bases and republished, signed and with
  SLSA provenance, and `stable` moves only through a human-approved promotion —
  but nothing in the cluster acts on that by itself. Point your existing
  delivery mechanism at the digest you want. An unattended rollout across a
  hundred production clusters is a fleet-wide outage delivery mechanism, and the
  hub is the single point of failure for every agent.
- **The hub defaults to three replicas behind a single Ingress hostname.**
  Credentials live in a shared Secret, so every replica sees the same keys —
  but a *tunnel* pins a spoke to the replica that accepted it, and there is
  deliberately no hub-to-hub forwarding. That used to mean every replica needed
  its own external hostname wired into every spoke; now the hub counts its own
  replicas via a headless Service and tells each spoke how many to expect, and
  the spoke keeps dialing the one hostname until it has reached them all. A
  cluster may likewise run several spoke pods, pooled by the hub with no leader
  election. Documented in full:
  [docs/operations/high-availability.md](docs/operations/high-availability.md).
- Alerts, runbooks and dashboards: [docs/operations/](docs/operations/).

---

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | Components, data flow, session lifecycle, failure domains |
| [Security](docs/security.md) | Threat model, PKI, credential lifecycle, prompt injection |
| [MCP tools](docs/mcp-tools.md) | Every tool, schema, example and error code |
| [Configuration](docs/configuration.md) | Every environment variable and flag |
| [Deployment](docs/deployment/) | Quickstart, hub chart, spoke chart, TLS |
| [Spoke enrollment](docs/spoke-enrollment.md) | Token → CSR → certificate → renewal → revocation |
| [Operations](docs/operations/) | Runbook, alerts, HA, capacity |
| [Troubleshooting](docs/troubleshooting.md) | Symptom → cause → fix |
| [Development](docs/development.md) | Build, test, lint, codegen, release |
| [ADRs](docs/adr/) | Why the design is the way it is |

---

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the
development loop, the dependency budget (it is deliberately tiny — a new direct
dependency needs an ADR), and the review checklist.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
