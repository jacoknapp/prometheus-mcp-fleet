<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# Configuration

Every setting is available as both a command-line flag and an environment
variable. The two names derive from a single declaration in `internal/config`,
so they cannot drift: flag `--foo-bar` is environment variable `PMF_FOO_BAR`.

**Precedence:** flag > environment variable > default.

Validation reports *every* problem at once rather than the first, and each
message names both the flag and the variable it came from. The full list is
generated from the source and is meant to be printed by `--help` — but as of
this writing `--help` exits `0` and prints nothing (a bug: the loader builds
the usage text, main just never writes it out). Until that is fixed, passing
any unrecognised flag prints the same usage text to stderr as a side effect of
reporting the error:

```console
$ hub --not-a-real-flag   # prints the full flag list to stderr, then exits 1
$ hub version
```

## Hub

### Listeners

The three listeners are separated deliberately: an agent key reaching the admin
API would be a privilege escalation, so the admin API is not on the port an
agent can reach.

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--mcp-addr` | `:8080` | Agent-facing MCP endpoint. Exposed through a standard Ingress. |
| `--tunnel-path` | `/tunnel` | Path on the MCP listener where spokes open a WebSocket. There is no separate tunnel port: an Ingress terminates TLS, so mutual authentication happens inside the connection (ADR-0014). |
| `--admin-addr` | `127.0.0.1:9090` | Admin API, metrics, health and pprof. **Never expose this.** The chart fails the render if you try. |
| `--public-url` | — | Canonical external URL of the MCP endpoint, used in the RFC 9728 protected-resource document. |
| `--peer-discovery-domain` | — | Headless Service FQDN resolving to one address per hub replica. Enables multi-replica HA behind one Ingress hostname: since a tunnel terminates on exactly one replica and there is no hub-to-hub forwarding, the hub counts addresses here and tells each spoke how many replicas to expect, so it dials the same hostname until it has seen them all. Empty disables discovery. |

### State

There is no database and no PersistentVolumeClaim; see
[ADR-0005](adr/0005-no-database-state-in-secrets.md).

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--state-backend` | `auto` | `secret`, `file`, or `auto` to pick by whether a projected service account token is present. |
| `--state-secret-name` | `prometheus-mcp-fleet-state` | Secret holding the credential records. |
| `--ca-secret-name` | `prometheus-mcp-fleet-ca` | Secret holding the CA certificate, key and HMAC pepper. Separate from the state Secret so the two have different blast radii. |
| `--state-file` | `<data-dir>/state.json` | JSON file used by the `file` backend. |
| `--namespace` | projected | Namespace of both Secrets. |
| `--data-dir` | `/var/lib/prometheus-mcp-fleet` | Scratch space for CA material and the pepper. **Need not be durable** — it is an `emptyDir` in the chart. |

The hub needs a Role granting `get,create,update` on `secrets`, restricted by
`resourceNames` to exactly those two objects. A missing Role surfaces as a
startup error naming the rule you are missing.

### PKI

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--trust-domain` | `fleet.local` | Authority component of spoke certificate URI SANs (`pmf://<domain>/spoke/<id>`). Lowercase DNS name. |
| `--ca-cert-file` | — | Internal CA certificate. Empty self-initialises inside `--data-dir`. |
| `--ca-key-file` | — | Private key for the above. Both must be set or neither. |
| `--ca-trust-bundle-file` | — | Additional root certificates accepted on spoke chains alongside the active signer. **Every root in this file can mint any spoke identity in the fleet** — it is not "the CA my Ingress uses", and pointing it at a corporate CA would let anyone holding a client cert from that CA authenticate as any cluster. Normal rotations never need it: the hub carries its outgoing root through the CA Secret on its own. It exists for recovery — rejoining a hub to a fleet whose Secret was restored from a backup taken before a rotation. Empty trusts only the signer. |
| `--ca-rotation-enabled` | `true` | Let the hub rotate its own signing root: publish the successor, switch signing once every spoke trusts it, and retire the outgoing root only when no live session still chains to it. Requires `--state-backend=secret`. See [ADR-0015](adr/0015-ca-rotation.md). |
| `--ca-rotate-at-remaining-fraction` | `0.2` | Fraction of the signing root's life remaining at which rotation begins. |
| `--ca-rotation-poll-interval` | `5m` | How often each replica re-reads the CA Secret to notice a rotation another replica started. |
| `--spoke-cert-ttl` | `336h` (14d) | Lifetime of an issued spoke certificate. Spokes renew at half life with jitter. |
| `--renew-grace` | `720h` (30d) | How long after expiry `/renew` still accepts a spoke's certificate, given a valid possession proof and an unrevoked serial. `0` restores strict expiry. See [Renewing an expired certificate](spoke-enrollment.md#renewing-an-expired-certificate). |

### Credentials

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--enrollment-token-ttl` | `15m` | Lifetime of an enrollment token. Applies whether the token is reusable (the default) or `--single-use`; a reusable token still expires, it just can be redeemed more than once before it does. |
| `--agent-key-ttl` | `2160h` (90d) | Default lifetime of a minted agent key, and the maximum a create request may ask for. Nothing rotates agent keys automatically, so expiry here is an outage on a timer; a key may also be minted with no expiry at all (`--no-expiry`, agent keys only). |
| `--admin-key-ttl` | `2160h` (90d) | Default and maximum lifetime of a minted admin key, including the bootstrap key printed on first start. Separate from `--agent-key-ttl` on purpose: relaxing agent expiry must not silently relax the credential that mints credentials, and unlike an agent key an admin key can never be minted without an expiry. |
| `--pepper-file` | `<data-dir>/pepper.key` | Out-of-database HMAC pepper. Generated on first start. |

### Limits

These are the guardrails that stop a curious model from melting a production
TSDB. A scope attached to an agent key can tighten any of them; nothing can
widen them past what is set here.

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--query-timeout` | `30s` | Instant and metadata queries. |
| `--range-query-timeout` | `120s` | Range queries. |
| `--max-response-bytes` | `32Mi` | Maximum accepted from one upstream response, enforced **during** the read and applied to the decompressed size. |
| `--max-inflight-per-cluster` | `8` | Per-cluster in-flight limit. Over it returns a retryable "busy", not an unbounded queue. |
| `--max-response-budget-bytes` | `256Mi` | Process-wide budget for response bytes actively IN TRANSFER. It is reserved before the upstream call and released the moment it returns, so it does not cover the decoded and rendered copies a tool call still holds afterwards — set the pod memory limit to several times this, not equal to it. |
| `--max-spokes` | `0` | Optional cap on concurrent spoke sessions per hub replica. `0` means no limit. It counts sessions, not clusters — a cluster holds one per spoke pod. |
| `--facts-poll-interval` | `60s` | How often cluster facts are refreshed. Unchanged facts cost about 40 bytes. |
| `--enable-status-config` | `false` | Ungates `/api/v1/status/config`. **Leave this off** unless you have audited your scrape configurations — they routinely contain bearer tokens in plain text. |

> The hub bounds *response size*, not *evaluation cost*. We deliberately do not
> parse PromQL ([ADR-0006](adr/0006-no-promql-parsing-in-process.md)), so an
> expensive query still reaches Prometheus. Set `--query.max-samples` and a
> query timeout on your Prometheus servers; that is the backstop that actually
> bounds work.

### Observability and lifecycle

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. `debug` logs one line per request. |
| `--log-format` | `json` | `json` or `text`. |
| `--otel-exporter-otlp-endpoint` | — | OTLP/gRPC endpoint for traces. Empty installs a no-op provider with no network activity. Also honours the unprefixed `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `--trace-sample-ratio` | `0.05` | Trace sampling ratio. |
| `--pprof-enabled` | `false` | Exposes `/debug/pprof` on the admin listener only. |
| `--shutdown-drain-delay` | `5s` | How long `/readyz` reports 503 before work stops, so the endpoint controller notices first. |
| `--shutdown-grace` | `30s` | Budget for in-flight work to finish. |

## Spoke

### Hub connection

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--hub-endpoints` | **required** | Comma-separated hub tunnel URLs, e.g. `wss://pmf.example.com/tunnel`. List one per hub replica; the spoke holds a tunnel to each. |
| `--hub-api-url` | **required** | HTTPS base URL of the hub's enrollment listener. |
| `--hub-ca-file` | — | Trust bundle for the hub. Empty uses the bundle cached in `--data-dir` from enrollment. |
| `--hub-tls-insecure` | `false` | Skips verification of the hub certificate. Requires `--allow-insecure` as a second, deliberate opt-in. |
| `--allow-insecure` | `false` | Permits the insecure options. Never set this in production. |
| `--reconnect-min-backoff` | `500ms` | Initial reconnect delay. |
| `--reconnect-max-backoff` | `30s` | Maximum reconnect delay. Full jitter is applied — with ~100 spokes, synchronised retry against a restarting hub is a self-inflicted denial of service. |

### Identity

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--cluster-id` | **required** | Immutable cluster identity, matching `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`. It ends up in a certificate SAN. |
| `--cluster-sdlc` | **required** | Lifecycle stage such as `dev`, `staging` or `prod`. Normalised before validation — `PROD` and `Pre Prod` become `prod` and `pre-prod` — then published as the reserved label `sdlc`, which agent key scopes and `fanout_query` select on. A cluster enrolled without it is one no scoped credential can reach and no fleet-wide query targets. |
| `--cluster-display-name` | — | Human-facing name, e.g. `prod-us-east-1`. |
| `--cluster-description` | — | One line describing what this cluster runs. Shown to the agent. |
| `--cluster-k8s-version` | — | Kubernetes version, for a cluster whose Prometheus does not publish `kubernetes_build_info`. The spoke has no Kubernetes API access by design, so without either source this fact is unavailable. Set, it wins over anything derived. |
| `--cluster-k8s-uid` | — | Kubernetes cluster UID, same reasoning as `--cluster-k8s-version`. |
| `--cluster-k8s-nodes` | `0` | Node count, for a cluster that does not scrape `kube_node_info`. |
| `--cluster-labels` | — | `k=v,k=v` selector labels, e.g. `env=prod,region=us-east-1`. Agent key scopes match on these. `sdlc` is reserved for `--cluster-sdlc` and wins over any entry of that name here. |
| `--enrollment-token-file` | — | File holding the enrollment token (reusable when minted by `hub enroll create`; see [spoke-enrollment.md](spoke-enrollment.md#tokens-are-reusable-by-default)). |
| `--identity-backend` | `auto` | `secret`, `file`, `memory`, or `auto`. |
| `--identity-secret-name` | `prometheus-mcp-fleet-identity` | Secret holding the issued key and certificate. |
| `--namespace` | projected | Namespace of the identity Secret. |
| `--data-dir` | `/var/lib/prometheus-mcp-fleet` | Holds the key, certificate and cached hub trust bundle for the `file` backend. |

`identity-backend: secret` needs a Role granting `get,create,update` on exactly
that one Secret by name — nothing cluster-scoped, nothing else in the namespace.

`identity-backend: memory` needs **no RBAC at all**, at the cost of re-enrolling
on every restart, which in turn requires a multi-use enrollment token. That is a
weaker posture; choose it deliberately.

### Prometheus

| Flag / `PMF_` variable | Default | Description |
|---|---|---|
| `--prometheus-url` | `http://prometheus-operated.monitoring.svc:9090` | The local Prometheus-compatible server. A path prefix such as `http://gateway/prom` is preserved. |
| `--prometheus-timeout` | `25s` | One upstream request. The spoke subtracts a 250 ms hop margin so it can return a structured error rather than a truncated stream. |
| `--prometheus-bearer-token-file` | — | Re-read on every request, because Kubernetes rotates projected tokens in place. |
| `--prometheus-tls-ca-file` | — | Trust bundle for an HTTPS Prometheus. |
| `--prometheus-tls-skip-verify` | `false` | Requires `--allow-insecure`. |
| `--prometheus-max-response-bytes` | `32Mi` | Maximum accepted from one response, enforced during the read. |
| `--facts-refresh-interval` | `10m` | How often cluster facts are recollected. `Describe` is always answered from cache and never triggers collection inline. |

### Observability and lifecycle

Same keys as the hub: `--admin-addr` (default `:9090`), `--log-level`,
`--log-format`, `--otel-exporter-otlp-endpoint`, `--trace-sample-ratio`,
`--pprof-enabled`, `--shutdown-drain-delay`, `--shutdown-grace`.

## Health endpoint semantics

Both binaries serve these on the admin listener.

`/healthz` — process liveness. Returns 200 once the server is up and **never
checks a dependency**. A dead Prometheus must not restart the pod.

`/readyz` — able to serve. The body is JSON listing what is blocking.

The hub is **not ready** when: the credential store is unopened or unwritable,
the CA key cannot be loaded, the CA certificate expires within 24 hours, the
pepper is unreadable, the tunnel listener is not bound, or a drain has started.
Spoke count is deliberately *not* an input — a hub with zero spokes is
legitimately ready.

The spoke is **not ready** when: no tunnel is attached to any endpoint, or the
local Prometheus probe has failed twice consecutively.

## Worked examples

**Hub, in Kubernetes, behind an Ingress:**

```yaml
env:
  - name: PMF_MCP_ADDR
    value: ":8080"
  - name: PMF_PUBLIC_URL
    value: "https://pmf.example.com/mcp"
  - name: PMF_TRUST_DOMAIN
    value: "fleet.example.com"
  - name: PMF_STATE_BACKEND
    value: "secret"
```

**Spoke, in a monitored cluster:**

```yaml
env:
  - name: PMF_CLUSTER_ID
    value: "prod-us-east-1"
  - name: PMF_CLUSTER_SDLC
    value: "prod"
  - name: PMF_CLUSTER_LABELS
    value: "env=prod,region=us-east-1,tier=customer-facing"
  - name: PMF_HUB_ENDPOINTS
    value: "wss://pmf.example.com/tunnel"
  - name: PMF_HUB_API_URL
    value: "https://pmf.example.com"
  - name: PMF_PROMETHEUS_URL
    value: "http://kube-prometheus-stack-prometheus.monitoring.svc:9090"
  - name: PMF_ENROLLMENT_TOKEN_FILE
    value: "/etc/pmf/enrollment/token"
```

**Both, locally, with no Kubernetes:** see
[development.md](development.md#running-it-locally-without-kubernetes).
