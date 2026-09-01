
# prometheus-mcp-spoke

![Version: 0.3.0](https://img.shields.io/badge/Version-0.3.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.8.1](https://img.shields.io/badge/AppVersion-0.8.1-informational?style=flat-square)

Tiny outbound-only agent that dials the prometheus-mcp-hub over an authenticated WebSocket and proxies this cluster's Prometheus HTTP API. One namespaced Role over one Secret, or no RBAC at all in memory identity mode.

The spoke is a tiny agent that runs in **one** Kubernetes cluster, dials **out** to a
`prometheus-mcp-hub` over ordinary HTTPS — a WebSocket on the hub's MCP listener at
`wss://<hub>/tunnel`, mutually authenticated inside the connection
([ADR-0014](../../docs/adr/0014-websocket-tunnel-through-standard-ingress.md)) — and serves
that cluster's Prometheus HTTP API back through the tunnel. It streams opaque bytes and never parses Prometheus JSON,
which is why it is this small and why it works unchanged against Thanos, Mimir and Cortex.

**The hub is in a different cluster.** Every spoke is its own Helm release in its own
cluster, and there are typically ~100 of them. Nothing in this chart references a hub
Service, hub RBAC or a hub release name, and nothing defaults to an in-cluster address: a
default that only works when the hub happens to be local is a trap that fails on the other
99 installs.

## TL;DR

```console
helm install spoke oci://ghcr.io/jacoknapp/prometheus-mcp-fleet/charts/prometheus-mcp-spoke \
  --namespace prometheus-mcp --create-namespace \
  --set cluster.id=prod-us-east-1 \
  --set hub.endpoints[0]=wss://mcp.example.com/tunnel \
  --set hub.apiUrl=https://mcp.example.com \
  --set enrollment.existingSecret=spoke-enrollment
```

## Required values

Four values have no usable default and the chart refuses to render without them. They are
also `required` in `values.schema.json`, so `helm install` fails before a single template
runs.

| Value | Why it cannot be defaulted |
|---|---|
| `cluster.id` | Immutable identity the hub binds into this spoke's certificate URI SAN. Two clusters sharing one would fight over a single certificate identity, each deregistering the other. |
| `hub.endpoints` | The hub is in another cluster. There is no `.svc` name to fall back to. A `wss://` URL: the hub's Ingress host plus the hub's `tunnel.path`, e.g. `wss://mcp.example.com/tunnel`. |
| `hub.apiUrl` | Same, for the enrollment listener. |
| `prometheus.url` | Defaulted to `prometheus-operated.monitoring.svc:9090`, but wrong for most clusters. |

`cluster.id` must match `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`; the hub validates it again
at enrollment.

## Identity, and the RBAC trade

The spoke's P-256 private key and its issued certificate have to survive a restart, or
every restart needs a fresh enrollment token. `identity.backend` decides where they live,
and this is the one real security decision in the chart.

| `identity.backend` | RBAC | Token projected | Survives restart | Enrollment token needed |
|---|---|---|---|---|
| `secret` (default) | one `Role` over one Secret | yes | yes | single-use |
| `memory` | **none at all** | no | no | **multi-use** |
| `file` | none | no | no (it is the `/tmp` `emptyDir`) | **multi-use** |

### `secret`

The spoke writes `<release>-identity` in its own namespace. That costs exactly this:

```yaml
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create"]                        # cannot be name-scoped
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["<release>-identity"]
  verbs: ["get", "update"]
```

Namespaced, one named Secret, **no `list` and no `watch`** — a token that can list Secrets
can read every Secret in the namespace. `create` is a separate rule because Kubernetes
cannot restrict `create` by `resourceNames`: at authorization time the object has no name,
and a rule that pairs them silently authorizes nothing. It permits creating a Secret, never
reading one.

This is a deliberate, reviewable change from the project's earlier "spoke ships with zero
RBAC" claim, and it is stated here rather than buried.

### `memory`

For operators whose policy forbids the spoke any RBAC. It renders **no Role, no
RoleBinding, and no projected service account token** — `automountServiceAccountToken` is
`false`.

Be clear about what it costs. The key exists only in the pod's memory, so every restart —
node drain, image update, OOM, eviction, a routine `helm upgrade` — throws it away and the
spoke re-enrols from scratch. A single-use enrollment token is then not enough: you must
issue a **multi-use** token, which is a standing credential that mints cluster identities
and lives in this cluster indefinitely.

Trading one namespaced Role over one named Secret for a permanent identity-minting
credential is, in most threat models, a **worse** posture, not a better one. `memory` is
supported because some policies leave no choice, not because it is safer.

## Exactly one replica

`replicaCount` must be `1`; the chart and the schema both refuse anything else, and the
Deployment uses `strategy: Recreate` rather than `RollingUpdate`.

A spoke's identity is one certificate bound to one cluster ID, held in one Secret. During a
rolling update the old and new pods would both hold it: they would renew over each other in
the Secret, and the hub — which keys a tunnel by the cluster ID in the certificate URI SAN —
would see each new tunnel deregister the other's. Two spokes sharing one cluster ID fight.
The brief gap `Recreate` costs is the correct trade; the hub reports this cluster
disconnected for a few seconds and agents get an explicit, retryable tool error.

Scale the hub, never the spoke.

## Networking

The spoke opens **nothing** inbound except its metrics port. It dials out to exactly four
places, and the rendered NetworkPolicy says so:

| Destination | Rule |
|---|---|
| DNS | `kube-system`, UDP+TCP 53 |
| The hub | `ipBlock` from `networkPolicy.egress.hub.cidrs`, on the ports parsed out of the `hub.endpoints` URLs — **443** for a `wss://` URL with no explicit port |
| Local Prometheus | `namespaceSelector` plus the port parsed out of `prometheus.url` |
| Kubernetes API | TCP 443 (only needed by `identity.backend: secret`) |

The hub rule is an `ipBlock` and never a `namespaceSelector`, because the hub is not in this
cluster and there is no namespace to select. Any `hub.endpoints` entry that is already an IP
literal is additionally pinned to an exact `/32` (or `/128`). A DNS name cannot be resolved
by a NetworkPolicy at all, so named hubs fall back to `networkPolicy.egress.hub.cidrs`,
which defaults to the honest `0.0.0.0/0` — **narrow it to your hub's real addresses.**

The port comes from the endpoint URL and is `443` by default, not `8443`. Since
[ADR-0014](../../docs/adr/0014-websocket-tunnel-through-standard-ingress.md) the tunnel is a
WebSocket on the hub's ordinary MCP listener behind a standard Ingress; there is no separate
tunnel listener to open a separate port for. `networkPolicy.egress.hub.ports` overrides the
derivation for the case where an egress gateway or a NAT moves the port.

The only Service this chart renders is a ClusterIP for metrics. `service.type` must stay
`ClusterIP` and an `Ingress` in `extraManifests` is rejected outright, because the spoke's
only listener is the admin port and publishing it would expose metrics and pprof.

## Enrollment and trust

`enrollment.existingSecret` is the right answer. `enrollment.token` is offered for a first
install and is worse: a Helm value lands in the release Secret and in `helm get values`.
The token buys exactly one certificate and the hub burns it atomically on redemption, so
the window is short — but it is not zero.

`hub.caBundle` (inline PEM, rendered into a ConfigMap because a CA certificate is public)
or `hub.existingCASecret` supplies the trust bundle for the **hub's server certificate** —
the one its Ingress terminates, on both `hub.endpoints` and `hub.apiUrl`. It is not
client-certificate material and has nothing to do with this spoke's own identity, which
comes from enrollment. If the hub's Ingress serves a publicly trusted certificate you do not
need either value; they exist for a private CA. Supply it **out of band**: the hub is in a
different cluster, so nothing here vouches for it on first enrollment. With neither set the
spoke accepts the bundle the hub returns at enrollment and caches it — trust on first use,
which is fine on a trusted path and not fine on the open internet.

`hub.tlsInsecure` and `prometheus.tls.skipVerify` each require `hub.allowInsecure` as well.
Two independent settings mean an insecure spoke cannot be reached by a single typo.

## Security context

Non-negotiable, and asserted by the unit tests:

```yaml
runAsNonRoot: true
runAsUser: 65532        # nullable for an OpenShift SCC
runAsGroup: 65532
fsGroup: 65532
seccompProfile: { type: RuntimeDefault }
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: [ALL] }
```

The only writable path is an `emptyDir` at `/tmp`. There is no PersistentVolumeClaim
anywhere in this chart. On OpenShift set the three numeric IDs to `null`; see
`ci/openshift-values.yaml`.

## Resources and probes

Requests `25m` / `64Mi`; the memory limit is `256Mi`. There is **no default CPU limit**:
CFS-throttling the process that holds this cluster's only tunnel to the hub turns a CPU
spike into a cluster that drops off the fleet. `GOMEMLIMIT` comes from the memory limit
through the downward API, so it tracks the cgroup and not node allocatable.

Startup and liveness probe `/healthz`; readiness probes `/readyz`; all three on the admin
port. **`/healthz` never checks a dependency.** An unreachable hub or a dead Prometheus
must not restart this pod — and in `identity.backend: memory` every restart burns another
enrollment. `/readyz` is 503 while no tunnel is attached or the local Prometheus has been
failing for more than two refresh intervals, which is exactly what `helm test` asserts.

## Metrics and alerts

`metrics.serviceMonitor.enabled` and `metrics.prometheusRule.enabled` render the Prometheus
Operator objects; both need the `monitoring.coreos.com/v1` CRDs.

Every metric name in the shipped expressions comes from `internal/obs/metrics.go`:
`promfleet_spoke_tunnel_up`, `promfleet_spoke_tunnel_reconnects_total`,
`promfleet_spoke_prom_requests_total`, `promfleet_spoke_prom_duration_seconds`,
`promfleet_spoke_prom_up`, `promfleet_spoke_facts_refresh_total`,
`promfleet_spoke_client_cert_expiry_seconds`, `promfleet_spoke_inflight_requests`.

`promfleet_spoke_client_cert_expiry_seconds` holds **seconds remaining**, not a unix
timestamp. Renewal happens automatically at half the certificate's life, so
`PrometheusMCPSpokeCertExpiringSoon` firing means renewal is failing, not that renewal is
due.

## When the spoke cannot reach the hub

This is the usual first-install failure, and it is almost always a network or DNS problem in
**your** cluster, on the outbound path. The hub never dials in, so there is nothing to fix on
its firewall.

1. **Pod Running but NotReady, log repeating a dial error.** That is correct: `/healthz`
   never checks a dependency, so an unreachable hub must not restart the pod.
2. **DNS.** Resolve the hub name from inside the cluster. The spoke image is distroless, so
   use a debug pod.
3. **Egress.** Confirm the hub's real address falls inside `networkPolicy.egress.hub.cidrs`
   and that the port derived from `hub.endpoints` — 443 for a plain `wss://` URL — is
   allowed. Check for *other* policies too: NetworkPolicies are additive for allow, and a
   default-deny egress policy elsewhere in the namespace still applies.
4. **Proxy / egress NAT.** The tunnel is an HTTP `Upgrade` to a WebSocket over ordinary
   HTTPS, so a forward proxy **can** carry it and `HTTPS_PROXY` **is** honoured. Two things
   to check: the proxy must pass the `Upgrade` through rather than stripping it, and it must
   not close the connection while idle. The tunnel pings every 10 seconds, so any idle
   timeout above ~30 seconds is fine.
5. **TLS.** `certificate signed by unknown authority` means the trust bundle for the hub's
   **server** certificate is wrong: set `hub.caBundle` or `hub.existingCASecret`.
   `certificate is valid for X, not Y` means the hub's Ingress certificate does not cover
   the host in your `hub.endpoints` — fixed on the hub's `ingress.host` /
   `certManager.serving.dnsNames`, not here.
6. **Wrong URL.** `hub.endpoints` must be the hub's Ingress host plus the hub's
   `tunnel.path`, e.g. `wss://mcp.example.com/tunnel`. A 404 on the upgrade means the hub's
   Ingress does not route that path.
7. **Enrollment 401/409.** A single-use token that was already redeemed returns a replay
   error; mint a fresh one. In `identity.backend: memory` every restart redeems again, which
   is why that mode needs a multi-use token.

`helm test <release>` runs all of this as an assertion: it fails unless `/readyz` returns
200 and `promfleet_spoke_tunnel_up` is 1 for at least one hub endpoint.

## Uninstalling

`helm uninstall` removes the Deployment and the RBAC, but **not** the identity Secret, which
the spoke created itself and Helm does not own. Delete it deliberately; the next install in
this cluster will then need a fresh enrollment token.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| jacoknapp | <jacoknapp@gmail.com> | <https://github.com/jacoknapp> |

## Source Code

* <https://github.com/jacoknapp/prometheus-mcp-fleet>

## Requirements

Kubernetes: `>=1.28.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | `spec.template.spec.affinity`. |
| cluster.description | string | `""` | `PMF_CLUSTER_DESCRIPTION`. One line describing what this cluster runs, to orient an agent. |
| cluster.displayName | string | `""` | `PMF_CLUSTER_DISPLAY_NAME`. Human-facing name an agent sees when choosing a cluster. |
| cluster.id | string | `""` | `PMF_CLUSTER_ID`. REQUIRED, and deliberately has NO DEFAULT. Immutable, must match `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`. This is the identity the hub binds into this spoke's certificate URI SAN. Two clusters that accidentally shared an ID would fight over one certificate identity at the hub and each would deregister the other, so there is nothing sensible to default it to. |
| cluster.k8sNodes | int | `0` | `PMF_CLUSTER_K8S_NODES`. Node count, for a cluster that does not scrape `kube_node_info`. |
| cluster.k8sUid | string | `""` | `PMF_CLUSTER_K8S_UID`. Kubernetes cluster UID, same reasoning as `k8sVersion`. |
| cluster.k8sVersion | string | `""` | `PMF_CLUSTER_K8S_VERSION`. Kubernetes version, for a cluster whose Prometheus does not publish `kubernetes_build_info`. The spoke has no Kubernetes API access by design, so without either source this fact is simply unavailable. Set, it wins over anything derived. |
| cluster.labels | list | `[]` | `PMF_CLUSTER_LABELS`. Operator-supplied selectors, rendered as `k=v,k=v`. A list, so entries stay ordered and readable in review and a GitOps overlay can append one without rewriting a map. Keys must be unique; the chart refuses duplicates rather than letting one silently win. `sdlc` is reserved — set `cluster.sdlc` instead, and it wins over any entry of that name here. These are what agent key scopes (`matchLabels`) and `fanout_query` select on, so they are worth deciding before onboarding the first cluster rather than the fiftieth. |
| cluster.sdlc | string | `""` | `PMF_CLUSTER_SDLC`. REQUIRED. Lifecycle stage: `dev`, `staging`, `prod`, or whatever taxonomy this fleet uses. Case and separators are normalised, so `PROD`, `Pre Prod` and `pre_prod` become `prod` and `pre-prod`; the result must be a lowercase slug. It is published as the reserved label `sdlc`, which is how agent key scopes (`matchLabels`) and `fanout_query` select on it. It is required because a cluster with no lifecycle label is one no scoped credential can reach and no fleet-wide query targets — a failure that is silent at install and mysterious at query time. |
| commonAnnotations | object | `{}` | Extra annotations added to every object this chart renders. |
| commonLabels | object | `{}` | Extra labels added to every object this chart renders. |
| config.dataDir | string | `"/tmp/prometheus-mcp-fleet"` | `PMF_DATA_DIR`. Scratch directory for the cached hub trust bundle, and for the client key when `identity.backend` is `file`. It is the `/tmp` emptyDir; the chart refuses to render a path outside `/tmp` unless you mount a writable volume there yourself. |
| config.factsRefreshInterval | string | `"10m"` | `PMF_FACTS_REFRESH_INTERVAL`. How often cluster facts are recollected and republished to the hub. |
| config.logFormat | string | `"json"` | `PMF_LOG_FORMAT`. One of `json`, `text`. |
| config.logLevel | string | `"info"` | `PMF_LOG_LEVEL`. One of `debug`, `info`, `warn`, `error`. |
| config.pprofEnabled | bool | `false` | `PMF_PPROF_ENABLED`. Exposes `/debug/pprof` on the admin listener. |
| config.reconnectMaxBackoff | string | `"30s"` | `PMF_RECONNECT_MAX_BACKOFF`. Maximum tunnel reconnect delay. Keep it well under a scrape interval so a hub restart is invisible. |
| config.reconnectMinBackoff | string | `"500ms"` | `PMF_RECONNECT_MIN_BACKOFF`. Initial tunnel reconnect delay. |
| config.shutdownDrainDelay | string | `"5s"` | `PMF_SHUTDOWN_DRAIN_DELAY`. Time `/readyz` reports 503 before the tunnels close. |
| config.shutdownGrace | string | `"30s"` | `PMF_SHUTDOWN_GRACE`. Budget for draining in-flight Prometheus requests. |
| containerSecurityContext.allowPrivilegeEscalation | bool | `false` | Disallow gaining more privileges than the parent process. |
| containerSecurityContext.capabilities | object | `{"drop":["ALL"]}` | Linux capabilities. |
| containerSecurityContext.readOnlyRootFilesystem | bool | `true` | Read-only root filesystem. The only writable path is the `/tmp` emptyDir. |
| dnsConfig | object | `{}` | `spec.template.spec.dnsConfig`. |
| dnsPolicy | string | `""` | `spec.template.spec.dnsPolicy`. Empty means the cluster default. |
| enrollment.existingSecret | string | `""` | Name of an existing Secret holding the enrollment token. Preferred over `enrollment.token`. The chart never creates it. |
| enrollment.mountPath | string | `"/etc/prometheus-mcp-fleet/enrollment"` | Where the enrollment Secret is mounted, from which `PMF_ENROLLMENT_TOKEN_FILE` is derived. |
| enrollment.secretKey | string | `"token"` | Key inside the enrollment Secret holding the token. |
| enrollment.token | string | `""` | A `pmf_enr_` enrollment token, rendered into a Secret by this chart. Convenient, but it puts the token into the Helm release values, which are stored in a Secret in this namespace and show up in `helm get values`. `enrollment.existingSecret` is better. Tokens are reusable unless minted with `--single-use`; a single-use token cannot survive being reconciled from git, cannot outlive a cluster rebuild, and cannot serve several pods that start together. |
| extraArgs | list | `[]` | Extra arguments appended to the spoke command line. Flags beat environment (`--foo-bar` == `PMF_FOO_BAR`). |
| extraContainers | list | `[]` | Extra containers (sidecars) for the spoke pod. |
| extraEnv | list | `[]` | Extra environment variables for the spoke container, in raw `EnvVar` form. The only supported way to set a `PMF_` key this chart does not model. |
| extraEnvFrom | list | `[]` | Extra `envFrom` sources for the spoke container. |
| extraManifests | list | `[]` | Extra manifests rendered verbatim. Each entry is a full object and is passed through `tpl`, so it may contain Helm templating. |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the spoke container. |
| extraVolumes | list | `[]` | Extra volumes for the spoke pod. |
| fullnameOverride | string | `""` | Override the fully qualified name of every object this chart renders. |
| goRuntime.memLimit | bool | `true` | Set `GOMEMLIMIT` from `resources.limits.memory`. Skipped when no memory limit is set, because there would be nothing but node allocatable to derive it from. |
| goRuntime.memLimitRatio | float | `0.9` | Fraction of the memory limit used for `GOMEMLIMIT`. 0.9 leaves headroom for non-Go allocations before the kernel OOM killer. Computed at render time into a literal byte count: a downward API `resourceFieldRef` can only divide, and Kubernetes accepts no divisor that expresses a ratio. |
| hostNetwork | bool | `false` | `spec.template.spec.hostNetwork`. |
| hub.allowInsecure | bool | `false` | `PMF_ALLOW_INSECURE`. The second key that must be turned for any insecure option to take effect. Two independent settings mean an insecure spoke cannot be reached by a single typo. |
| hub.apiUrl | string | `""` | `PMF_HUB_API_URL`. REQUIRED, no default. `https://host[:port]` base URL of the hub's enrollment listener, which the hub serves on its MCP port — the same listener and the same Ingress host as `hub.endpoints`, so in practice this is the `https://` form of it without the tunnel path. External, like `hub.endpoints`. |
| hub.caBundle | string | `""` | Trust bundle for the hub's SERVER certificate, rendered into a ConfigMap and mounted as `PMF_HUB_CA_FILE`. This is inline PEM. It verifies the certificate the hub's Ingress presents on `hub.endpoints` and `hub.apiUrl` — it is NOT client-certificate material and has nothing to do with the spoke's own identity, which comes from enrollment. If your hub's Ingress serves a publicly trusted certificate (Let's Encrypt, a corporate CA already in the image's trust store) you do not need this at all; it exists for a private CA. The spoke needs it OUT OF BAND on first enrollment, because the hub is in a different cluster and nothing here vouches for it yet. A CA certificate is public, so this is not secret material. Empty means SYSTEM ROOTS, which is correct for a publicly issued Ingress certificate. It does NOT fall back to the bundle the hub returns at enrollment: that is the internal CA which signs spoke IDENTITIES, and it can never have signed the certificate the Ingress presents, so trusting it would make every wss:// dial fail with an unknown authority. |
| hub.caMountPath | string | `"/etc/prometheus-mcp-fleet/hub-ca"` | Where the hub trust bundle is mounted. |
| hub.caSecretKey | string | `"ca.crt"` | Key inside `hub.existingCASecret` holding the PEM bundle. |
| hub.endpoints | list | `[]` | `PMF_HUB_ENDPOINTS`. REQUIRED, no default. Hub tunnel endpoints as `wss://` URLs, joined with commas — for example `wss://hub.example.com/tunnel`, which is the hub's Ingress host plus the hub's `tunnel.path`. Since ADR-0014 the tunnel is a WebSocket on the hub's ordinary MCP listener behind a standard Ingress, so this is a URL and the port is the ordinary HTTPS port unless you name another. A bare `host:port` is read by the binary as `wss://<host:port>/tunnel`, which for the old `:8443` default is simply the wrong port and never connects; the chart refuses it rather than let you find out in production. The spoke holds ONE TUNNEL PER ENDPOINT: that is how hub HA works, because a tunnel is pinned to one hub replica and there is no hub-to-hub forwarding. List every hub replica's external URL. |
| hub.existingCASecret | string | `""` | Name of an existing Secret holding the hub's SERVER trust bundle, used instead of `hub.caBundle`. Same thing, out of a Secret you already have. The chart never creates it. |
| hub.tlsInsecure | bool | `false` | `PMF_HUB_TLS_INSECURE`. Skips verification of the hub's server certificate — the one its Ingress terminates — which lets anything on the network impersonate the hub and collect this cluster's metrics. It does nothing unless `hub.allowInsecure` is also true, and the chart refuses to render that combination without it. |
| identity.backend | string | `"secret"` | `PMF_IDENTITY_BACKEND`. Where the issued client key and certificate live. `secret` (default) writes them to a Secret in this namespace, so a pod restart reuses the existing certificate. It costs exactly one `Role` with `get,create,update` on that one Secret by name — see the "RBAC" section of the README. It is also what lets several pods of this cluster share ONE certificate: they read the same Secret, and at renewal whichever pod goes first writes it back while the rest adopt it instead of minting competitors. `replicaCount > 1` therefore requires this backend. `memory` needs NO RBAC at all, but the key is lost on every restart, so the spoke re-enrolls each time and is limited to a single pod. `file` writes under `config.dataDir`, which is the `/tmp` emptyDir, so in a pod it behaves like `memory` while looking durable. It exists for running the binary outside Kubernetes. |
| identity.secretName | string | `""` | `PMF_IDENTITY_SECRET_NAME`. Name of the Secret the spoke owns. Empty means `<fullname>-identity`. This exact name is what the rendered Role restricts by `resourceNames`. |
| image.digest | string | `""` | Image digest (`sha256:...`). When set the image is pinned by digest and the tag is ignored. Recommended for production and set automatically by the release workflow. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.registry | string | `"ghcr.io"` | Image registry. |
| image.repository | string | `"jacoknapp/prometheus-mcp-fleet/spoke"` | Image repository, without the registry. |
| image.tag | string | `""` | Image tag. Empty means `.Chart.AppVersion`. Ignored when `image.digest` is set. |
| imagePullSecrets | list | `[]` | Image pull secrets for a private registry. |
| initContainers | list | `[]` | Init containers for the spoke pod. |
| livenessProbe.enabled | bool | `true` | Enable the liveness probe. It targets `/healthz`, which never checks a dependency — a dead Prometheus or an unreachable hub must NOT restart this pod, because a restart in `memory` identity mode burns another enrollment. |
| livenessProbe.failureThreshold | int | `6` | Failure threshold. |
| livenessProbe.initialDelaySeconds | int | `0` | Initial delay. |
| livenessProbe.periodSeconds | int | `10` | Probe period. |
| livenessProbe.successThreshold | int | `1` | Success threshold. |
| livenessProbe.timeoutSeconds | int | `3` | Probe timeout. |
| metrics.prometheusRule.additionalGroups | list | `[]` | Extra rule groups appended verbatim to `spec.groups`. |
| metrics.prometheusRule.additionalRuleLabels | object | `{}` | Extra labels added to every shipped alert. |
| metrics.prometheusRule.annotations | object | `{}` | Annotations for the PrometheusRule. |
| metrics.prometheusRule.enabled | bool | `false` | Render a Prometheus Operator `PrometheusRule`. Requires the `monitoring.coreos.com/v1` CRDs. |
| metrics.prometheusRule.labels | object | `{}` | Extra labels. Must match your Prometheus' `ruleSelector`. |
| metrics.prometheusRule.namespace | string | `""` | Namespace for the PrometheusRule. Empty means the release namespace. |
| metrics.prometheusRule.rules.certExpiringSoon | bool | `true` | `PrometheusMCPSpokeCertExpiringSoon` — `promfleet_spoke_client_cert_expiry_seconds` below `thresholds.certExpirySeconds`. Renewal happens at half life, so this firing means renewal is failing. |
| metrics.prometheusRule.rules.factsRefreshFailing | bool | `true` | `PrometheusMCPSpokeFactsRefreshFailing` — `promfleet_spoke_facts_refresh_total{result="error"}` rising, so the hub's view of this cluster is going stale. |
| metrics.prometheusRule.rules.partialCoverage | bool | `true` | `PrometheusMCPSpokePartialCoverage` — this spoke reaches only SOME hub replicas (`promfleet_spoke_tunnels_covered` < `promfleet_spoke_hub_replicas`). The cluster still looks connected while a share of tool calls fail as if it were down, so this is the hardest failure in the system to diagnose without an alert. Usually Ingress session affinity. |
| metrics.prometheusRule.rules.promErrorRatioHigh | bool | `true` | `PrometheusMCPSpokePromErrorRatioHigh` — 5xx ratio from the local Prometheus above `thresholds.promErrorRatio`. |
| metrics.prometheusRule.rules.prometheusDown | bool | `true` | `PrometheusMCPSpokePrometheusDown` — `promfleet_spoke_prom_up` is 0, so the local Prometheus is unreachable. |
| metrics.prometheusRule.rules.spokeDown | bool | `true` | `PrometheusMCPSpokeDown` — this spoke is not being scraped successfully. |
| metrics.prometheusRule.rules.tunnelDown | bool | `true` | `PrometheusMCPSpokeTunnelDown` — `promfleet_spoke_tunnel_up` is 0 for some hub endpoint, so this cluster is invisible to every agent. |
| metrics.prometheusRule.rules.tunnelFlapping | bool | `true` | `PrometheusMCPSpokeTunnelFlapping` — `promfleet_spoke_tunnel_reconnects_total` rising faster than `thresholds.reconnectsPerHour`. |
| metrics.prometheusRule.runbookUrlPrefix | string | `"https://github.com/jacoknapp/prometheus-mcp-fleet/blob/main/docs/operations/runbook.md#"` | Runbook URL prefix; the alert name is appended. |
| metrics.prometheusRule.selector | string | `""` | Label matcher appended to every shipped expression. Empty means `job="<chart name>"`, which is what a default ServiceMonitor produces. |
| metrics.prometheusRule.thresholds.certExpirySeconds | int | `259200` | Seconds of remaining client certificate validity below which `PrometheusMCPSpokeCertExpiringSoon` fires. 3 days against the hub's 14 day default TTL, which is well after the half-life renewal should have happened. |
| metrics.prometheusRule.thresholds.promErrorRatio | float | `0.1` | 5xx ratio from the local Prometheus above which `PrometheusMCPSpokePromErrorRatioHigh` fires. |
| metrics.prometheusRule.thresholds.reconnectsPerHour | int | `12` | Tunnel reconnects in one hour above which `PrometheusMCPSpokeTunnelFlapping` fires. |
| metrics.serviceMonitor.annotations | object | `{}` | Annotations for the ServiceMonitor. |
| metrics.serviceMonitor.enabled | bool | `false` | Render a Prometheus Operator `ServiceMonitor` for the metrics port. Requires the `monitoring.coreos.com/v1` CRDs and `service.enabled`. |
| metrics.serviceMonitor.honorLabels | bool | `false` | `honorLabels`. |
| metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels. Must match your Prometheus' `serviceMonitorSelector`. |
| metrics.serviceMonitor.metricRelabelings | list | `[]` | `metricRelabelings` applied after scraping. |
| metrics.serviceMonitor.namespace | string | `""` | Namespace for the ServiceMonitor. Empty means the release namespace. |
| metrics.serviceMonitor.path | string | `"/metrics"` | Metrics path on the admin listener. |
| metrics.serviceMonitor.relabelings | list | `[]` | `relabelings` applied before scraping. |
| metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout. |
| metrics.serviceMonitor.targetLabels | list | `[]` | Service labels copied onto scraped metrics. |
| nameOverride | string | `""` | Override the chart name used in resource names. |
| namespaceOverride | string | `""` | Render every object into this namespace instead of `.Release.Namespace`. |
| networkPolicy.egress.allowDNS | bool | `true` | Allow DNS egress to `kube-system`. |
| networkPolicy.egress.enabled | bool | `true` | Restrict spoke egress to DNS, the hub, Prometheus and the Kubernetes API. |
| networkPolicy.egress.extraRules | list | `[]` | Raw additional `egress` rules, appended verbatim. |
| networkPolicy.egress.hub.cidrs | list | `["0.0.0.0/0"]` | CIDRs the hub may be reached at. `0.0.0.0/0` is the honest default: the hub lives outside this cluster and a NetworkPolicy cannot resolve a DNS name. Narrow it to your hub's addresses. Any `hub.endpoints` entry that is already an IP literal is added as an exact `/32` (or `/128`) rule automatically and does not need to appear here. |
| networkPolicy.egress.hub.enabled | bool | `true` | Allow egress to the hub. Without this the tunnel never establishes. |
| networkPolicy.egress.hub.ports | list | `[]` | Ports the hub is reached on. Empty derives them from the `hub.endpoints` URLs, which is what you want: a `wss://` URL with no explicit port means 443, because the tunnel now arrives on the hub's ordinary HTTPS Ingress rather than a dedicated 8443 listener. Set this only when something between here and the hub — an egress gateway, a NAT — moves the port. |
| networkPolicy.egress.kubeAPI.enabled | bool | `true` | Allow egress to the Kubernetes API server. Required whenever `identity.backend` is `secret`; pointless otherwise. |
| networkPolicy.egress.kubeAPI.port | int | `443` | Port of the Kubernetes API server for the egress rule. |
| networkPolicy.egress.prometheus.enabled | bool | `true` | Allow egress to the local Prometheus, on the port parsed from `prometheus.url`. |
| networkPolicy.egress.prometheus.namespaceSelector | object | `{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}` | `namespaceSelector` for the namespace Prometheus runs in. |
| networkPolicy.egress.prometheus.podSelector | object | `{}` | `podSelector` for the Prometheus pods. Empty selects every pod in the selected namespaces. |
| networkPolicy.enabled | bool | `true` | Render a NetworkPolicy. On by default: the spoke's egress set is small, known and worth pinning down, because this pod holds a credential that can read the whole cluster's metrics. |
| networkPolicy.ingress.enabled | bool | `true` | Allow ingress to the metrics port. The spoke accepts nothing else — the tunnel is outbound. |
| networkPolicy.ingress.extraFrom | list | `[]` | Additional raw `ingress.from` entries for the metrics port. |
| networkPolicy.ingress.namespaceSelector | object | `{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}` | `namespaceSelector` for the only namespace allowed to scrape the metrics port. |
| networkPolicy.ingress.podSelector | object | `{}` | `podSelector` for scrapers allowed to reach the metrics port. Empty selects every pod in the selected namespaces. |
| networkPolicy.labels | object | `{}` | Extra labels for the NetworkPolicy. |
| nodeSelector | object | `{}` | `spec.template.spec.nodeSelector`. |
| podAnnotations | object | `{}` | Annotations for the spoke pods. |
| podDisruptionBudget.enabled | bool | `true` | Render a PodDisruptionBudget. Force-disabled below `replicaCount: 2`, where a budget can never be satisfied and would block every node drain forever. |
| podDisruptionBudget.maxUnavailable | string | `"50%"` | `spec.maxUnavailable`. A percentage rather than a count so it stays correct if you change `replicaCount`. |
| podDisruptionBudget.minAvailable | string | `""` | `spec.minAvailable`. Mutually exclusive with `maxUnavailable`, which is set below and wins. |
| podDisruptionBudget.unhealthyPodEvictionPolicy | string | `"AlwaysAllow"` | `spec.unhealthyPodEvictionPolicy` (Kubernetes >= 1.27). `AlwaysAllow` means a pod that is not Ready does not consume the budget, so a node carrying a crashlooping spoke can still be drained. |
| podLabels | object | `{}` | Extra labels for the spoke pods. |
| podSecurityContext.fsGroup | int | `65532` | Supplemental filesystem group. Set to `null` on OpenShift. |
| podSecurityContext.runAsGroup | int | `65532` | Pod GID. Set to `null` on OpenShift. |
| podSecurityContext.runAsNonRoot | bool | `true` | Refuse to start any container in the pod as UID 0. |
| podSecurityContext.runAsUser | int | `65532` | Pod UID. Set to `null` on OpenShift so the SCC can assign one from the namespace range. |
| podSecurityContext.seccompProfile | object | `{"type":"RuntimeDefault"}` | Seccomp profile for every container in the pod. |
| ports.admin | int | `9090` | Container port of the metrics, health and pprof listener (`PMF_ADMIN_ADDR`). The spoke has no other listener: it DIALS the hub, so nothing ever connects in except a scraper and the kubelet. |
| priorityClassName | string | `""` | `spec.template.spec.priorityClassName`. The spoke is this cluster's only path to the fleet, so a system-cluster-critical class is defensible. |
| prometheus.bearerToken.existingSecret | string | `""` | Name of an existing Secret holding a bearer token for an authenticating Prometheus. Empty leaves `PMF_PROMETHEUS_BEARER_TOKEN_FILE` unset. |
| prometheus.bearerToken.mountPath | string | `"/etc/prometheus-mcp-fleet/prometheus-auth"` | Where the bearer token Secret is mounted. |
| prometheus.bearerToken.secretKey | string | `"token"` | Key inside `prometheus.bearerToken.existingSecret`. |
| prometheus.maxResponseBytes | int | `33554432` | `PMF_PROMETHEUS_MAX_RESPONSE_BYTES`. Maximum bytes accepted from one Prometheus response. |
| prometheus.timeout | string | `"25s"` | `PMF_PROMETHEUS_TIMEOUT`. Deliberately below the hub's `queryTimeout` so the spoke fails first and returns a useful error instead of the hub timing out blind. |
| prometheus.tls.existingSecret | string | `""` | Name of an existing Secret or ConfigMap holding the trust bundle for an https Prometheus. Empty leaves `PMF_PROMETHEUS_TLS_CA_FILE` unset. |
| prometheus.tls.mountPath | string | `"/etc/prometheus-mcp-fleet/prometheus-ca"` | Where the Prometheus trust bundle is mounted. |
| prometheus.tls.secretKey | string | `"ca.crt"` | Key inside `prometheus.tls.existingSecret` holding the PEM bundle. |
| prometheus.tls.skipVerify | bool | `false` | `PMF_PROMETHEUS_TLS_SKIP_VERIFY`. Requires `hub.allowInsecure` as well; the chart refuses to render it otherwise. |
| prometheus.url | string | `"http://prometheus-operated.monitoring.svc:9090"` | `PMF_PROMETHEUS_URL`. REQUIRED. The local, IN-CLUSTER Prometheus-compatible server this spoke proxies. Thanos Query, Mimir and Cortex all work: the spoke never parses the response body. |
| rbac.create | bool | `true` | Render the namespaced Role and RoleBinding that let the spoke write its own identity Secret. Only rendered when `identity.backend` is `secret`; in `memory` and `file` mode the spoke gets no RBAC at all. |
| readinessProbe.enabled | bool | `true` | Enable the readiness probe. It targets `/readyz`, which is 503 while no tunnel is attached or the local Prometheus has been failing for more than two refresh intervals. |
| readinessProbe.failureThreshold | int | `3` | Failure threshold. |
| readinessProbe.initialDelaySeconds | int | `0` | Initial delay. |
| readinessProbe.periodSeconds | int | `10` | Probe period. |
| readinessProbe.successThreshold | int | `1` | Success threshold. |
| readinessProbe.timeoutSeconds | int | `3` | Probe timeout. |
| replicaCount | int | `3` | Number of spoke replicas. Three by default: every query a spoke serves is a read-only, idempotent Prometheus call, so sibling pods are interchangeable, the hub pools them, and losing one is invisible to an agent. There is deliberately no leader election — nothing needs serialising, and an election would add split-brain risk and failover latency for no gain.  The pods share one certificate through the identity Secret, so above 1 requires `identity.backend: secret` (the default) and the chart refuses anything else. |
| resources.limits.memory | string | `"256Mi"` | Memory limit. Also the source of `GOMEMLIMIT`. |
| resources.requests.cpu | string | `"25m"` | CPU request. The spoke streams opaque bytes and never parses Prometheus JSON, so it is genuinely this small. |
| resources.requests.memory | string | `"64Mi"` | Memory request. |
| restartOnConfigChange | bool | `true` | Roll the pod when the rendered ConfigMap changes, by stamping its checksum as a pod annotation. |
| revisionHistoryLimit | int | `5` | Number of old ReplicaSets retained. |
| service.annotations | object | `{}` | Annotations for the Service. |
| service.enabled | bool | `true` | Render a Service for the metrics port. This is the ONLY Service this chart renders: the spoke dials out and has nothing to publish. It is required for a ServiceMonitor. |
| service.labels | object | `{}` | Extra labels for the Service. |
| service.port | int | `9090` | Service port for metrics. |
| service.type | string | `"ClusterIP"` | Service type. `ClusterIP` is the only sensible value; the chart refuses anything else, because publishing the spoke's admin listener outside the cluster exposes pprof and metrics. |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount. |
| serviceAccount.automountServiceAccountToken | string | `""` | Mount the projected ServiceAccount token. Empty means "whatever `identity.backend` needs": true for `secret`, false for `memory` and `file`. Set it explicitly only to override that. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount for the spoke. |
| serviceAccount.name | string | `""` | Name of the ServiceAccount. Empty means the chart fullname. |
| startupProbe.enabled | bool | `true` | Enable the startup probe on `/healthz`. It is what lets the liveness probe stay aggressive while a first enrollment round-trips to the hub. |
| startupProbe.failureThreshold | int | `60` | Failure threshold. 60 x 5s = 5 minutes to enrol against a hub that may be cold. |
| startupProbe.initialDelaySeconds | int | `0` | Initial delay. |
| startupProbe.periodSeconds | int | `5` | Probe period. |
| startupProbe.successThreshold | int | `1` | Success threshold. |
| startupProbe.timeoutSeconds | int | `3` | Probe timeout. |
| terminationGracePeriodSeconds | int | `60` | `spec.template.spec.terminationGracePeriodSeconds`. Must exceed `config.shutdownDrainDelay` plus `config.shutdownGrace`. |
| tests.image.pullPolicy | string | `"IfNotPresent"` | Pull policy for the `helm test` image. |
| tests.image.registry | string | `"docker.io"` | Registry for the `helm test` image. |
| tests.image.repository | string | `"busybox"` | Repository for the `helm test` image. Needs `wget`. |
| tests.image.tag | string | `"1.37.0"` | Tag for the `helm test` image. |
| tmpDirSizeLimit | string | `"32Mi"` | `sizeLimit` of the `/tmp` emptyDir that makes `readOnlyRootFilesystem: true` workable. |
| tolerations | list | `[]` | `spec.template.spec.tolerations`. |
| topologySpreadConstraints | list | `[]` | `spec.template.spec.topologySpreadConstraints`. Never use `DoNotSchedule` in a default; it turns a scheduling hint into an outage on small clusters. |
| tracing.enabled | bool | `false` | Enable OTLP trace export. |
| tracing.endpoint | string | `""` | `PMF_OTEL_EXPORTER_OTLP_ENDPOINT`. OTLP/gRPC collector endpoint. |
| tracing.sampleRatio | string | `"0.05"` | `PMF_TRACE_SAMPLE_RATIO`. Head sampling ratio between 0 and 1, as a string so YAML never reformats it. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs)
