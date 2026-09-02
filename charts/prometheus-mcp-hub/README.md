
# prometheus-mcp-hub

![Version: 0.5.1](https://img.shields.io/badge/Version-0.5.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.10.1](https://img.shields.io/badge/AppVersion-0.10.1-informational?style=flat-square)

MCP server that gives AI agents Prometheus capability across a fleet of Kubernetes clusters, terminating WebSocket tunnels dialled out by prometheus-mcp-spoke through a standard Ingress.

The hub is the MCP (Model Context Protocol) server that gives AI agents Prometheus
capability across a fleet of Kubernetes clusters. Spokes in each cluster dial **out** to
it over ordinary HTTPS — a WebSocket on the hub's MCP listener, mutually authenticated
inside the connection ([ADR-0014](../../docs/adr/0014-websocket-tunnel-through-standard-ingress.md)).
The hub terminates those tunnels, routes agent tool calls to the right cluster, and
returns token-efficient results.

It is deployed **once**, in one cluster. The spoke chart
(`prometheus-mcp-spoke`) is deployed separately in each of the other clusters.

## TL;DR

```console
helm install hub oci://ghcr.io/jacoknapp/prometheus-mcp-fleet/charts/prometheus-mcp-hub \
  --namespace prometheus-mcp --create-namespace \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.host=mcp.example.com \
  --set ingress.tls.enabled=true \
  --set ingress.tls.secretName=mcp-tls
```

`config.publicURL` (`PMF_PUBLIC_URL`, the canonical `https://<host>/mcp`) is
derived from the Ingress host when it is left empty and the Ingress terminates
TLS, as above. Set it yourself when the published hostname is not
`ingress.host` or TLS ends somewhere the chart cannot see, and expect the
render to be refused when there is neither: the binary will not start without
one, and the chart will not invent a plaintext URL for it.

## There is no database and no PersistentVolumeClaim

Everything durable lives in two Kubernetes Secrets that the hub reads and writes itself
through the API server:

| Secret | Default name | Holds |
|---|---|---|
| state | `<release>-state` | HMAC pepper, issued agent/admin key records, enrollment burn state, revoked serials |
| CA | `<release>-ca` | The internal CA certificate and private key |

They are separate on purpose: different blast radii, so they can carry different RBAC and
be rotated independently. A Secret's `resourceVersion` also gives optimistic concurrency
for free, which is what makes single-use enrollment burn atomic across replicas.

The cluster registry is **not** persisted at all. It is self-registering: spokes reconnect
and re-publish their facts, so it is rebuilt within seconds of a restart. A cluster that
has never reconnected simply does not appear, which is the truth and better than a stale
entry an agent might query.

Consequently the hub is a plain **Deployment**, `config.dataDir` is an `emptyDir` under
`/tmp`, and there is no `persistence.*` section to configure. Setting
`state.backend: file` puts the whole credential store on that `emptyDir`, where it is lost
on the next restart and orphans every enrolled spoke — it is a development mode, and
`NOTES.txt` says so loudly at install time.

## RBAC

One namespaced `Role` and one `RoleBinding`. Nothing cluster-scoped is ever rendered.

```yaml
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create"]                       # cannot be name-scoped; see below
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["<release>-ca", "<release>-state"]
  verbs: ["get", "update"]
```

There is deliberately **no `list` and no `watch`**: a token that can list Secrets can read
every Secret in the namespace, which is the whole thing being avoided here.

`create` is split into its own rule because Kubernetes cannot restrict `create` by
`resourceNames` — at authorization time the object has no name yet, and a rule that pairs
them silently authorizes nothing. That verb grants "may create a Secret in this one
namespace", not "may read Secrets". Pre-create the two Secrets yourself and set
`rbac.allowCreate=false` to remove even that.

`serviceAccount.automountServiceAccountToken` must stay `true` while
`state.backend: secret`; the chart refuses to render otherwise.

## Exposure

**Two** container ports, and only one of them is ever published.

| Listener | Port | Carries | How it is published |
|---|---|---|---|
| MCP | 8080 | Agent MCP requests, spoke enrollment **and the spoke tunnel WebSocket** at `tunnel.path` | Standard `networking.k8s.io/v1` **Ingress** (`ingress.*`) |
| Admin / metrics / health / pprof | 9090 | Credential-issuing REST API, `/metrics`, probes, pprof | ClusterIP only. Never anything else. |

There is no tunnel port, no tunnel Service and no `tunnel.service.*` values. Since
[ADR-0014](../../docs/adr/0014-websocket-tunnel-through-standard-ingress.md) the tunnel is
a WebSocket on the MCP listener at `tunnel.path` (`/tunnel` by default), so one Ingress
rule and one certificate publish the whole product. Mutual authentication moved inside the
connection as a signed-nonce exchange over the spoke's certificate, which means the hub
presents no tunnel server certificate and asks for none at the TLS layer — the Ingress is
a plain proxy and verifies nothing on its own. A spoke's
`hub.endpoints` entry is therefore a URL: `wss://hub.example.com/tunnel`.

The Ingress **must** route `tunnel.path`. `ingress.path: /` (the default) covers it. If
you narrow `ingress.path` to something that does not — `/mcp`, say — the chart renders a
**second path entry** for `tunnel.path` on that host automatically, and `NOTES.txt` says
it did. This is not politeness: a hub whose Ingress misses `/tunnel` serves MCP perfectly,
passes every probe and accepts zero spokes.

### Idle timeouts

The tunnel is a long-lived upgraded connection through your Ingress controller, and
controllers close idle ones. The tunnel's HTTP/2 keepalive pings run every **10 seconds**,
comfortably inside ingress-nginx's 60-second `proxy-read-timeout` default, so **the
defaults are fine**. A controller tuned below that will disconnect every spoke in the
fleet on a timer while the hub keeps reporting healthy. Raise it through
`ingress.annotations`:

```yaml
ingress:
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
```

HAProxy uses `haproxy.org/timeout-tunnel`; Traefik uses the entrypoint's
`respondingTimeouts`. See `ci/ingress-values.yaml`.

An **ssl-passthrough Ingress still works** if you have it (for example
`nginx.ingress.kubernetes.io/ssl-passthrough: "true"`), and restores end-to-end TLS
between spoke and hub. It is deliberately not the default: it is an nginx annotation
rather than part of the Ingress API, several controllers do not implement it, and the
deployment constraint this chart is built for is standard Ingress only.

There is no Gateway API `HTTPRoute` and no OpenShift `Route` in this chart.

### The admin port never leaves the cluster

The admin listener carries the credential-issuing REST API, `/metrics`, health and
optionally pprof. Four render-time guards enforce that it stays inside:

* `service.type` must be `ClusterIP` while `service.admin.enabled` is true.
* `ingress.servicePortName` must be `mcp` — the only port that may ever be routed.
* `service.mcpPort` may not equal `ports.admin`.
* `ports.mcp` and `ports.admin` must differ.
* `tunnel.path` must start with `/` and may not be `/`, which would swallow the MCP
  endpoint it shares a listener with.

Each is a `fail` in `_helpers.tpl` with an explanation, not a silent default.

### NetworkPolicy

`networkPolicy.mcp` is the hub's whole inbound story, because spoke tunnels arrive on the
MCP port from the Ingress controller exactly as agent requests do. There is no tunnel rule
to open. It defaults to the Ingress controller's namespace rather than `allowAll`, which is
defence in depth — the hub authenticates every spoke itself, inside the connection — but it
is still right. If you narrow it further, narrow it to the **controller**; narrowing it to
the agents alone cuts off every spoke in the fleet.

## Certificates

`certManager.enabled` renders a cert-manager `Certificate` for the hub's **serving**
certificate against an issuer you already have, and wires `ingress.tls.secretName` to the
Secret cert-manager writes — so the name is stated once and the two cannot drift apart:

```yaml
ingress:
  enabled: true
  host: pmf.example.com
  tls:
    enabled: true
certManager:
  enabled: true
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
```

Every cert-manager resource is guarded by `.Capabilities.APIVersions.Has "cert-manager.io/v1"`,
so the chart still renders on a cluster without the CRDs. `certManager.enabled` on such a
cluster is a render-time `fail` with a named cause rather than a silent no-op that would
leave the Ingress with no certificate at all. When rendering offline, tell Helm the CRDs
exist: `helm template --api-versions cert-manager.io/v1`.

**cert-manager does not, and cannot, supply the hub's internal CA.** That CA signs spoke
identities, so the hub must hold its *private key* to sign an enrollment; it is generated
on first boot into the CA Secret the hub owns (`state.caSecretName`) and read back from
there. A cert-manager `Certificate` hands you a certificate, not a signing service, and
replacing the internal CA with one would break enrollment entirely.

**Spoke certificates do not come from cert-manager either.** They come from the hub's
enrollment API, because cert-manager in one of a hundred unrelated clusters has no access
to the hub's CA key — which is the entire reason the enrollment flow exists. Do not try to
wire it up.

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

The only writable path is an `emptyDir` at `/tmp`. On OpenShift set `runAsUser`,
`runAsGroup` and `fsGroup` to `null` so the SCC can assign IDs from the namespace range;
see `ci/openshift-values.yaml`.

## Resources and probes

Requests `250m` / `256Mi`; the memory limit is `1Gi`. There is **no default CPU limit**:
CFS-throttling a process that terminates ~100 long-lived spoke tunnels turns a CPU spike
into fleet-wide latency. `GOMEMLIMIT` is derived from the memory limit through the
downward API (at `goRuntime.memLimitRatio`, 0.9 by default), so it tracks the cgroup and
not node allocatable.

Startup and liveness probe `/healthz`; readiness probes `/readyz`; all three on the admin
port. **`/healthz` never checks a dependency** — a liveness probe that did would turn a
blinking upstream into a restart loop. `/readyz` is where dependency state belongs, and it
reports 503 during the shutdown drain so a load balancer notices before connections stop.

## PodDisruptionBudget

`podDisruptionBudget.enabled` is `true`, but **no PDB is rendered below two replicas**. A
`minAvailable: 1` PDB in front of a single replica can never be satisfied, so it blocks
every node drain in the cluster forever. The guard lives in `_helpers.tpl` and the unit
tests assert both halves: absent at `replicaCount: 1`, present at `replicaCount: 2`.

Before raising `replicaCount`, read this: a spoke tunnel is pinned to exactly one replica
and there is deliberately no hub-to-hub forwarding. Credential state is shared because it
is one Secret, but tunnels are not. Real HA needs every replica individually routable
from outside the cluster and every spoke configured with all N addresses.

## Metrics and alerts

`metrics.serviceMonitor.enabled` renders a `ServiceMonitor` against the admin port;
`metrics.prometheusRule.enabled` renders a `PrometheusRule`. Both need the
`monitoring.coreos.com/v1` CRDs.

Every metric name in the shipped expressions comes from `internal/obs/metrics.go`:
`promfleet_hub_spoke_connected`, `promfleet_hub_spokes_connected`,
`promfleet_hub_enrollments_total`, `promfleet_hub_proxy_requests_total`,
`promfleet_hub_proxy_duration_seconds`, `promfleet_hub_proxy_inflight`,
`promfleet_hub_proxy_response_bytes`, `promfleet_hub_mcp_tool_calls_total`,
`promfleet_hub_mcp_tool_duration_seconds`, `promfleet_hub_authn_failures_total`,
`promfleet_hub_spoke_cert_expiry_seconds`, `promfleet_hub_ca_cert_expiry_seconds`,
`promfleet_hub_store_op_duration_seconds`.

Both `*_cert_expiry_seconds` gauges hold **seconds remaining**, not a unix timestamp, so
the alerts compare them directly and never subtract `time()`.

Alerts shipped: `PrometheusMCPHubDown`, `PrometheusMCPSpokesDisconnected`,
`PrometheusMCPHubCACertExpiringSoon`, `PrometheusMCPHubSpokeCertExpiringSoon`,
`PrometheusMCPHubProxyErrorRatioHigh`, `PrometheusMCPHubRestartLoop` (needs
kube-state-metrics).

## Bootstrapping with your own CA

`bootstrap.existingSecret` adopts an operator-supplied HMAC pepper and/or CA keypair from a
Secret **this chart does not create**, so no key material ever passes through Helm values
or into the release Secret. See `ci/bootstrap-values.yaml`.

## Uninstalling

`helm uninstall` removes the Deployment and the RBAC, but **not** the state and CA Secrets,
which the hub created itself and Helm does not own. Delete them deliberately — and
understand that deleting the CA Secret orphans every enrolled spoke in every cluster, each
of which then needs a fresh enrollment token by hand.

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
| adminToken.existingSecret | string | `""` | Name of an existing Secret holding an admin token to mount read-only into the hub pod. Empty mounts nothing, and the administrative subcommands then need `PMF_ADMIN_TOKEN` or an explicit `--admin-token-file`. |
| adminToken.key | string | `"admin-token"` | Key inside `adminToken.existingSecret` holding the token. The default makes the mounted file `/var/run/pmf/admin-token`, which is the path the documentation passes to `--admin-token-file`. |
| adminToken.mountPath | string | `"/var/run/pmf"` | Directory the Secret is mounted at. The file is `<mountPath>/<key>`, which is what `--admin-token-file` should point at. |
| affinity | object | `{}` | `spec.template.spec.affinity`. |
| bootstrap.caCertKey | string | `""` | Key inside `bootstrap.existingSecret` holding the PEM CA certificate. Empty leaves `PMF_CA_CERT_FILE` unset. Must be set together with `bootstrap.caKeyKey`. |
| bootstrap.caKeyKey | string | `""` | Key inside `bootstrap.existingSecret` holding the PEM CA private key. Empty leaves `PMF_CA_KEY_FILE` unset. |
| bootstrap.existingSecret | string | `""` | Name of an existing Secret holding operator-supplied bootstrap material (HMAC pepper and/or CA keypair) to adopt instead of letting the hub self-generate. Mounted read-only; the chart never creates this Secret, so no key material is ever stored in Helm release values. |
| bootstrap.mountPath | string | `"/etc/prometheus-mcp-fleet/bootstrap"` | Where `bootstrap.existingSecret` is mounted. |
| bootstrap.pepperKey | string | `""` | Key inside `bootstrap.existingSecret` holding the HMAC pepper. Empty leaves `PMF_PEPPER_FILE` unset. |
| certManager.enabled | bool | `false` | Render cert-manager resources. Requires the `cert-manager.io/v1` CRDs. |
| certManager.issuerRef.group | string | `"cert-manager.io"` | API group of the issuer. |
| certManager.issuerRef.kind | string | `"ClusterIssuer"` | `Issuer` or `ClusterIssuer`. |
| certManager.issuerRef.name | string | `""` | Name of the existing Issuer or ClusterIssuer that signs the hub's serving certificate. Required when `certManager.enabled`. |
| certManager.serving.dnsNames | list | `[]` | DNS names on the certificate. Empty means `ingress.host` plus every `ingress.extraHosts` entry. |
| certManager.serving.duration | string | `""` | `spec.duration`. Empty leaves the issuer's default. |
| certManager.serving.enabled | bool | `true` | Render a `Certificate` for the hub's serving certificate and wire `ingress.tls.secretName` to it. |
| certManager.serving.privateKey | object | `{"algorithm":"ECDSA","rotationPolicy":"Always","size":256}` | `spec.privateKey`. `rotationPolicy: Always` means a renewal issues a fresh key rather than re-signing the old one. |
| certManager.serving.renewBefore | string | `""` | `spec.renewBefore`. Empty leaves the issuer's default. |
| certManager.serving.secretAnnotations | object | `{}` | `spec.secretTemplate.annotations` on the generated Secret. |
| certManager.serving.secretName | string | `""` | Secret cert-manager writes the serving certificate to. Empty means `<fullname>-serving-tls`. |
| commonAnnotations | object | `{}` | Extra annotations added to every object this chart renders. |
| commonLabels | object | `{}` | Extra labels added to every object this chart renders. |
| config.adminKeyTTL | string | `"2160h"` | `PMF_ADMIN_KEY_TTL`. Default and maximum lifetime of a minted `pmf_adm_` admin key, including the bootstrap key printed on first start. A separate knob from agentKeyTTL on purpose: relaxing agent expiry must not silently relax the credential that mints credentials. |
| config.agentKeyTTL | string | `"2160h"` | `PMF_AGENT_KEY_TTL`. Default lifetime of a minted `pmf_agt_` agent key, and the maximum a create request may ask for. Nothing rotates agent keys automatically (the holder is an AI agent's configuration, not a process that can re-enrol itself), so expiry is an outage on a timer. A key may be minted with no expiry at all via the no-expiry flag of `hub keys create`; revocation is then how it is withdrawn. |
| config.caRotateAtRemainingFraction | float | `0.2` | `PMF_CA_ROTATE_AT_REMAINING_FRACTION`. How much of the signing root's life must be left before a rotation starts: `0.2` begins in its last fifth. A root lives ten years and a rotation takes about two months at the default certificate TTL and renewal grace, so the default leaves two years of runway for a job needing one thirtieth of it. There is a floor underneath this that no value can lower — `2 × spokeCertTTL + renewGrace`, the time a rotation cannot finish in less than — so setting this small does not let the hub start a rotation it could not complete before the signer expires. |
| config.caRotationEnabled | bool | `true` | `PMF_CA_ROTATION_ENABLED`. Let the hub rotate its own signing root instead of an operator running a runbook. It mints a successor, publishes it to the trust bundle, promotes it to signer and retires the outgoing root, each step gated on evidence and coordinated between replicas by a compare-and-swap on the CA Secret. It needs `state.backend: secret` and the CA the hub generates for itself; a CA you supply through `bootstrap.existingSecret` is yours to rotate, and the hub says so in its log and declines. See `docs/adr/0015-ca-rotation.md`. |
| config.caRotationPollInterval | string | `"5m"` | `PMF_CA_ROTATION_POLL_INTERVAL`. How often each replica re-reads the CA Secret to notice a rotation, its own or another replica's. There is no PVC and no channel between replicas, so this poll is the only way one learns what another did. It costs one GET per replica per interval and correctness does not depend on it being short: a replica lagging a poll behind is still trusting every root the fleet trusts. |
| config.dataDir | string | `"/tmp/prometheus-mcp-fleet"` | `PMF_DATA_DIR`. Scratch directory for the self-generated HMAC pepper and the CA material materialised out of the CA Secret. NOTHING here is durable — it is the `/tmp` emptyDir. It must stay under `/tmp` unless you mount a writable volume elsewhere with `extraVolumes`/`extraVolumeMounts`; the chart refuses to render otherwise. |
| config.enableStatusConfig | bool | `false` | `PMF_ENABLE_STATUS_CONFIG`. Ungates the `/api/v1/status/config` Prometheus endpoint. Off by default because scrape configurations routinely embed bearer tokens and basic-auth passwords in plain text, and this hub hands its output to an AI agent. |
| config.enrollmentTokenTTL | string | `"15m"` | `PMF_ENROLLMENT_TOKEN_TTL`. Lifetime of a `pmf_enr_` token. The 15 minute default suits an imperative install where a human mints a token and uses it immediately. A GitOps rollout wants a reusable token with a much longer TTL, because the credential is reconciled from git rather than handed over once. |
| config.factsPollInterval | string | `"60s"` | `PMF_FACTS_POLL_INTERVAL`. How often the hub refreshes cluster facts. |
| config.logFormat | string | `"json"` | `PMF_LOG_FORMAT`. One of `json`, `text`. |
| config.logLevel | string | `"info"` | `PMF_LOG_LEVEL`. One of `debug`, `info`, `warn`, `error`. |
| config.maxInflightPerCluster | int | `8` | `PMF_MAX_INFLIGHT_PER_CLUSTER`. Per-cluster in-flight request semaphore. |
| config.maxResponseBudgetBytes | int | `268435456` | `PMF_MAX_RESPONSE_BUDGET_BYTES`. Process-wide in-flight response byte budget. |
| config.maxResponseBytes | int | `33554432` | `PMF_MAX_RESPONSE_BYTES`. Maximum bytes accepted from one upstream response. |
| config.maxSpokes | int | `0` | `PMF_MAX_SPOKES`. Optional cap on concurrent spoke sessions on one hub replica. `0`, the default, means no limit. A cap here refuses spokes rather than shedding load: it is applied before the WebSocket upgrade, so an over-limit spoke gets a 503 and its cluster silently never joins, which looks like a missing cluster rather than a limit being hit. It also counts sessions and not clusters — a cluster running several spoke pods holds one per pod — so any number picked for a cluster count is wrong by that multiple. Set it only as a deliberate resource guard. |
| config.pprofEnabled | bool | `false` | `PMF_PPROF_ENABLED`. Exposes `/debug/pprof` on the admin listener. |
| config.publicURL | string | `""` | `PMF_PUBLIC_URL`. Canonical external MCP URL, `https://<host>/mcp`, published as the `resource` of the OAuth protected-resource-metadata document the 401 challenge points at. The binary refuses to start without one. Empty derives `https://<ingress.host>/mcp` when `ingress.enabled` and `ingress.tls.enabled` are both true; otherwise the chart refuses to render rather than ship a Deployment that CrashLoops on startup validation, or a plaintext URL that enrollment tokens would then be sent over. Set it explicitly when the published hostname differs from `ingress.host` (a load balancer or gateway in front), or when TLS really is terminated somewhere the chart cannot see. |
| config.queryTimeout | string | `"30s"` | `PMF_QUERY_TIMEOUT`. Deadline for a call that states none (metadata and selector lookups). Instant queries default to 30s and range queries to 60s at the tool layer. |
| config.rangeQueryTimeout | string | `"120s"` | `PMF_RANGE_QUERY_TIMEOUT`. Ceiling every per-call deadline is clamped to. The tool layer caps callers at 120s, so a larger value changes nothing; a smaller one tightens every tool. |
| config.renewGrace | string | `"720h"` | `PMF_RENEW_GRACE`. How long after a spoke certificate expires the hub will still renew it, given proof the spoke still holds the private key. A spoke renews at half its certificate's life, so an expired certificate means the cluster was unreachable for half a lifetime; without this it is locked out permanently, because `/renew` refuses the expired certificate and its enrollment token was burned at install. Nothing else is relaxed: the chain must still verify, the certificate must not be revoked, and the possession proof must still pass. Set to `0` to require an unexpired certificate. |
| config.shutdownDrainDelay | string | `"5s"` | `PMF_SHUTDOWN_DRAIN_DELAY`. Time `/readyz` reports 503 before work stops, so load balancers notice. |
| config.shutdownGrace | string | `"30s"` | `PMF_SHUTDOWN_GRACE`. Graceful shutdown budget for in-flight work. |
| config.spokeCertTTL | string | `"336h"` | `PMF_SPOKE_CERT_TTL`. Lifetime of an issued spoke client certificate. |
| config.statePruneInterval | string | `"6h"` | `PMF_STATE_PRUNE_INTERVAL`. How often each replica prunes the state document. Zero disables pruning, which leaves the Secret growing toward its 700 KiB write ceiling with only `PrometheusMCPHubStateSecretLarge` to catch it. |
| config.stateRetention | string | `"720h"` | `PMF_STATE_RETENTION`. How long expired credentials and lapsed certificate revocations are kept before the hub prunes them. A forensics window, not a safety margin: nothing pruned can change an answer, so the only reason to keep it is that an operator investigating last week wants last week's records. |
| config.trustDomain | string | `"fleet.local"` | `PMF_TRUST_DOMAIN`. Appears in every spoke certificate URI SAN `pmf://<trust-domain>/spoke/<cluster-id>`. Changing it invalidates every issued spoke certificate. |
| containerSecurityContext.allowPrivilegeEscalation | bool | `false` | Disallow gaining more privileges than the parent process. |
| containerSecurityContext.capabilities | object | `{"drop":["ALL"]}` | Linux capabilities. |
| containerSecurityContext.readOnlyRootFilesystem | bool | `true` | Read-only root filesystem. The only writable path is the `/tmp` emptyDir. |
| dnsConfig | object | `{}` | `spec.template.spec.dnsConfig`. |
| dnsPolicy | string | `""` | `spec.template.spec.dnsPolicy`. Empty means the cluster default. |
| extraArgs | list | `[]` | Extra arguments appended to the hub command line. Flags beat environment (`--foo-bar` == `PMF_FOO_BAR`). |
| extraContainers | list | `[]` | Extra containers (sidecars) for the hub pod. |
| extraEnv | list | `[]` | Extra environment variables for the hub container, in raw `EnvVar` form. The only supported way to set a `PMF_` key this chart does not model. |
| extraEnvFrom | list | `[]` | Extra `envFrom` sources for the hub container. |
| extraManifests | list | `[]` | Extra manifests rendered verbatim. Each entry is a full object and is passed through `tpl`, so it may contain Helm templating. |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the hub container. |
| extraVolumes | list | `[]` | Extra volumes for the hub pod. |
| fullnameOverride | string | `""` | Override the fully qualified name of every object this chart renders. |
| goRuntime.memLimit | bool | `true` | Set `GOMEMLIMIT` from `resources.limits.memory`. Skipped when no memory limit is set, because there would be nothing but node allocatable to derive it from. |
| goRuntime.memLimitRatio | float | `0.9` | Fraction of the memory limit used for `GOMEMLIMIT`. 0.9 leaves headroom for non-Go allocations before the kernel OOM killer. Computed at render time into a literal byte count: a downward API `resourceFieldRef` can only divide, and Kubernetes accepts no divisor that expresses a ratio. |
| hostNetwork | bool | `false` | `spec.template.spec.hostNetwork`. |
| image.digest | string | `""` | Image digest (`sha256:...`). When set the image is pinned by digest and the tag is ignored. Recommended for production and set automatically by the release workflow. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.registry | string | `"ghcr.io"` | Image registry. |
| image.repository | string | `"jacoknapp/prometheus-mcp-fleet/hub"` | Image repository, without the registry. |
| image.tag | string | `""` | Image tag. Empty means `.Chart.AppVersion`. Ignored when `image.digest` is set. |
| imagePullSecrets | list | `[]` | Image pull secrets for a private registry. |
| ingress.annotations | object | `{}` | Annotations for the Ingress. IDLE TIMEOUTS: an Ingress controller closes an idle upgraded connection, and the tunnel is a long-lived WebSocket. nginx defaults to 60s while the tunnel's HTTP/2 keepalive pings run every 10s, so the defaults are fine — but a controller tuned BELOW ~30s disconnects every spoke in the fleet, repeatedly, and the hub still looks healthy. Raise it there:   nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"   nginx.ingress.kubernetes.io/proxy-send-timeout: "3600" (HAProxy: `haproxy.org/timeout-tunnel`. Traefik: the entrypoint's respondingTimeouts.) |
| ingress.className | string | `""` | `spec.ingressClassName`. |
| ingress.enabled | bool | `false` | Render a standard `networking.k8s.io/v1` Ingress for the MCP port. This carries EVERYTHING: the agent-facing MCP endpoint and the spoke tunnel WebSocket at `tunnel.path` share the one listener, so one rule and one certificate publish the whole product. There is no second Service, no LoadBalancer and no `ssl-passthrough` to arrange. The controller only has to proxy `Connection: Upgrade`, which every Ingress controller does natively. |
| ingress.extraHosts | list | `[]` | Additional hosts, each an object with `host`, and optionally `path` and `pathType`. Each one gets the same tunnel-path treatment as `ingress.host`. |
| ingress.host | string | `""` | Hostname. Required when `ingress.enabled` is true. |
| ingress.path | string | `"/"` | Path exposed. `/` publishes both the MCP endpoint and the tunnel at `tunnel.path`. A narrower path that does not cover `tunnel.path` gets a SECOND path entry rendered for the tunnel automatically — an Ingress that does not route `tunnel.path` accepts zero spokes while looking perfectly healthy. |
| ingress.pathType | string | `"Prefix"` | `pathType`. |
| ingress.servicePortName | string | `"mcp"` | Name of the Service port to route to. Must be `mcp`; the chart refuses to route the admin port through an Ingress. |
| ingress.tls.enabled | bool | `false` | Terminate TLS at the Ingress. Spokes dial `wss://`, so in practice this is on. |
| ingress.tls.hosts | list | `[]` | Override the hosts listed in the TLS block. Empty means `ingress.host` plus every `ingress.extraHosts` entry. |
| ingress.tls.secretName | string | `""` | Secret holding the serving certificate. Empty with `enabled: true` means the controller's default certificate — unless `certManager.enabled` is true, in which case this is wired automatically to the Secret cert-manager writes. |
| initContainers | list | `[]` | Init containers for the hub pod. |
| livenessProbe.enabled | bool | `true` | Enable the liveness probe. It targets `/healthz`, which never checks a dependency — a dead upstream must not restart the hub. |
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
| metrics.prometheusRule.rules.caCertExpiringSoon | bool | `true` | `PrometheusMCPHubCACertExpiringSoon` — `promfleet_hub_ca_cert_expiry_seconds` below `thresholds.caCertExpirySeconds`. |
| metrics.prometheusRule.rules.caRotationStalled | bool | `true` | `PrometheusMCPHubCARotationStalled` — a self-service CA rotation has been in `publishing` or `signing` for longer than `thresholds.caRotationStalledSeconds`. The rotation is deliberately slow, so this fires only when it has stopped making progress; both roots stay trusted meanwhile, so it is a warning, not an outage. |
| metrics.prometheusRule.rules.hubDown | bool | `true` | `PrometheusMCPHubDown` — no hub instance is being scraped successfully. |
| metrics.prometheusRule.rules.peerDiscoveryBroken | bool | `true` | `PrometheusMCPHubPeerDiscoveryBroken` — peer discovery resolves fewer replicas than are deployed. Spokes then never learn the true count, hold too few tunnels, and their own partial-coverage alert cannot fire because they have no count to fall short of. |
| metrics.prometheusRule.rules.proxyErrorRatioHigh | bool | `true` | `PrometheusMCPHubProxyErrorRatioHigh` — 5xx ratio of proxied Prometheus requests above `thresholds.proxyErrorRatio`. |
| metrics.prometheusRule.rules.restartLoop | bool | `true` | `PrometheusMCPHubRestartLoop` — container restarts above `thresholds.restartsPerHour`. Requires kube-state-metrics. |
| metrics.prometheusRule.rules.revocationStale | bool | `true` | `PrometheusMCPHubRevocationStale` — no successful revoked-serial cache refresh for `thresholds.revocationStaleSeconds`. While this fires, a revocation committed elsewhere is NOT being enforced by the affected replica. |
| metrics.prometheusRule.rules.spokeCertExpiringSoon | bool | `true` | `PrometheusMCPHubSpokeCertExpiringSoon` — `promfleet_hub_spoke_cert_expiry_seconds` below `thresholds.spokeCertExpirySeconds` for some cluster. |
| metrics.prometheusRule.rules.spokesDisconnected | bool | `true` | `PrometheusMCPSpokesDisconnected` — more than `thresholds.spokesDisconnectedRatio` of enrolled spokes have no tunnel. |
| metrics.prometheusRule.rules.stateSecretLarge | bool | `true` | `PrometheusMCPHubStateSecretLarge` — `promfleet_hub_state_bytes` above `thresholds.stateBytes`. The hub refuses writes at 700 KiB, so this fires while there is still room to prune. |
| metrics.prometheusRule.runbookUrlPrefix | string | `"https://github.com/jacoknapp/prometheus-mcp-fleet/blob/main/docs/operations/runbook.md#"` | Runbook URL prefix; the alert name is appended. |
| metrics.prometheusRule.selector | string | `""` | Label matcher appended to every shipped expression. Empty means `job="<fullname>"`, which is what a default ServiceMonitor produces. |
| metrics.prometheusRule.thresholds.caCertExpirySeconds | int | `1209600` | Seconds of remaining CA certificate validity below which `PrometheusMCPHubCACertExpiringSoon` fires. 14 days. `promfleet_hub_ca_cert_expiry_seconds` is seconds REMAINING, not a unix timestamp. |
| metrics.prometheusRule.thresholds.caRotationStalledSeconds | int | `6480000` | Seconds a CA rotation phase may last before `PrometheusMCPHubCARotationStalled` fires. 75 days against the default `2 × spokeCertTTL + renewGrace` of 58 days, so a healthy rotation never trips it. Raise it if you lengthen `config.spokeCertTTL` or `config.renewGrace`. |
| metrics.prometheusRule.thresholds.proxyErrorRatio | float | `0.1` | 5xx ratio of proxied requests above which `PrometheusMCPHubProxyErrorRatioHigh` fires. |
| metrics.prometheusRule.thresholds.restartsPerHour | int | `3` | Container restarts in one hour above which `PrometheusMCPHubRestartLoop` fires. |
| metrics.prometheusRule.thresholds.revocationStaleSeconds | int | `300` | Seconds since the last successful revoked-serial refresh above which `PrometheusMCPHubRevocationStale` fires. Refreshes normally land at least every 30s (the cache TTL), so 300 is ten missed refreshes. |
| metrics.prometheusRule.thresholds.spokeCertExpirySeconds | int | `259200` | Seconds of remaining spoke certificate validity below which `PrometheusMCPSpokeCertExpiringSoon` fires. 3 days against a 14 day certificate TTL. |
| metrics.prometheusRule.thresholds.spokesDisconnectedRatio | float | `0.1` | Fraction of enrolled spokes that may be disconnected before `PrometheusMCPSpokesDisconnected` fires. |
| metrics.prometheusRule.thresholds.stateBytes | int | `512000` | Encoded state document size in bytes above which `PrometheusMCPHubStateSecretLarge` fires. 500 KiB against the hub's hard 700 KiB write ceiling, so the alert leads the failure by a wide margin. |
| metrics.serviceMonitor.annotations | object | `{}` | Annotations for the ServiceMonitor. |
| metrics.serviceMonitor.enabled | bool | `false` | Render a Prometheus Operator `ServiceMonitor` for the admin/metrics port. Requires the `monitoring.coreos.com/v1` CRDs. |
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
| networkPolicy.admin.extraFrom | list | `[]` | Additional raw `ingress.from` entries for the admin port. |
| networkPolicy.admin.namespaceSelector | object | `{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}` | `namespaceSelector` for the only namespace allowed to reach the admin/metrics port. |
| networkPolicy.admin.podSelector | object | `{}` | `podSelector` for scrapers allowed to reach the admin/metrics port. |
| networkPolicy.egress.allowDNS | bool | `true` | Allow DNS egress to `kube-system`. |
| networkPolicy.egress.allowKubeAPI | bool | `true` | Allow egress to the Kubernetes API server. Required whenever `state.backend` is `secret`. |
| networkPolicy.egress.enabled | bool | `true` | Restrict hub egress. On by default now that the hub talks to a known, small set: DNS, the Kubernetes API for its state Secret, and optionally an OTLP collector. |
| networkPolicy.egress.extraRules | list | `[]` | Raw additional `egress` rules, appended verbatim. |
| networkPolicy.egress.kubeAPIPort | string | `nil` | Deprecated, superseded by `kubeAPIPorts`. A single extra port to allow, appended to the list when set. |
| networkPolicy.egress.kubeAPIPorts | list | `[443,6443]` | Ports of the Kubernetes API server for the egress rule. Both defaults matter: the pod dials `kubernetes.default.svc:443`, but most CNIs evaluate egress policy AFTER kube-proxy has DNATed that to the real API server endpoint, which kubeadm, k3s, RKE2 and most managed control planes serve on 6443. A rule for 443 alone then drops every state Secret read and the hub cannot start. Trim to the one your cluster uses if you know it. |
| networkPolicy.enabled | bool | `true` | Render a NetworkPolicy. On by default: the hub terminates connections from outside the cluster and holds a CA. |
| networkPolicy.labels | object | `{}` | Extra labels for the NetworkPolicy. |
| networkPolicy.mcp.allowAll | bool | `false` | Allow ingress to the MCP port from any source. Use when your Ingress controller's identity cannot be expressed as a selector. Leave it false. This one rule is the hub's whole inbound story: SPOKE TUNNELS arrive here too, on the same port, from the same Ingress controller, so there is no separate tunnel rule to open. Restricting the port to the controller is defence in depth — the hub authenticates every spoke itself, inside the connection — but it is still right, and if you narrow it, narrow it to the CONTROLLER and never to the agents alone or you cut off every spoke in the fleet. |
| networkPolicy.mcp.extraFrom | list | `[]` | Additional raw `ingress.from` entries for the MCP port. |
| networkPolicy.mcp.namespaceSelector | object | `{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}}` | `namespaceSelector` for clients allowed to reach the MCP port. |
| networkPolicy.mcp.podSelector | object | `{}` | `podSelector` for clients allowed to reach the MCP port. Empty selects every pod in the selected namespaces. |
| nodeSelector | object | `{}` | `spec.template.spec.nodeSelector`. |
| peerDiscovery.domain | string | `""` | `PMF_PEER_DISCOVERY_DOMAIN`. Empty derives `<fullname>-peers.<namespace>.svc` from the headless Service above. Set it only to point at a Service this chart does not render. |
| peerDiscovery.enabled | bool | `true` | Render the headless Service the hub resolves to count its replicas. Leave on for `replicaCount > 1`; harmless at 1. |
| podAnnotations | object | `{}` | Annotations for the hub pods. |
| podDisruptionBudget.enabled | bool | `true` | Render a PodDisruptionBudget. It is force-disabled whenever `replicaCount < 2`: a budget on a single-replica workload blocks every node drain forever. |
| podDisruptionBudget.maxUnavailable | string | `"50%"` | `spec.maxUnavailable`. `50%` keeps at least half the replicas serving during a voluntary disruption: at 3 replicas one node may drain at a time. A percentage rather than a count so it stays correct if you change `replicaCount`. |
| podDisruptionBudget.minAvailable | string | `""` | `spec.minAvailable`. Mutually exclusive with `maxUnavailable`, which is set below and wins. |
| podDisruptionBudget.unhealthyPodEvictionPolicy | string | `"AlwaysAllow"` | `spec.unhealthyPodEvictionPolicy` (Kubernetes >= 1.27). `AlwaysAllow` means a pod that is not Ready — crashlooping, stuck pulling, wedged — does NOT consume the budget and can always be evicted. The default, `IfHealthyBudget`, does the opposite: broken pods are protected, so a node with a crashlooping hub on it cannot be drained until someone fixes the pod. That is the wrong way round for a workload whose whole point is to be replaceable. |
| podLabels | object | `{}` | Extra labels for the hub pods. |
| podSecurityContext.fsGroup | int | `65532` | Supplemental filesystem group. Set to `null` on OpenShift. |
| podSecurityContext.runAsGroup | int | `65532` | Pod GID. Set to `null` on OpenShift. |
| podSecurityContext.runAsNonRoot | bool | `true` | Refuse to start any container in the pod as UID 0. |
| podSecurityContext.runAsUser | int | `65532` | Pod UID. Set to `null` on OpenShift so the SCC can assign one from the namespace range. |
| podSecurityContext.seccompProfile | object | `{"type":"RuntimeDefault"}` | Seccomp profile for every container in the pod. |
| ports.admin | int | `9090` | Container port of the admin REST + metrics + health + pprof listener (`PMF_ADMIN_ADDR`). Never routed through an Ingress and never carried by a LoadBalancer or NodePort Service; the chart fails to render if you try. |
| ports.mcp | int | `8080` | Container port of the agent-facing MCP listener (`PMF_MCP_ADDR`). |
| priorityClassName | string | `""` | `spec.template.spec.priorityClassName`. |
| rbac.allowCreate | bool | `true` | Grant the unrestricted `create` verb on Secrets in this namespace. Kubernetes cannot restrict `create` by `resourceNames` (the object has no name at authorization time), so this one verb cannot be name-scoped. It permits creating a Secret, never reading one. Pre-create the state Secret and set this to false to leave the hub with nothing but name-restricted `get,update`. |
| rbac.create | bool | `true` | Render the namespaced Role and RoleBinding that let the hub read and write its own state Secret. Nothing cluster-scoped is ever rendered by this chart. |
| rbac.extraSecretNames | list | `[]` | Extra `resourceNames` appended to the name-restricted Secret rule. Use only if you point `PMF_STATE_SECRET_NAME` elsewhere through `extraEnv`. |
| readinessProbe.enabled | bool | `true` | Enable the readiness probe. It targets `/readyz`, which does check dependencies. |
| readinessProbe.failureThreshold | int | `3` | Failure threshold. `/readyz` reflects a state-store probe that runs every 15 seconds, so one failed probe holds the replica not-ready for at least 15 seconds; at the default period that is two kubelet failures. Keep this at 2 or more, or a single API-server blip removes the replica from the Endpoints. |
| readinessProbe.initialDelaySeconds | int | `0` | Initial delay. |
| readinessProbe.periodSeconds | int | `10` | Probe period. |
| readinessProbe.successThreshold | int | `1` | Success threshold. |
| readinessProbe.timeoutSeconds | int | `3` | Probe timeout. |
| replicaCount | int | `3` | Number of hub replicas. Read before raising above 1: a spoke tunnel is pinned to exactly one replica and there is deliberately no hub-to-hub forwarding (BUILD_SPEC 1.11). Credential state is shared because it lives in one Secret, but tunnels are not. Real HA needs every replica individually addressable from outside the cluster and every spoke configured with all N addresses in `hub.endpoints`. |
| resources.limits.memory | string | `"1Gi"` | Memory limit. Also the source of `GOMEMLIMIT`. |
| resources.requests.cpu | string | `"250m"` | CPU request. |
| resources.requests.memory | string | `"256Mi"` | Memory request. |
| restartOnConfigChange | bool | `true` | Roll the pods when the rendered ConfigMap changes, by stamping its checksum as a pod annotation. |
| revisionHistoryLimit | int | `10` | Number of old ReplicaSets retained. |
| service.admin.enabled | bool | `true` | Publish the admin/metrics port on the ClusterIP Service so a ServiceMonitor can scrape it. |
| service.admin.port | int | `9090` | Service port for admin/metrics traffic. |
| service.annotations | object | `{}` | Annotations for the MCP Service. |
| service.clusterIP | string | `""` | Static ClusterIP. Empty means allocated. |
| service.ipFamilyPolicy | string | `""` | `spec.ipFamilyPolicy`. Empty means the cluster default. |
| service.labels | object | `{}` | Extra labels for the MCP Service. |
| service.mcpPort | int | `8080` | Service port for MCP traffic. |
| service.sessionAffinity | string | `"None"` | `spec.sessionAffinity`. The MCP transport is stateless (BUILD_SPEC 1.10), so `None` is correct. |
| service.type | string | `"ClusterIP"` | Type of the MCP + admin Service. Must stay `ClusterIP` while `service.admin.enabled` is true; the chart refuses to render a LoadBalancer or NodePort carrying the admin port. |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount. |
| serviceAccount.automountServiceAccountToken | bool | `true` | Mount the projected ServiceAccount token. The hub REQUIRES this: it reads and writes its own state Secret through the Kubernetes API. Setting it false makes the hub unable to start with `state.backend: secret`. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount for the hub. |
| serviceAccount.name | string | `""` | Name of the ServiceAccount. Empty means the chart fullname. |
| startupProbe.enabled | bool | `true` | Enable the startup probe on `/healthz`. It is what lets the liveness probe stay aggressive without killing a slow CA or state Secret read. |
| startupProbe.failureThreshold | int | `60` | Failure threshold. 60 x 5s = 5 minutes to load the CA and open the state Secret. |
| startupProbe.initialDelaySeconds | int | `0` | Initial delay. |
| startupProbe.periodSeconds | int | `5` | Probe period. |
| startupProbe.successThreshold | int | `1` | Success threshold. |
| startupProbe.timeoutSeconds | int | `3` | Probe timeout. |
| state.backend | string | `"secret"` | `PMF_STATE_BACKEND`. `secret` stores all durable state in a Kubernetes Secret (production). `file` writes a single JSON file under `state.file` and is for local development only — in a pod it lives on an emptyDir and is LOST on restart, orphaning every enrolled spoke. |
| state.caSecretName | string | `""` | `PMF_CA_SECRET_NAME`. Name of the Secret holding the internal CA certificate and key. Empty means `<fullname>-ca`. Deliberately separate from the state Secret so the two have different blast radii; it is the second entry in the Role's `resourceNames`. |
| state.file | string | `"/tmp/prometheus-mcp-fleet/state.json"` | `PMF_STATE_FILE`. Only used when `state.backend` is `file`. |
| state.secretName | string | `""` | `PMF_STATE_SECRET_NAME`. Name of the Secret the hub owns. Empty means `<fullname>-state`. This exact name is what the rendered Role restricts by `resourceNames`. |
| terminationGracePeriodSeconds | int | `60` | `spec.template.spec.terminationGracePeriodSeconds`. Must exceed `config.shutdownDrainDelay` plus `config.shutdownGrace`. |
| tests.image.pullPolicy | string | `"IfNotPresent"` | Pull policy for the `helm test` image. |
| tests.image.registry | string | `"docker.io"` | Registry for the `helm test` image. |
| tests.image.repository | string | `"busybox"` | Repository for the `helm test` image. Needs `wget`. |
| tests.image.tag | string | `"1.37.0"` | Tag for the `helm test` image. |
| tmpDirSizeLimit | string | `"64Mi"` | `sizeLimit` of the `/tmp` emptyDir that makes `readOnlyRootFilesystem: true` workable. |
| tolerations | list | `[]` | `spec.template.spec.tolerations`. |
| topologySpreadConstraints | list | `[]` | `spec.template.spec.topologySpreadConstraints`. Never use `DoNotSchedule` in a default; it turns a scheduling hint into an outage on small clusters. |
| tracing.enabled | bool | `false` | Enable OTLP trace export. |
| tracing.endpoint | string | `""` | `PMF_OTEL_EXPORTER_OTLP_ENDPOINT`. OTLP/gRPC collector endpoint. |
| tracing.sampleRatio | string | `"0.05"` | `PMF_TRACE_SAMPLE_RATIO`. Head sampling ratio between 0 and 1, as a string so YAML never reformats it. |
| tunnel.path | string | `"/tunnel"` | `PMF_TUNNEL_PATH`. Path on the MCP listener where spokes open the tunnel WebSocket. There is no separate tunnel port and no tunnel Service: an Ingress terminates TLS and cannot pass a client certificate through, so the tunnel arrives as ordinary HTTP on the MCP listener and mutual authentication happens INSIDE the connection, over the spoke's certificate, before any gRPC byte (ADR-0014). The Ingress is a plain proxy and verifies nothing. A spoke's `hub.endpoints` entry is `wss://<ingress host><tunnel.path>`. It may not be `/`, which would collide with the MCP endpoint. |
| updateStrategy.rollingUpdate | object | `{}` | `spec.strategy.rollingUpdate`. Empty means the Kubernetes defaults. |
| updateStrategy.type | string | `"RollingUpdate"` | Deployment strategy type, `RollingUpdate` or `Recreate`. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs)
