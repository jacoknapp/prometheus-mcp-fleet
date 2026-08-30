# prometheus-mcp-hub

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

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
  --set ingress.host=hub.example.com \
  --set ingress.enabled=true \
  --set ingress.host=mcp.example.com \
  --set config.publicURL=https://mcp.example.com
```

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
kube-state-metrics) and `PrometheusMCPAutoUpdateFailed` (only when auto-update is on).

## Automatic updates

**`autoUpdate.enabled` is `false`, and on the hub it should usually stay that way.**

Say the quiet part out loud: an automatic weekly rollout to a fleet of production clusters
is a fleet-wide outage delivery mechanism. One bad image, and every cluster applies it
unattended, on a schedule, while nobody is watching. The hub makes that worse, because it
is the single point of failure for every agent's access to every cluster.

That is exactly why the path, when you do enable it, is built the way it is:

* **Off by default.** Nothing renders at all while `autoUpdate.enabled` is false.
* **Digest-pinned.** The job resolves the moving `autoUpdate.channelTag` to a digest and
  patches the workload to `repo@sha256:...`. A tag is never written into the pod spec, so
  the running workload cannot move underneath you between reconciliations.
* **Signature- and provenance-verified.** Both `cosign verify` and
  `cosign verify-attestation --type slsaprovenance` must pass, against a pinned OIDC issuer
  and a narrow `--certificate-identity-regexp`. `set -e` means either failure aborts the
  job before anything is patched. The chart refuses to render a `.*` identity regexp.
* **Staggered.** With no `autoUpdate.schedule`, the schedule is derived from
  `adler32(release/namespace)`: minute `h%60`, hour `2 + h%4`, weekday `(h + cohortShift)%7`.
  A hundred clusters therefore spread across a whole week instead of pulling one new digest
  in the same minute. Set `autoUpdate.identity` when many clusters share a release name.
* **Cohorted.** `canary` accepts a promotion immediately, `early` after 72h, `stable` after
  7 days, and the cohort also shifts the weekday so canaries always move first. An
  unparseable image timestamp fails closed.
* **Rolled back.** On a failed `kubectl rollout status` the job runs `kubectl rollout undo`
  and exits non-zero, which raises `PrometheusMCPAutoUpdateFailed`.
* **Scoped.** Its `Role` is namespaced and restricted by `resourceNames` to exactly the one
  Deployment this release owns. `list`/`watch` are namespace-scoped only because a
  collection request carries no resource name for RBAC to match; they grant no mutation.

`autoUpdate.image` must provide a POSIX shell plus `kubectl`, `cosign`, `crane` and `jq` —
the hub image is distroless and has none of them. The job aborts with a named error if a
tool is missing.

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
| affinity | object | `{}` | `spec.template.spec.affinity`. |
| autoUpdate.activeDeadlineSeconds | int | `900` | `activeDeadlineSeconds` of the update Job. |
| autoUpdate.backoffLimit | int | `0` | `backoffLimit` of the update Job. 0 — a failed verified rollout must not be retried blindly. |
| autoUpdate.certificateIdentityRegexp | string | `"^https://github\\.com/jacoknapp/prometheus-mcp-fleet/\\.github/workflows/.+@refs/tags/v.+$"` | Regex the signing certificate's SAN identity must match. Narrow, never `.*`. |
| autoUpdate.certificateOidcIssuer | string | `"https://token.actions.githubusercontent.com"` | OIDC issuer that must have signed the image. |
| autoUpdate.channelTag | string | `"stable"` | Moving OCI tag the updater resolves to a digest. It is never written into the pod spec. |
| autoUpdate.cohort | string | `"stable"` | Release cohort. `canary` accepts a promotion immediately, `early` after 72h, `stable` after 7 days. The cohort also shifts the derived weekday so canaries always move first. |
| autoUpdate.concurrencyPolicy | string | `"Forbid"` | `spec.concurrencyPolicy`. |
| autoUpdate.containerSecurityContext | object | `{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}` | Container security context for the update job. |
| autoUpdate.enabled | bool | `false` | Render a CronJob that resolves `autoUpdate.channelTag` to a digest, verifies the signature and SLSA provenance with cosign, and patches this Deployment to that DIGEST. OFF BY DEFAULT AND DISCOURAGED ON THE HUB. An unattended weekly rollout across a fleet is a fleet-wide outage delivery mechanism, and the hub is the single point of failure for every agent. Read "Automatic updates" in the README before enabling. |
| autoUpdate.extraEnv | list | `[]` | Extra environment variables for the update job, in raw `EnvVar` form. Proxy settings and registry credential helpers go here. |
| autoUpdate.failedJobsHistoryLimit | int | `3` | `spec.failedJobsHistoryLimit`. |
| autoUpdate.identity | string | `""` | Extra string mixed into the stagger hash. Empty means release name plus namespace. Set it to your cluster identity when many clusters share a release name. |
| autoUpdate.image.digest | string | `""` | Digest of the updater image. Strongly recommended: this image is handed write access to your workload. |
| autoUpdate.image.pullPolicy | string | `"IfNotPresent"` | Pull policy for the updater image. |
| autoUpdate.image.registry | string | `"ghcr.io"` | Registry of the updater image. |
| autoUpdate.image.repository | string | `"jacoknapp/prometheus-mcp-fleet/updater"` | Repository of the updater image. It MUST provide a POSIX shell plus `kubectl`, `cosign`, `crane` and `jq`; the hub and spoke images are distroless and have no shell. The job aborts if a tool is missing. Point this at your own internal image if you will not consume ours. |
| autoUpdate.image.tag | string | `""` | Tag of the updater image. Empty means `.Chart.AppVersion`. |
| autoUpdate.nodeSelector | object | `{}` | Node selector for the update job. |
| autoUpdate.pinned | bool | `false` | Refuse to patch anything. Set alongside an explicit `image.digest` to freeze the workload while keeping the CronJob's verification output. |
| autoUpdate.podSecurityContext | object | `{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context for the update job. Deliberately does not pin a UID, because the updater image is not ours to make assumptions about. |
| autoUpdate.rekorURL | string | `""` | Rekor transparency log URL. Empty uses cosign's default public instance. |
| autoUpdate.resources.limits.memory | string | `"512Mi"` | Memory limit for the update job. |
| autoUpdate.resources.requests.cpu | string | `"50m"` | CPU request for the update job. |
| autoUpdate.resources.requests.memory | string | `"128Mi"` | Memory request for the update job. |
| autoUpdate.rolloutTimeout | string | `"5m"` | `kubectl rollout status` timeout. On expiry the job runs `kubectl rollout undo`. |
| autoUpdate.schedule | string | `""` | Explicit cron schedule. Empty derives one from a hash of the release identity so a fleet spreads across a whole week instead of updating simultaneously. |
| autoUpdate.scratchSizeLimit | string | `"512Mi"` | `sizeLimit` of the writable scratch emptyDir the updater needs for cosign and crane caches. |
| autoUpdate.startingDeadlineSeconds | int | `600` | `spec.startingDeadlineSeconds`. |
| autoUpdate.successfulJobsHistoryLimit | int | `3` | `spec.successfulJobsHistoryLimit`. |
| autoUpdate.timeZone | string | `""` | IANA time zone for the schedule (Kubernetes >= 1.27). Empty means the kube-controller-manager's zone. |
| autoUpdate.tolerations | list | `[]` | Tolerations for the update job. |
| autoUpdate.ttlSecondsAfterFinished | string | `""` | `ttlSecondsAfterFinished` of the update Job. Empty means unset. |
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
| config.agentKeyTTL | string | `"720h"` | `PMF_AGENT_KEY_TTL`. Default lifetime of a minted `pmf_agt_` agent key. |
| config.dataDir | string | `"/tmp/prometheus-mcp-fleet"` | `PMF_DATA_DIR`. Scratch directory for the self-generated HMAC pepper and the CA material materialised out of the CA Secret. NOTHING here is durable — it is the `/tmp` emptyDir. It must stay under `/tmp` unless you mount a writable volume elsewhere with `extraVolumes`/`extraVolumeMounts`; the chart refuses to render otherwise. |
| config.enableStatusConfig | bool | `false` | `PMF_ENABLE_STATUS_CONFIG`. Ungates the `/api/v1/status/config` Prometheus endpoint. Off by default because scrape configurations routinely embed bearer tokens and basic-auth passwords in plain text, and this hub hands its output to an AI agent. |
| config.enrollmentTokenTTL | string | `"15m"` | `PMF_ENROLLMENT_TOKEN_TTL`. Lifetime of a single-use `pmf_enr_` token. |
| config.factsPollInterval | string | `"60s"` | `PMF_FACTS_POLL_INTERVAL`. How often the hub refreshes cluster facts. |
| config.logFormat | string | `"json"` | `PMF_LOG_FORMAT`. One of `json`, `text`. |
| config.logLevel | string | `"info"` | `PMF_LOG_LEVEL`. One of `debug`, `info`, `warn`, `error`. |
| config.maxInflightPerCluster | int | `8` | `PMF_MAX_INFLIGHT_PER_CLUSTER`. Per-cluster in-flight request semaphore. |
| config.maxResponseBudgetBytes | int | `268435456` | `PMF_MAX_RESPONSE_BUDGET_BYTES`. Process-wide in-flight response byte budget. |
| config.maxResponseBytes | int | `33554432` | `PMF_MAX_RESPONSE_BYTES`. Maximum bytes accepted from one upstream response. |
| config.maxSpokes | int | `256` | `PMF_MAX_SPOKES`. Hard cap on enrolled clusters. |
| config.pprofEnabled | bool | `false` | `PMF_PPROF_ENABLED`. Exposes `/debug/pprof` on the admin listener. |
| config.publicURL | string | `""` | `PMF_PUBLIC_URL`. Canonical external MCP URL, used for the OAuth protected-resource-metadata document. Set this to whatever your Ingress publishes. |
| config.queryTimeout | string | `"30s"` | `PMF_QUERY_TIMEOUT`. Instant and metadata query deadline. |
| config.rangeQueryTimeout | string | `"120s"` | `PMF_RANGE_QUERY_TIMEOUT`. Range query deadline. |
| config.shutdownDrainDelay | string | `"5s"` | `PMF_SHUTDOWN_DRAIN_DELAY`. Time `/readyz` reports 503 before work stops, so load balancers notice. |
| config.shutdownGrace | string | `"30s"` | `PMF_SHUTDOWN_GRACE`. Graceful shutdown budget for in-flight work. |
| config.spokeCertTTL | string | `"336h"` | `PMF_SPOKE_CERT_TTL`. Lifetime of an issued spoke client certificate. |
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
| goRuntime.memLimit | bool | `true` | Set `GOMEMLIMIT` from `resources.limits.memory` via the downward API. Skipped when no memory limit is set, because the downward API would then report node allocatable. |
| goRuntime.memLimitRatio | float | `0.9` | Fraction of the memory limit used for `GOMEMLIMIT`, as a downward API divisor. 0.9 leaves headroom for non-Go allocations before the kernel OOM killer. |
| hostNetwork | bool | `false` | `spec.template.spec.hostNetwork`. |
| image.digest | string | `""` | Image digest (`sha256:...`). When set the image is pinned by digest and the tag is ignored. Recommended for production and set automatically by the release workflow. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.registry | string | `"ghcr.io"` | Image registry. |
| image.repository | string | `"jacoknapp/prometheus-mcp-fleet/hub"` | Image repository, without the registry. |
| image.tag | string | `""` | Image tag. Empty means `.Chart.AppVersion`. Ignored when `image.digest` is set. |
| imagePullSecrets | list | `[]` | Image pull secrets for a private registry. |
| ingress.annotations | object | `{}` | Annotations for the Ingress. IDLE TIMEOUTS: an Ingress controller closes an idle upgraded connection, and the tunnel is a long-lived WebSocket. nginx defaults to 60s while the tunnel's HTTP/2 keepalive pings run every 10s, so the defaults are fine — but a controller tuned BELOW ~30s disconnects every spoke in the fleet, repeatedly, and the hub still looks healthy. Raise it there: nginx.ingress.kubernetes.io/proxy-read-timeout: "3600" nginx.ingress.kubernetes.io/proxy-send-timeout: "3600" (HAProxy: `haproxy.org/timeout-tunnel`. Traefik: the entrypoint's respondingTimeouts.) |
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
| metrics.prometheusRule.rules.autoUpdateFailed | bool | `true` | `PrometheusMCPAutoUpdateFailed` — the auto-update CronJob failed. Requires kube-state-metrics. Only rendered when `autoUpdate.enabled` is true. |
| metrics.prometheusRule.rules.caCertExpiringSoon | bool | `true` | `PrometheusMCPHubCACertExpiringSoon` — `promfleet_hub_ca_cert_expiry_seconds` below `thresholds.caCertExpirySeconds`. |
| metrics.prometheusRule.rules.hubDown | bool | `true` | `PrometheusMCPHubDown` — no hub instance is being scraped successfully. |
| metrics.prometheusRule.rules.proxyErrorRatioHigh | bool | `true` | `PrometheusMCPHubProxyErrorRatioHigh` — 5xx ratio of proxied Prometheus requests above `thresholds.proxyErrorRatio`. |
| metrics.prometheusRule.rules.restartLoop | bool | `true` | `PrometheusMCPHubRestartLoop` — container restarts above `thresholds.restartsPerHour`. Requires kube-state-metrics. |
| metrics.prometheusRule.rules.spokeCertExpiringSoon | bool | `true` | `PrometheusMCPHubSpokeCertExpiringSoon` — `promfleet_hub_spoke_cert_expiry_seconds` below `thresholds.spokeCertExpirySeconds` for some cluster. |
| metrics.prometheusRule.rules.spokesDisconnected | bool | `true` | `PrometheusMCPSpokesDisconnected` — more than `thresholds.spokesDisconnectedRatio` of enrolled spokes have no tunnel. |
| metrics.prometheusRule.runbookUrlPrefix | string | `"https://github.com/jacoknapp/prometheus-mcp-fleet/blob/main/docs/runbooks/"` | Runbook URL prefix; the alert name is appended. |
| metrics.prometheusRule.selector | string | `""` | Label matcher appended to every shipped expression. Empty means `job="<fullname>"`, which is what a default ServiceMonitor produces. |
| metrics.prometheusRule.thresholds.caCertExpirySeconds | int | `1209600` | Seconds of remaining CA certificate validity below which `PrometheusMCPHubCACertExpiringSoon` fires. 14 days. `promfleet_hub_ca_cert_expiry_seconds` is seconds REMAINING, not a unix timestamp. |
| metrics.prometheusRule.thresholds.proxyErrorRatio | float | `0.1` | 5xx ratio of proxied requests above which `PrometheusMCPHubProxyErrorRatioHigh` fires. |
| metrics.prometheusRule.thresholds.restartsPerHour | int | `3` | Container restarts in one hour above which `PrometheusMCPHubRestartLoop` fires. |
| metrics.prometheusRule.thresholds.spokeCertExpirySeconds | int | `259200` | Seconds of remaining spoke certificate validity below which `PrometheusMCPSpokeCertExpiringSoon` fires. 3 days against a 14 day certificate TTL. |
| metrics.prometheusRule.thresholds.spokesDisconnectedRatio | float | `0.1` | Fraction of enrolled spokes that may be disconnected before `PrometheusMCPSpokesDisconnected` fires. |
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
| networkPolicy.egress.kubeAPIPort | int | `443` | Port of the Kubernetes API server for the egress rule. |
| networkPolicy.enabled | bool | `true` | Render a NetworkPolicy. On by default: the hub terminates connections from outside the cluster and holds a CA. |
| networkPolicy.labels | object | `{}` | Extra labels for the NetworkPolicy. |
| networkPolicy.mcp.allowAll | bool | `false` | Allow ingress to the MCP port from any source. Use when your Ingress controller's identity cannot be expressed as a selector. Leave it false. This one rule is the hub's whole inbound story: SPOKE TUNNELS arrive here too, on the same port, from the same Ingress controller, so there is no separate tunnel rule to open. Restricting the port to the controller is defence in depth — the hub authenticates every spoke itself, inside the connection — but it is still right, and if you narrow it, narrow it to the CONTROLLER and never to the agents alone or you cut off every spoke in the fleet. |
| networkPolicy.mcp.extraFrom | list | `[]` | Additional raw `ingress.from` entries for the MCP port. |
| networkPolicy.mcp.namespaceSelector | object | `{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}}` | `namespaceSelector` for clients allowed to reach the MCP port. |
| networkPolicy.mcp.podSelector | object | `{}` | `podSelector` for clients allowed to reach the MCP port. Empty selects every pod in the selected namespaces. |
| nodeSelector | object | `{}` | `spec.template.spec.nodeSelector`. |
| podAnnotations | object | `{}` | Annotations for the hub pods. |
| podDisruptionBudget.enabled | bool | `true` | Render a PodDisruptionBudget. It is force-disabled whenever `replicaCount < 2`: `minAvailable: 1` on a single-replica workload blocks every node drain forever. |
| podDisruptionBudget.maxUnavailable | string | `""` | `spec.maxUnavailable`. Empty means unset. |
| podDisruptionBudget.minAvailable | int | `1` | `spec.minAvailable`. Mutually exclusive with `maxUnavailable`. |
| podDisruptionBudget.unhealthyPodEvictionPolicy | string | `""` | `spec.unhealthyPodEvictionPolicy` (Kubernetes >= 1.27). `AlwaysAllow` lets a broken pod be evicted. |
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
| readinessProbe.failureThreshold | int | `3` | Failure threshold. |
| readinessProbe.initialDelaySeconds | int | `0` | Initial delay. |
| readinessProbe.periodSeconds | int | `10` | Probe period. |
| readinessProbe.successThreshold | int | `1` | Success threshold. |
| readinessProbe.timeoutSeconds | int | `3` | Probe timeout. |
| replicaCount | int | `1` | Number of hub replicas. Read before raising above 1: a spoke tunnel is pinned to exactly one replica and there is deliberately no hub-to-hub forwarding (BUILD_SPEC 1.11). Credential state is shared because it lives in one Secret, but tunnels are not. Real HA needs every replica individually routable from outside the cluster and every spoke configured with all N URLs in `hub.endpoints`. |
| resources.limits.memory | string | `"1Gi"` | Memory limit. Also the source of `GOMEMLIMIT` via the downward API. |
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
