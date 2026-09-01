{{/*
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0

Nothing in this chart may reference a hub Service, hub RBAC or a hub release
name. The hub runs in a DIFFERENT cluster; it is reached only through the
operator-supplied `hub.endpoints` and `hub.apiUrl`.
*/}}

{{/* Chart name, overridable. */}}
{{- define "prometheus-mcp-spoke.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified release name used for every object this chart renders. */}}
{{- define "prometheus-mcp-spoke.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Namespace every object is rendered into. */}}
{{- define "prometheus-mcp-spoke.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "prometheus-mcp-spoke.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Selector labels. Immutable across upgrades — never add anything version-bearing. */}}
{{- define "prometheus-mcp-spoke.selectorLabels" -}}
app.kubernetes.io/name: {{ include "prometheus-mcp-spoke.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "prometheus-mcp-spoke.labels" -}}
helm.sh/chart: {{ include "prometheus-mcp-spoke.chart" . }}
{{ include "prometheus-mcp-spoke.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: spoke
app.kubernetes.io/part-of: prometheus-mcp-fleet
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Labels with app.kubernetes.io/component replaced. The base label set already
carries component=spoke, so a template that appended its own produced a DUPLICATE
YAML key -- which parses under Helm and is rejected by a strict decoder. Call as
(list . "spoke-autoupdate").
*/}}
{{- define "prometheus-mcp-spoke.componentLabels" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- $l := fromYaml (include "prometheus-mcp-spoke.labels" $root) -}}
{{- $_ := set $l "app.kubernetes.io/component" $component -}}
{{- toYaml $l -}}
{{- end -}}

{{- define "prometheus-mcp-spoke.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "prometheus-mcp-spoke.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "prometheus-mcp-spoke.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Whether to project the service account token. Empty in values means "whatever
the identity backend needs": the Secret backend talks to the Kubernetes API and
must have it, memory and file never touch the API and must not.
*/}}
{{- define "prometheus-mcp-spoke.automountToken" -}}
{{- if kindIs "bool" .Values.serviceAccount.automountServiceAccountToken -}}
{{- .Values.serviceAccount.automountServiceAccountToken -}}
{{- else if eq .Values.identity.backend "secret" -}}true
{{- else -}}false
{{- end -}}
{{- end -}}

{{/* Fully resolved image reference. A digest always wins over a tag. */}}
{{- define "prometheus-mcp-spoke.image" -}}
{{- $base := .Values.image.repository -}}
{{- with .Values.image.registry -}}
{{- $base = printf "%s/%s" . $.Values.image.repository -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $base .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $base (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/* Repository reference without a tag or digest, for `crane digest`. */}}
{{- define "prometheus-mcp-spoke.imageRepository" -}}
{{- if .Values.image.registry -}}
{{- printf "%s/%s" .Values.image.registry .Values.image.repository -}}
{{- else -}}
{{- .Values.image.repository -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret the spoke writes its issued key and certificate to. This is
the exact string the Role restricts by `resourceNames`, so it is derived in
exactly one place.
*/}}
{{- define "prometheus-mcp-spoke.identitySecretName" -}}
{{- if .Values.identity.secretName -}}
{{- .Values.identity.secretName -}}
{{- else -}}
{{- printf "%s-identity" (include "prometheus-mcp-spoke.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "prometheus-mcp-spoke.configMapName" -}}
{{- printf "%s-config" (include "prometheus-mcp-spoke.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "prometheus-mcp-spoke.hubCAConfigMapName" -}}
{{- printf "%s-hub-ca" (include "prometheus-mcp-spoke.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Name of the enrollment Secret, whether this chart renders it or the operator supplied it. */}}
{{- define "prometheus-mcp-spoke.enrollmentSecretName" -}}
{{- if .Values.enrollment.existingSecret -}}
{{- .Values.enrollment.existingSecret -}}
{{- else -}}
{{- printf "%s-enrollment" (include "prometheus-mcp-spoke.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* True when an enrollment token reaches the pod at all. */}}
{{- define "prometheus-mcp-spoke.hasEnrollment" -}}
{{- if or .Values.enrollment.token .Values.enrollment.existingSecret -}}true{{- end -}}
{{- end -}}

{{/*
Hub endpoint parsing. Since ADR-0014 a hub endpoint is a URL --
wss://hub.example.com/tunnel -- not host:port. The tunnel is a WebSocket on the
hub's ordinary MCP listener behind a standard Ingress, so the port that matters
for egress is the ordinary HTTPS port unless the URL names another.

Argument is the endpoint string, not the root context.
*/}}

{{/* Authority of an endpoint URL, e.g. "hub.example.com:8443" or "[2001:db8::1]". */}}
{{- define "prometheus-mcp-spoke.endpointAuthority" -}}
{{- $u := urlParse . -}}
{{- $u.host | default "" -}}
{{- end -}}

{{/* Host of an endpoint URL, with any port and any IPv6 brackets removed. */}}
{{- define "prometheus-mcp-spoke.endpointHost" -}}
{{- $auth := include "prometheus-mcp-spoke.endpointAuthority" . -}}
{{- if hasPrefix "[" $auth -}}
{{- regexFind "^\\[[^]]*\\]" $auth | trimPrefix "[" | trimSuffix "]" -}}
{{- else if regexMatch ":[0-9]+$" $auth -}}
{{- join ":" (initial (splitList ":" $auth)) -}}
{{- else -}}
{{- $auth -}}
{{- end -}}
{{- end -}}

{{/*
Port of an endpoint URL: the explicit one, else the scheme default. wss and
https are 443, ws and http are 80. This is why the NetworkPolicy no longer
assumes 8443 -- there is no separate tunnel listener to assume it for.
*/}}
{{- define "prometheus-mcp-spoke.endpointPort" -}}
{{- $u := urlParse . -}}
{{- $auth := $u.host | default "" -}}
{{- $port := "" -}}
{{- if hasPrefix "[" $auth -}}
{{- $rest := regexReplaceAll "^\\[[^]]*\\]" $auth "" -}}
{{- if hasPrefix ":" $rest -}}{{- $port = trimPrefix ":" $rest -}}{{- end -}}
{{- else if regexMatch ":[0-9]+$" $auth -}}
{{- $port = last (splitList ":" $auth) -}}
{{- end -}}
{{- if $port -}}
{{- $port -}}
{{- else if or (eq $u.scheme "ws") (eq $u.scheme "http") -}}
80
{{- else -}}
443
{{- end -}}
{{- end -}}

{{/*
CIDR for an endpoint host that is already an IP literal, or empty when it is a
DNS name. A NetworkPolicy cannot resolve a name, so a named hub falls back to
networkPolicy.egress.hub.cidrs. Argument is the endpoint string.
*/}}
{{- define "prometheus-mcp-spoke.endpointCIDR" -}}
{{- $host := include "prometheus-mcp-spoke.endpointHost" . -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" $host -}}
{{- printf "%s/32" $host -}}
{{- else if contains ":" $host -}}
{{- printf "%s/128" $host -}}
{{- end -}}
{{- end -}}

{{/*
Ports the NetworkPolicy opens towards the hub: the explicit override when given,
otherwise one per distinct hub endpoint URL.
*/}}
{{- define "prometheus-mcp-spoke.hubEgressPorts" -}}
{{- if .Values.networkPolicy.egress.hub.ports -}}
{{- toYaml .Values.networkPolicy.egress.hub.ports -}}
{{- else -}}
{{- $ports := list -}}
{{- range .Values.hub.endpoints -}}
{{- $ports = append $ports (include "prometheus-mcp-spoke.endpointPort" . | int) -}}
{{- end -}}
{{- toYaml ($ports | uniq) -}}
{{- end -}}
{{- end -}}

{{/* Port of the local Prometheus, from prometheus.url, defaulted by scheme. */}}
{{- define "prometheus-mcp-spoke.prometheusPort" -}}
{{- $u := urlParse .Values.prometheus.url -}}
{{- $host := $u.host | default "" -}}
{{- if regexMatch ":[0-9]+$" $host -}}
{{- last (splitList ":" $host) -}}
{{- else if eq $u.scheme "https" -}}443
{{- else -}}80
{{- end -}}
{{- end -}}

{{/*
Label matcher appended to every shipped alert expression. Empty resolves to
job="<name>", which is what a ServiceMonitor with jobLabel: app.kubernetes.io/name
produces for this chart.
*/}}
{{- define "prometheus-mcp-spoke.ruleSelector" -}}
{{- if .Values.metrics.prometheusRule.selector -}}
{{- .Values.metrics.prometheusRule.selector -}}
{{- else -}}
{{- printf "job=%q" (include "prometheus-mcp-spoke.name" .) -}}
{{- end -}}
{{- end -}}

{{/*
Fail-fast validation. Every one of these is a misconfiguration that would
otherwise install cleanly and be wrong in production, in a cluster nobody is
watching.
*/}}
{{- define "prometheus-mcp-spoke.validate" -}}

{{/* ---- one spoke, one identity ---- */}}
{{/*
Several spoke pods per cluster are supported and are the default.

The hub pools sessions per cluster rather than letting a new one displace the
last, so siblings do not deregister each other. They share ONE identity Secret
and therefore one certificate: pods that start together converge on whatever
the Secret ends up holding, and at renewal the first pod to renew writes it back
while the rest adopt it instead of minting competitors.

That sharing is what `identity.backend: secret` is for, so it is the only
backend that supports more than one pod. `memory` gives each pod its own
identity and re-enrols on every restart, which multiplies enrollments by pod
count for no benefit. `file` writes to an emptyDir, so it behaves like `memory`
while looking durable.
*/}}
{{- if lt (int .Values.replicaCount) 1 -}}
{{- fail (printf "prometheus-mcp-spoke: replicaCount is %d; it must be at least 1." (int .Values.replicaCount)) -}}
{{- end -}}
{{- if and (gt (int .Values.replicaCount) 1) (ne .Values.identity.backend "secret") -}}
{{- fail (printf "prometheus-mcp-spoke: replicaCount is %d with identity.backend=%s. Several pods of one cluster share a certificate through the identity Secret, so they need identity.backend=secret. %q gives every pod its own identity and re-enrols each on restart, which multiplies enrollments by pod count and leaves the pool renewing several certificates instead of rotating one." (int .Values.replicaCount) .Values.identity.backend .Values.identity.backend) -}}
{{- end -}}

{{/* ---- cluster identity ---- */}}
{{- if not .Values.cluster.id -}}
{{- fail "prometheus-mcp-spoke: cluster.id is required and has no default. It is the immutable identity the hub binds into this spoke's certificate URI SAN, and two clusters sharing one would fight over a single certificate identity." -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" .Values.cluster.id) -}}
{{- fail (printf "prometheus-mcp-spoke: cluster.id %q must match ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$. The hub validates this at enrollment and will refuse the request." .Values.cluster.id) -}}
{{- end -}}

{{/* ---- the hub is in another cluster ---- */}}
{{- if not .Values.hub.endpoints -}}
{{- fail "prometheus-mcp-spoke: hub.endpoints is required and has no default. The hub runs in a DIFFERENT cluster, so there is no in-cluster address to fall back to: set it to the tunnel URL your hub's Ingress publishes, such as wss://hub.example.com/tunnel, one entry per hub replica." -}}
{{- end -}}
{{- range .Values.hub.endpoints -}}
{{- if not (regexMatch "^wss?://" .) -}}
{{- fail (printf "prometheus-mcp-spoke: hub.endpoints entry %q must be a wss:// (or ws://) URL such as wss://hub.example.com/tunnel. Since ADR-0014 the tunnel is a WebSocket on the hub's ordinary MCP listener behind a standard Ingress, not a raw socket on its own port. A bare host:port is read by the binary as wss://<host:port>/tunnel, which for the old :8443 default is simply the wrong port and never connects." .) -}}
{{- end -}}
{{- if not (include "prometheus-mcp-spoke.endpointHost" .) -}}
{{- fail (printf "prometheus-mcp-spoke: hub.endpoints entry %q has no host." .) -}}
{{- end -}}
{{- if regexMatch "[?#]" . -}}
{{- fail (printf "prometheus-mcp-spoke: hub.endpoints entry %q carries a query or fragment; the tunnel URL is a plain path such as wss://hub.example.com/tunnel." .) -}}
{{- end -}}
{{- end -}}
{{- if not .Values.hub.apiUrl -}}
{{- fail "prometheus-mcp-spoke: hub.apiUrl is required and has no default. It is the external https base URL of the hub's enrollment listener, in another cluster." -}}
{{- end -}}
{{- if not (hasPrefix "http" .Values.hub.apiUrl) -}}
{{- fail (printf "prometheus-mcp-spoke: hub.apiUrl %q must be an absolute URL such as https://hub.example.com." .Values.hub.apiUrl) -}}
{{- end -}}
{{- if and .Values.hub.caBundle .Values.hub.existingCASecret -}}
{{- fail "prometheus-mcp-spoke: hub.caBundle and hub.existingCASecret are mutually exclusive; the spoke reads exactly one PMF_HUB_CA_FILE." -}}
{{- end -}}

{{/* ---- two keys for anything insecure ---- */}}
{{- if and .Values.hub.tlsInsecure (not .Values.hub.allowInsecure) -}}
{{- fail "prometheus-mcp-spoke: hub.tlsInsecure disables verification of the hub certificate, which lets anything on the network impersonate the hub and collect this cluster's metrics. Set hub.allowInsecure=true as well to acknowledge that; the binary refuses it otherwise anyway." -}}
{{- end -}}
{{- if and .Values.prometheus.tls.skipVerify (not .Values.hub.allowInsecure) -}}
{{- fail "prometheus-mcp-spoke: prometheus.tls.skipVerify disables verification of the Prometheus certificate. Set hub.allowInsecure=true as well to acknowledge that." -}}
{{- end -}}

{{/* ---- identity backend ---- */}}
{{- if not (has .Values.identity.backend (list "secret" "memory" "file")) -}}
{{- fail (printf "prometheus-mcp-spoke: identity.backend must be secret, memory or file, got %q." .Values.identity.backend) -}}
{{- end -}}
{{- if eq .Values.identity.backend "secret" -}}
{{- if ne (include "prometheus-mcp-spoke.automountToken" .) "true" -}}
{{- fail "prometheus-mcp-spoke: identity.backend is \"secret\" but serviceAccount.automountServiceAccountToken is false. The spoke writes its issued key and certificate through the Kubernetes API and needs the projected token. Use identity.backend=memory if you refuse any RBAC — but read the README first: it forces a re-enrollment on every restart and therefore a MULTI-USE enrollment token." -}}
{{- end -}}
{{- if and (not .Values.rbac.create) (not .Values.serviceAccount.name) -}}
{{- fail "prometheus-mcp-spoke: identity.backend is \"secret\" with rbac.create=false. Grant get,create,update on the identity Secret yourself and set serviceAccount.name to the account that holds it, or set rbac.create=true." -}}
{{- end -}}
{{- end -}}
{{- if not .Values.identity.secretName -}}
{{- if eq .Values.identity.backend "secret" -}}
{{- if gt (len (include "prometheus-mcp-spoke.identitySecretName" .)) 253 -}}
{{- fail "prometheus-mcp-spoke: the derived identity Secret name is too long; set identity.secretName." -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* ---- enrollment ---- */}}
{{- if and .Values.enrollment.token .Values.enrollment.existingSecret -}}
{{- fail "prometheus-mcp-spoke: enrollment.token and enrollment.existingSecret are mutually exclusive." -}}
{{- end -}}

{{/* ---- prometheus ---- */}}
{{- if not .Values.prometheus.url -}}
{{- fail "prometheus-mcp-spoke: prometheus.url is required." -}}
{{- end -}}
{{- if not (hasPrefix "http" .Values.prometheus.url) -}}
{{- fail (printf "prometheus-mcp-spoke: prometheus.url %q must be an absolute http or https URL." .Values.prometheus.url) -}}
{{- end -}}

{{/*
---- the admin port must never leave the cluster ----
The admin listener is the spoke's ONLY listener, and it carries /metrics and
pprof. So a non-ClusterIP Service here, or any Ingress at all, could only ever
be publishing that port.
*/}}
{{- if and .Values.service.enabled (ne .Values.service.type "ClusterIP") -}}
{{- fail (printf "prometheus-mcp-spoke: service.type is %q. The only port this chart exposes is the admin/metrics listener (%d), which carries metrics and pprof and must never be reachable from outside the cluster. Keep service.type=ClusterIP." .Values.service.type (int .Values.ports.admin)) -}}
{{- end -}}
{{- range .Values.extraManifests -}}
{{- if eq (dig "kind" "" .) "Ingress" -}}
{{- fail "prometheus-mcp-spoke: extraManifests contains an Ingress. The spoke has no inbound listener except the admin/metrics port -- it DIALS the hub -- so an Ingress here could only publish metrics and pprof. Scrape it with a ServiceMonitor instead." -}}
{{- end -}}
{{- end -}}
{{- if .Values.metrics.serviceMonitor.enabled -}}
{{- if not .Values.service.enabled -}}
{{- fail "prometheus-mcp-spoke: metrics.serviceMonitor.enabled requires service.enabled, otherwise there is no Service to scrape." -}}
{{- end -}}
{{- end -}}

{{/* ---- closed enums the binary itself rejects at startup ---- */}}
{{- if not (has .Values.config.logLevel (list "debug" "info" "warn" "error")) -}}
{{- fail (printf "prometheus-mcp-spoke: config.logLevel must be debug, info, warn or error, got %q." .Values.config.logLevel) -}}
{{- end -}}
{{- if not (has .Values.config.logFormat (list "json" "text")) -}}
{{- fail (printf "prometheus-mcp-spoke: config.logFormat must be json or text, got %q." .Values.config.logFormat) -}}
{{- end -}}

{{/* ---- tracing ---- */}}
{{- if and .Values.tracing.enabled (not .Values.tracing.endpoint) -}}
{{- fail "prometheus-mcp-spoke: tracing.enabled is true but tracing.endpoint is empty." -}}
{{- end -}}

{{/*
---- the only writable path is the /tmp emptyDir ----
PMF_DATA_DIR is where the spoke caches the hub trust bundle. With
readOnlyRootFilesystem: true anything outside /tmp fails at first write, which
surfaces as a CrashLoopBackOff several minutes into an install rather than as a
render error here.
*/}}
{{- if and .Values.containerSecurityContext.readOnlyRootFilesystem (not (hasPrefix "/tmp" .Values.config.dataDir)) (not .Values.extraVolumeMounts) -}}
{{- fail (printf "prometheus-mcp-spoke: config.dataDir is %q but containerSecurityContext.readOnlyRootFilesystem is true and no extraVolumeMounts make that path writable. Keep it under /tmp (the emptyDir this chart always mounts) or mount a writable volume there yourself." .Values.config.dataDir) -}}
{{- end -}}

{{- end -}}

{{/*
Bytes in a Kubernetes memory quantity, as an integer.

This exists because GOMEMLIMIT must be computed here rather than by the
downward API. `resourceFieldRef` can only divide — the value it produces is
ceil(resource / divisor) — and Kubernetes accepts a divisor of only 1 and the
unit quantities (1k, 1M, 1Gi, ...). There is no divisor that yields 90% of a
limit, so the obvious spelling, divisor: 1/ratio, renders "1.1111" and the API
server rejects the whole Deployment with "only divisor's values 1, 1k, 1M, ...
are supported". It renders and validates fine offline, which is why this
survived helm template, helm lint and kubeconform alike and only failed on a
real API server.
*/}}
{{- define "prometheus-mcp-spoke.memoryBytes" -}}
{{- $q := . | toString | trim -}}
{{- $num := regexFind "^[0-9]+(\\.[0-9]+)?" $q -}}
{{- if eq $num "" -}}
{{- fail (printf "prometheus-mcp-spoke: cannot read %q as a memory quantity." $q) -}}
{{- end -}}
{{- $suffix := substr (len $num) (len $q) $q -}}
{{- $units := dict "" 1.0 "k" 1000.0 "M" 1000000.0 "G" 1000000000.0 "T" 1000000000000.0 "P" 1000000000000000.0 "E" 1000000000000000000.0 "Ki" 1024.0 "Mi" 1048576.0 "Gi" 1073741824.0 "Ti" 1099511627776.0 "Pi" 1125899906842624.0 "Ei" 1152921504606846976.0 -}}
{{- if not (hasKey $units $suffix) -}}
{{- fail (printf "prometheus-mcp-spoke: memory quantity %q has an unsupported suffix %q. Use bytes or one of k, M, G, T, P, E, Ki, Mi, Gi, Ti, Pi, Ei." $q $suffix) -}}
{{- end -}}
{{- mulf (float64 $num) (get $units $suffix) | floor | int64 -}}
{{- end -}}

{{/*
GOMEMLIMIT: goRuntime.memLimitRatio of the declared container memory limit, in
bytes. Only ever rendered when resources.limits.memory is set, so it is always
derived from the cgroup limit and never from node allocatable.
*/}}
{{- define "prometheus-mcp-spoke.goMemLimit" -}}
{{- $bytes := include "prometheus-mcp-spoke.memoryBytes" (dig "limits" "memory" "" .Values.resources) | float64 -}}
{{- mulf $bytes .Values.goRuntime.memLimitRatio | floor | int64 -}}
{{- end -}}
