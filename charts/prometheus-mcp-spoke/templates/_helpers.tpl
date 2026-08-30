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

{{- define "prometheus-mcp-spoke.autoUpdate.image" -}}
{{- $base := .Values.autoUpdate.image.repository -}}
{{- with .Values.autoUpdate.image.registry -}}
{{- $base = printf "%s/%s" . $.Values.autoUpdate.image.repository -}}
{{- end -}}
{{- if .Values.autoUpdate.image.digest -}}
{{- printf "%s@%s" $base .Values.autoUpdate.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $base (.Values.autoUpdate.image.tag | default .Chart.AppVersion) -}}
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

{{- define "prometheus-mcp-spoke.autoUpdateName" -}}
{{- printf "%s-autoupdate" (include "prometheus-mcp-spoke.fullname" .) | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "prometheus-mcp-spoke.autoUpdate.serviceAccountName" -}}
{{- include "prometheus-mcp-spoke.autoUpdateName" . -}}
{{- end -}}

{{/*
Host part of a `host:port` endpoint, tolerating a bracketed IPv6 literal.
Argument is the endpoint string, not the root context.
*/}}
{{- define "prometheus-mcp-spoke.endpointHost" -}}
{{- $parts := splitList ":" . -}}
{{- join ":" (initial $parts) | trimPrefix "[" | trimSuffix "]" -}}
{{- end -}}

{{/* Port part of a `host:port` endpoint. Argument is the endpoint string. */}}
{{- define "prometheus-mcp-spoke.endpointPort" -}}
{{- last (splitList ":" .) -}}
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
Deterministic stagger. adler32sum over the release identity spreads a fleet of
100 clusters across a whole week instead of having them all update at 02:00
Monday. minute = h % 60, hour = 2 + h % 4, weekday = (h + cohortShift) % 7.

Set autoUpdate.identity to cluster.id when every cluster installs under the same
release name and namespace, or the hash is identical everywhere and the whole
point is lost.
*/}}
{{- define "prometheus-mcp-spoke.autoUpdate.schedule" -}}
{{- if .Values.autoUpdate.schedule -}}
{{- .Values.autoUpdate.schedule -}}
{{- else -}}
{{- $identity := .Values.autoUpdate.identity | default (printf "%s/%s" .Release.Name (include "prometheus-mcp-spoke.namespace" .)) -}}
{{- $h := adler32sum $identity | int64 -}}
{{- $minute := mod $h 60 -}}
{{- $hour := add 2 (mod $h 4) -}}
{{- $shift := 0 -}}
{{- if eq .Values.autoUpdate.cohort "early" -}}{{- $shift = 2 -}}{{- end -}}
{{- if eq .Values.autoUpdate.cohort "stable" -}}{{- $shift = 4 -}}{{- end -}}
{{- $weekday := mod (add $h $shift) 7 -}}
{{- printf "%d %d * * %d" $minute $hour $weekday -}}
{{- end -}}
{{- end -}}

{{/* Minimum age of a promotion this cohort will accept, in hours. */}}
{{- define "prometheus-mcp-spoke.autoUpdate.minAgeHours" -}}
{{- if eq .Values.autoUpdate.cohort "canary" -}}0
{{- else if eq .Values.autoUpdate.cohort "early" -}}72
{{- else -}}168
{{- end -}}
{{- end -}}

{{/*
Fail-fast validation. Every one of these is a misconfiguration that would
otherwise install cleanly and be wrong in production, in a cluster nobody is
watching.
*/}}
{{- define "prometheus-mcp-spoke.validate" -}}

{{/* ---- one spoke, one identity ---- */}}
{{- if ne (int .Values.replicaCount) 1 -}}
{{- fail (printf "prometheus-mcp-spoke: replicaCount is %d. A spoke's identity is ONE X.509 certificate bound to ONE cluster ID: two pods would renew over each other in the same identity Secret and each would deregister the other's tunnel at the hub. Scale the hub, never the spoke." (int .Values.replicaCount)) -}}
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
{{- fail "prometheus-mcp-spoke: hub.endpoints is required and has no default. The hub runs in a DIFFERENT cluster, so there is no in-cluster address to fall back to: set it to the external host:port your hub's tunnel Service publishes, one entry per hub replica." -}}
{{- end -}}
{{- range .Values.hub.endpoints -}}
{{- $port := include "prometheus-mcp-spoke.endpointPort" . -}}
{{- if or (not (contains ":" .)) (not (regexMatch "^[0-9]+$" $port)) -}}
{{- fail (printf "prometheus-mcp-spoke: hub.endpoints entry %q is not host:port. The spoke dials a raw mTLS socket, not a URL, so a scheme or a missing port cannot be guessed." .) -}}
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

{{/* ---- auto update ---- */}}
{{- if .Values.autoUpdate.enabled -}}
{{- if not (has .Values.autoUpdate.cohort (list "canary" "early" "stable")) -}}
{{- fail (printf "prometheus-mcp-spoke: autoUpdate.cohort must be canary, early or stable, got %q." .Values.autoUpdate.cohort) -}}
{{- end -}}
{{- if not .Values.autoUpdate.certificateIdentityRegexp -}}
{{- fail "prometheus-mcp-spoke: autoUpdate.certificateIdentityRegexp is empty. An unpinned signer identity makes cosign verification meaningless." -}}
{{- end -}}
{{- if eq .Values.autoUpdate.certificateIdentityRegexp ".*" -}}
{{- fail "prometheus-mcp-spoke: autoUpdate.certificateIdentityRegexp is \".*\", which accepts any signer." -}}
{{- end -}}
{{- if not .Values.autoUpdate.certificateOidcIssuer -}}
{{- fail "prometheus-mcp-spoke: autoUpdate.certificateOidcIssuer is empty." -}}
{{- end -}}
{{- if not .Values.autoUpdate.channelTag -}}
{{- fail "prometheus-mcp-spoke: autoUpdate.channelTag is empty; there is nothing to resolve to a digest." -}}
{{- end -}}
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
