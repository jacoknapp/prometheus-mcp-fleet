{{/*
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
*/}}

{{/* Chart name, overridable. */}}
{{- define "prometheus-mcp-hub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified release name used for every object this chart renders. */}}
{{- define "prometheus-mcp-hub.fullname" -}}
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
{{- define "prometheus-mcp-hub.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "prometheus-mcp-hub.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Selector labels. Immutable across upgrades — never add anything version-bearing. */}}
{{- define "prometheus-mcp-hub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "prometheus-mcp-hub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "prometheus-mcp-hub.labels" -}}
helm.sh/chart: {{ include "prometheus-mcp-hub.chart" . }}
{{ include "prometheus-mcp-hub.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: hub
app.kubernetes.io/part-of: prometheus-mcp-fleet
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Labels with app.kubernetes.io/component replaced. The base label set already
carries component=hub, so a template that appended its own produced a DUPLICATE
YAML key -- which parses under Helm and is rejected by a strict decoder. Call as
(list . "hub-tunnel").
*/}}
{{- define "prometheus-mcp-hub.componentLabels" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- $l := fromYaml (include "prometheus-mcp-hub.labels" $root) -}}
{{- $_ := set $l "app.kubernetes.io/component" $component -}}
{{- toYaml $l -}}
{{- end -}}

{{- define "prometheus-mcp-hub.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "prometheus-mcp-hub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "prometheus-mcp-hub.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Fully resolved image reference. A digest always wins over a tag. */}}
{{- define "prometheus-mcp-hub.image" -}}
{{- $registry := .Values.image.registry | default "" -}}
{{- $repo := .Values.image.repository -}}
{{- $base := $repo -}}
{{- if $registry -}}
{{- $base = printf "%s/%s" $registry $repo -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $base .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $base (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{- define "prometheus-mcp-hub.autoUpdate.image" -}}
{{- $registry := .Values.autoUpdate.image.registry | default "" -}}
{{- $base := .Values.autoUpdate.image.repository -}}
{{- if $registry -}}
{{- $base = printf "%s/%s" $registry .Values.autoUpdate.image.repository -}}
{{- end -}}
{{- if .Values.autoUpdate.image.digest -}}
{{- printf "%s@%s" $base .Values.autoUpdate.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $base (.Values.autoUpdate.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/* Repository reference without a tag or digest, for `crane digest`. */}}
{{- define "prometheus-mcp-hub.imageRepository" -}}
{{- if .Values.image.registry -}}
{{- printf "%s/%s" .Values.image.registry .Values.image.repository -}}
{{- else -}}
{{- .Values.image.repository -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret the hub owns. This is the exact string the Role restricts by
`resourceNames`, so it must be derived in exactly one place.
*/}}
{{- define "prometheus-mcp-hub.stateSecretName" -}}
{{- if .Values.state.secretName -}}
{{- .Values.state.secretName -}}
{{- else -}}
{{- printf "%s-state" (include "prometheus-mcp-hub.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding the CA certificate and key. Deliberately separate
from the state Secret: the two have different blast radii, so they can carry
different RBAC and be rotated independently.
*/}}
{{- define "prometheus-mcp-hub.caSecretName" -}}
{{- if .Values.state.caSecretName -}}
{{- .Values.state.caSecretName -}}
{{- else -}}
{{- printf "%s-ca" (include "prometheus-mcp-hub.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Scratch directory. readOnlyRootFilesystem:true means the only writable path is
the /tmp emptyDir, so PMF_DATA_DIR must live under it. Nothing here is durable;
that is the point of the state and CA Secrets.
*/}}
{{- define "prometheus-mcp-hub.dataDir" -}}
{{- .Values.config.dataDir -}}
{{- end -}}

{{- define "prometheus-mcp-hub.autoUpdate.serviceAccountName" -}}
{{- include "prometheus-mcp-hub.autoUpdateName" . -}}
{{- end -}}

{{/*
Label matcher appended to every shipped alert expression. Empty resolves to
job="<name>", which is what a ServiceMonitor with jobLabel: app.kubernetes.io/name
produces for this chart.
*/}}
{{- define "prometheus-mcp-hub.ruleSelector" -}}
{{- if .Values.metrics.prometheusRule.selector -}}
{{- .Values.metrics.prometheusRule.selector -}}
{{- else -}}
{{- printf "job=%q" (include "prometheus-mcp-hub.name" .) -}}
{{- end -}}
{{- end -}}

{{- define "prometheus-mcp-hub.configMapName" -}}
{{- printf "%s-config" (include "prometheus-mcp-hub.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "prometheus-mcp-hub.tunnelServiceName" -}}
{{- printf "%s-tunnel" (include "prometheus-mcp-hub.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "prometheus-mcp-hub.autoUpdateName" -}}
{{- printf "%s-autoupdate" (include "prometheus-mcp-hub.fullname" .) | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{/* PodDisruptionBudget is force-disabled below two replicas. */}}
{{- define "prometheus-mcp-hub.pdbEnabled" -}}
{{- if and .Values.podDisruptionBudget.enabled (ge (int .Values.replicaCount) 2) -}}true{{- end -}}
{{- end -}}

{{/*
Deterministic stagger. adler32sum over the release identity spreads a fleet of
clusters across a whole week instead of having them all update at 02:00 Monday.
minute = h % 60, hour = 2 + h % 4, weekday = (h + cohortShift) % 7.
*/}}
{{- define "prometheus-mcp-hub.autoUpdate.schedule" -}}
{{- if .Values.autoUpdate.schedule -}}
{{- .Values.autoUpdate.schedule -}}
{{- else -}}
{{- $identity := .Values.autoUpdate.identity | default (printf "%s/%s" .Release.Name (include "prometheus-mcp-hub.namespace" .)) -}}
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

{{/* Minimum age of the `stable` promotion this cohort will accept, in hours. */}}
{{- define "prometheus-mcp-hub.autoUpdate.minAgeHours" -}}
{{- if eq .Values.autoUpdate.cohort "canary" -}}0
{{- else if eq .Values.autoUpdate.cohort "early" -}}72
{{- else -}}168
{{- end -}}
{{- end -}}

{{/*
Fail-fast validation. Every one of these is a misconfiguration that would
otherwise install cleanly and be wrong in production.
*/}}
{{- define "prometheus-mcp-hub.validate" -}}

{{/* ---- the admin port must never leave the cluster ---- */}}
{{- if and .Values.service.admin.enabled (ne .Values.service.type "ClusterIP") -}}
{{- fail (printf "prometheus-mcp-hub: service.type is %q while service.admin.enabled is true. The admin listener carries the admin REST API and pprof and must never be reachable from outside the cluster. Either set service.type=ClusterIP or set service.admin.enabled=false." .Values.service.type) -}}
{{- end -}}

{{- if eq (int .Values.service.mcpPort) (int .Values.ports.admin) -}}
{{- fail (printf "prometheus-mcp-hub: service.mcpPort (%d) collides with ports.admin (%d); the MCP Service port would forward to the admin listener." (int .Values.service.mcpPort) (int .Values.ports.admin)) -}}
{{- end -}}

{{- if eq (int .Values.ports.mcp) (int .Values.ports.admin) -}}
{{- fail "prometheus-mcp-hub: ports.mcp and ports.admin must differ." -}}
{{- end -}}
{{- if eq (int .Values.ports.tunnel) (int .Values.ports.admin) -}}
{{- fail "prometheus-mcp-hub: ports.tunnel and ports.admin must differ." -}}
{{- end -}}
{{- if eq (int .Values.ports.mcp) (int .Values.ports.tunnel) -}}
{{- fail "prometheus-mcp-hub: ports.mcp and ports.tunnel must differ." -}}
{{- end -}}

{{- if .Values.ingress.enabled -}}
{{- if ne .Values.ingress.servicePortName "mcp" -}}
{{- fail (printf "prometheus-mcp-hub: ingress.servicePortName is %q. Only the %q port may be published through an Ingress; the admin port must never be routed and the tunnel port cannot survive an HTTP proxy (it is mutually authenticated TLS -- publish it with tunnel.service instead)." .Values.ingress.servicePortName "mcp") -}}
{{- end -}}
{{- if not .Values.ingress.host -}}
{{- fail "prometheus-mcp-hub: ingress.enabled is true but ingress.host is empty." -}}
{{- end -}}
{{- end -}}

{{- if .Values.tunnel.service.enabled -}}
{{- if eq (int .Values.tunnel.service.port) (int .Values.ports.admin) -}}
{{- fail (printf "prometheus-mcp-hub: tunnel.service.port (%d) equals ports.admin (%d); a LoadBalancer would publish the admin listener." (int .Values.tunnel.service.port) (int .Values.ports.admin)) -}}
{{- end -}}
{{- if not (has .Values.tunnel.service.type (list "LoadBalancer" "NodePort" "ClusterIP")) -}}
{{- fail (printf "prometheus-mcp-hub: tunnel.service.type must be LoadBalancer, NodePort or ClusterIP, got %q." .Values.tunnel.service.type) -}}
{{- end -}}
{{- end -}}

{{/* ---- state backend ---- */}}
{{- if not (has .Values.state.backend (list "secret" "file")) -}}
{{- fail (printf "prometheus-mcp-hub: state.backend must be \"secret\" or \"file\", got %q." .Values.state.backend) -}}
{{- end -}}
{{- if eq .Values.state.backend "secret" -}}
{{- if not .Values.serviceAccount.automountServiceAccountToken -}}
{{- fail "prometheus-mcp-hub: state.backend is \"secret\" but serviceAccount.automountServiceAccountToken is false. The hub reads and writes its own state Secret through the Kubernetes API and needs the projected token." -}}
{{- end -}}
{{- if and (not .Values.rbac.create) (not .Values.serviceAccount.name) -}}
{{- fail "prometheus-mcp-hub: state.backend is \"secret\" with rbac.create=false. Grant get,create,update on the state Secret yourself and set serviceAccount.name to the account that holds it, or set rbac.create=true." -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.state.backend "file" -}}
{{- if not .Values.state.file -}}
{{- fail "prometheus-mcp-hub: state.backend is \"file\" but state.file is empty." -}}
{{- end -}}
{{- end -}}

{{/* ---- bootstrap material ---- */}}
{{- if and .Values.bootstrap.caCertKey (not .Values.bootstrap.caKeyKey) -}}
{{- fail "prometheus-mcp-hub: bootstrap.caCertKey is set without bootstrap.caKeyKey; a certificate without its key cannot issue." -}}
{{- end -}}
{{- if and .Values.bootstrap.caKeyKey (not .Values.bootstrap.caCertKey) -}}
{{- fail "prometheus-mcp-hub: bootstrap.caKeyKey is set without bootstrap.caCertKey." -}}
{{- end -}}
{{- if and (not .Values.bootstrap.existingSecret) (or .Values.bootstrap.pepperKey .Values.bootstrap.caCertKey .Values.bootstrap.caKeyKey) -}}
{{- fail "prometheus-mcp-hub: bootstrap.*Key is set but bootstrap.existingSecret is empty." -}}
{{- end -}}

{{/* ---- disruption budget ---- */}}
{{- if and .Values.podDisruptionBudget.minAvailable .Values.podDisruptionBudget.maxUnavailable -}}
{{- fail "prometheus-mcp-hub: podDisruptionBudget.minAvailable and podDisruptionBudget.maxUnavailable are mutually exclusive." -}}
{{- end -}}

{{/* ---- shutdown budget must fit the grace period ---- */}}
{{- if .Values.tracing.enabled -}}
{{- if not .Values.tracing.endpoint -}}
{{- fail "prometheus-mcp-hub: tracing.enabled is true but tracing.endpoint is empty." -}}
{{- end -}}
{{- end -}}

{{/* ---- auto update ---- */}}
{{- if .Values.autoUpdate.enabled -}}
{{- if not (has .Values.autoUpdate.cohort (list "canary" "early" "stable")) -}}
{{- fail (printf "prometheus-mcp-hub: autoUpdate.cohort must be canary, early or stable, got %q." .Values.autoUpdate.cohort) -}}
{{- end -}}
{{- if not .Values.autoUpdate.certificateIdentityRegexp -}}
{{- fail "prometheus-mcp-hub: autoUpdate.certificateIdentityRegexp is empty. An unpinned signer identity makes cosign verification meaningless." -}}
{{- end -}}
{{- if eq .Values.autoUpdate.certificateIdentityRegexp ".*" -}}
{{- fail "prometheus-mcp-hub: autoUpdate.certificateIdentityRegexp is \".*\", which accepts any signer." -}}
{{- end -}}
{{- if not .Values.autoUpdate.certificateOidcIssuer -}}
{{- fail "prometheus-mcp-hub: autoUpdate.certificateOidcIssuer is empty." -}}
{{- end -}}
{{- if not .Values.autoUpdate.channelTag -}}
{{- fail "prometheus-mcp-hub: autoUpdate.channelTag is empty; there is nothing to resolve to a digest." -}}
{{- end -}}
{{- end -}}

{{/* ---- closed enums the binary itself rejects at startup ---- */}}
{{- if not (has .Values.config.logLevel (list "debug" "info" "warn" "error")) -}}
{{- fail (printf "prometheus-mcp-hub: config.logLevel must be debug, info, warn or error, got %q." .Values.config.logLevel) -}}
{{- end -}}
{{- if not (has .Values.config.logFormat (list "json" "text")) -}}
{{- fail (printf "prometheus-mcp-hub: config.logFormat must be json or text, got %q." .Values.config.logFormat) -}}
{{- end -}}
{{- if not (has .Values.service.sessionAffinity (list "None" "ClientIP")) -}}
{{- fail (printf "prometheus-mcp-hub: service.sessionAffinity must be None or ClientIP, got %q." .Values.service.sessionAffinity) -}}
{{- end -}}
{{- if .Values.ingress.enabled -}}
{{- if not (has .Values.ingress.pathType (list "Prefix" "Exact" "ImplementationSpecific")) -}}
{{- fail (printf "prometheus-mcp-hub: ingress.pathType must be Prefix, Exact or ImplementationSpecific, got %q." .Values.ingress.pathType) -}}
{{- end -}}
{{- end -}}

{{/*
---- the only writable path is the /tmp emptyDir ----
PMF_DATA_DIR is where the hub self-generates the pepper and materialises CA
material. With readOnlyRootFilesystem: true anything outside /tmp fails at
first write, which surfaces as a CrashLoopBackOff several minutes into an
install rather than as a render error here.
*/}}
{{- if and .Values.containerSecurityContext.readOnlyRootFilesystem (not (hasPrefix "/tmp" .Values.config.dataDir)) (not .Values.extraVolumeMounts) -}}
{{- fail (printf "prometheus-mcp-hub: config.dataDir is %q but containerSecurityContext.readOnlyRootFilesystem is true and no extraVolumeMounts make that path writable. Keep it under /tmp (the emptyDir this chart always mounts) or mount a writable volume there yourself." .Values.config.dataDir) -}}
{{- end -}}

{{- end -}}
