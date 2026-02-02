{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "ncm-issuer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "helm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ncm-issuer.template.labels" -}}
app: {{template "ncm-issuer.name" .}}
{{- end -}}

{{- define "ncm-issuer.app" -}}
app: {{template "ncm-issuer.name" .}}
{{- end -}}

{{- define "ncm-issuer.release" -}}
release: {{ .Release.Name }}
{{- end -}}

{{/*
ncm-issuer.labels.standard prints the standard Helm labels.
The standard labels are frequently used in metadata.
*/}}
{{- define "ncm-issuer.labels.standard" -}}
app: {{template "ncm-issuer.name" .}}-app
chart: {{template "ncm-issuer.chartref" . }}
app.kubernetes.io/name: {{template "ncm-issuer.name" .}}-app
helm.sh/chart: {{template "ncm-issuer.chartref" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.Version }}
com.nokia.neo/commitId: "commitid"
{{- end -}}

{{- /*
ncm-issuer.chartref prints a chart name and version.
It does minimal escaping for use in Kubernetes labels.
*/ -}}
{{- define "ncm-issuer.chartref" -}}
  {{- replace "+" "_" .Chart.Version | printf "%s-%s" .Chart.Name -}}
{{- end -}}

{{/*
Return the cert-manager approver ClusterRole name in an upgrade-safe way.

ClusterRoleBinding.roleRef is immutable. Older chart versions (and/or manual installs)
may have created a ClusterRoleBinding with a different roleRef.name (e.g. the historical
trailing "v" typo). During helm upgrade we preserve the already-installed roleRef.name
when the binding exists to avoid "cannot change roleRef" failures.
*/}}
{{- define "ncm-issuer.certManagerRbac.roleName" -}}
{{- $default := .Values.certManagerRbac.role -}}
{{- $existingBinding := lookup "rbac.authorization.k8s.io/v1" "ClusterRoleBinding" "" .Values.certManagerRbac.binding -}}
{{- if $existingBinding -}}
{{- /* If present, prefer the immutable existing roleRef.name */ -}}
{{- $existingBinding.roleRef.name | default $default -}}
{{- else -}}
{{- $default -}}
{{- end -}}
{{- end -}}
