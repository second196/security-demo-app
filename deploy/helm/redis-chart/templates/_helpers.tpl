# Helm helpers template
{{/*
Expand the name of the chart.
*/}}
{{- define "redis-chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "redis-chart.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "redis-chart.labels" -}}
helm.sh/chart: {{ include "redis-chart.name" . }}
{{ include "redis-chart.selectorLabels" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "redis-chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "redis-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "redis-chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "redis-chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
