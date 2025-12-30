{{/*
Expand the name of the chart.
*/}}
{{- define "jellyseerr-sso-bridge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "jellyseerr-sso-bridge.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "jellyseerr-sso-bridge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "jellyseerr-sso-bridge.labels" -}}
helm.sh/chart: {{ include "jellyseerr-sso-bridge.chart" . }}
{{ include "jellyseerr-sso-bridge.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "jellyseerr-sso-bridge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jellyseerr-sso-bridge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "jellyseerr-sso-bridge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "jellyseerr-sso-bridge.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name
*/}}
{{- define "jellyseerr-sso-bridge.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "jellyseerr-sso-bridge.fullname" . }}-secrets
{{- end }}
{{- end }}

{{/*
TLS secret name for ingress
*/}}
{{- define "jellyseerr-sso-bridge.tlsSecretName" -}}
{{- if .Values.ingress.tls.secretName }}
{{- .Values.ingress.tls.secretName }}
{{- else }}
{{- include "jellyseerr-sso-bridge.fullname" . }}-tls
{{- end }}
{{- end }}

