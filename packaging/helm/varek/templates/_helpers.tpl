{{/* SPDX-License-Identifier: MIT */}}

{{- define "varek.labels" -}}
app.kubernetes.io/name: varek
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "varek.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
{{- end -}}

{{/* the runtime's state directory, where each container's bundle is */}}
{{- define "varek.state" -}}
{{- if eq .Values.runtime "containerd" -}}
{{ index .Values.node.state "containerd" }}
{{- else if eq .Values.runtime "cri-o" -}}
{{ index .Values.node.state "cri-o" }}
{{- else -}}
{{ fail (printf "runtime %q: give containerd or cri-o" .Values.runtime) }}
{{- end -}}
{{- end -}}

{{- define "varek.admissionName" -}}{{ .Release.Name }}-admission{{- end -}}
{{- define "varek.nodeName" -}}{{ .Release.Name }}-node{{- end -}}
