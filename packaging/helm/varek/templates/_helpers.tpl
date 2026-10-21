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

{{/* The DNS server the node agent resolves policies' names through: the
  value given, or the cluster's DNS service's address where the chart can
  look it up (helm install; helm template sees no cluster), or none ("none":
  the pod's, which the webhook keeps to the cluster's) */}}
{{- define "varek.dnsServer" -}}
{{- $v := .Values.node.dnsServer -}}
{{- if eq $v "none" -}}
{{- else if $v -}}{{ $v }}
{{- else -}}
{{- $svc := lookup "v1" "Service" "kube-system" "kube-dns" -}}
{{- if not $svc }}{{ $svc = lookup "v1" "Service" "openshift-dns" "dns-default" }}{{ end -}}
{{- if and $svc $svc.spec $svc.spec.clusterIP (ne $svc.spec.clusterIP "None") (regexMatch "^[0-9.]+$" $svc.spec.clusterIP) -}}
{{ $svc.spec.clusterIP }}:53
{{- end -}}
{{- end -}}
{{- end -}}
