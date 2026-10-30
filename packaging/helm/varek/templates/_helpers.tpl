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

{{/* v1.36 step 4 (D1): warden-secrets' configuration from the credentials
  values, key = value lines, or "" when no vault: or aws-sm: store is
  configured (file: stores need none); step 6 (D5): and the CA its token
  issuers are verified with */}}
{{- define "varek.secretsConf" -}}
{{- $c := .Values.credentials -}}
{{- if and (or $c.vault.caSecret $c.vault.kubernetesAuth.role) (not $c.vault.addr) }}
{{- fail "credentials.vault: caSecret and kubernetesAuth.role need vault.addr" }}
{{- end }}
{{- if $c.vault.addr }}
vault_addr = {{ $c.vault.addr }}
{{- if $c.vault.caSecret }}
vault_ca = /etc/varek/vault-ca/ca.crt
{{- end }}
{{- if $c.vault.kubernetesAuth.role }}
vault_k8s_role = {{ $c.vault.kubernetesAuth.role }}
vault_k8s_jwt_file = /var/run/varek/tokens/vault/token
vault_k8s_mount = {{ $c.vault.kubernetesAuth.mount }}
{{- end }}
{{- end }}
{{- if $c.aws.region }}
aws_region = {{ $c.aws.region }}
{{- end }}
{{- if and $c.aws.roleArn $c.aws.podIdentity }}
{{- fail "credentials.aws: give roleArn (IRSA) or podIdentity, not both" }}
{{- end }}
{{- if $c.aws.roleArn }}
aws_role_arn = {{ $c.aws.roleArn }}
aws_web_identity_token_file = /var/run/varek/tokens/aws/token
{{- end }}
{{- if $c.aws.podIdentity }}
aws_container_credentials_uri = http://169.254.170.23/v1/credentials
aws_container_token_file = /var/run/varek/tokens/aws/token
{{- end }}
{{- if .Values.onBehalfOf.issuerCaConfigMap }}
oidc_ca = /etc/varek/issuer-ca/ca.crt
{{- end }}
{{- end -}}

{{/* v1.36 step 11 (review): what the chart's values must hold, failed at
  render, not found on the node. The node's key's directory and its public
  key's are apart, each apart from every other directory a container of the
  DaemonSet mounts (a key under the streams' directory would be the
  exporter's to read); the credentials' directory apart from the node agent's
  other mounts; a stream's segment 0 (none) or 65536 bytes or more, as the
  Warden takes it. */}}
{{- define "varek.validate" -}}
{{- $n := .Values.node -}}
{{- $dirs := dict "node.policies" $n.policies "node.streams" $n.streams "node.socket" $n.socket "node.bin" $n.bin "node.control" $n.control "node.exportState" $n.exportState "node.kubelet" $n.kubelet "flowPolicy.stateDir" .Values.flowPolicy.stateDir "credentials.dir" .Values.credentials.dir -}}
{{- if and (not .Values.signing.secretName) .Values.signing.nodeKey.enabled -}}
{{- $_ := set $dirs "signing.nodeKey.dir" .Values.signing.nodeKey.dir -}}
{{- $_ := set $dirs "signing.nodeKey.pubDir" .Values.signing.nodeKey.pubDir -}}
{{- end -}}
{{- range $a, $pa := $dirs -}}
{{- if not (and (kindIs "string" $pa) (hasPrefix "/" $pa) (not (contains "/../" (printf "%s/" $pa)))) -}}
{{- fail (printf "%s: an absolute path, with no .. (it is %v)" $a $pa) -}}
{{- end -}}
{{- range $b, $pb := $dirs -}}
{{- if and (lt $a $b) (or (eq (trimSuffix "/" $pa) (trimSuffix "/" $pb)) (hasPrefix (printf "%s/" (trimSuffix "/" $pa)) $pb) (hasPrefix (printf "%s/" (trimSuffix "/" $pb)) $pa)) -}}
{{- fail (printf "%s (%s) and %s (%s): each a directory of its own, neither in the other" $a $pa $b $pb) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- /* the CRDs, the varek-crds chart's: checked where the chart is
  installed on a cluster (lookup sees one, by the namespace's default service
  account, which a namespaced installer may read; helm template sees none) */ -}}
{{- if and .Values.crds.check (lookup "v1" "ServiceAccount" .Release.Namespace "default") -}}
{{- range $k := list "VarekPolicy" "VarekPlan" "VarekCredential" "VarekNodeKey" -}}
{{- if not ($.Capabilities.APIVersions.Has (printf "varek.dev/v1alpha1/%s" $k)) -}}
{{- fail (printf "the cluster has no %s: install the varek-crds chart first (helm install varek-crds oci://ghcr.io/kwdoug63/charts/varek-crds; packaging/helm/varek-crds/README.md)" $k) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $r := .Values.streams.rotateBytes -}}
{{- if not (and (kindIs "float64" $r | or (kindIs "int" $r) (kindIs "int64" $r)) (eq (float64 $r) (float64 (int64 $r))) (or (eq (int64 $r) 0) (ge (int64 $r) 65536))) -}}
{{- fail (printf "streams.rotateBytes: 0 (no rotation) or a whole number of bytes, 65536 or more (it is %v)" $r) -}}
{{- end -}}
{{- end -}}
