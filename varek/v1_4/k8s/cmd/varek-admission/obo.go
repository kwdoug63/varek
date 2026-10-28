// SPDX-License-Identifier: MIT
//
// v1.36 step 6 (docs/security/v1.36-kubernetes-parity.md, D5): a pod acting
// for a user. It names the Secret its user's token is in (key token) with
// the annotation varek.dev/on-behalf-of: SECRET. The node agent reads the
// token from the kubelet's copy of a Secret volume of the pod, varek-obo,
// which no container of the agent's mounts: the kubelet mounts no volume no
// container names (M2b), so an init container of the webhook's names it and
// runs /bin/true, from the node image.
//
//	/pod-mutate  (a MutatingWebhookConfiguration's) a pod created with
//	             varek.dev/policy and varek.dev/on-behalf-of is given the
//	             volume and the init container, unless it has them as the
//	             webhook gives them; one of their names otherwise is refused;
//	/pod         and the validating hook holds the pod to them: the volume,
//	             of that Secret, its key token alone; the init container as
//	             given (its command, its image, no environment, read-only
//	             mounts, no privilege, the runtime's default seccomp profile:
//	             the NRI plugin lets it through as it is, since it runs no
//	             agent); no other container mounting the volume (an
//	             ephemeral one added later neither); and a policy that says
//	             `require on-behalf-of` under a pod naming no Secret refused.
//	             On an update, the annotation is fixed as the policy's is.
package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

const (
	oboAnnotation = "varek.dev/on-behalf-of"
	oboName       = "varek-obo" // the volume, and the init container
	oboKey        = "token"
	oboMount      = "/var/run/varek-obo"
	oboCommand    = "/bin/true"
	oboNobody     = 65534
)

// a Secret's name (a DNS subdomain), as the NRI plugin and the node agent take it
var secretName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// `require on-behalf-of` (the Warden splits a line on the same white space)
var requireOBO = regexp.MustCompile(`(?m)^[ \t\r\v\f]*require[ \t\r\v\f]+on-behalf-of[ \t\r\v\f]*(#.*)?$`)

// the pod's parts the volume and the init container are checked in, as
// they are: a field the webhook does not know is one it refuses
type rawPod struct {
	Spec struct {
		Volumes        []map[string]json.RawMessage `json:"volumes"`
		InitContainers []map[string]json.RawMessage `json:"initContainers"`
	} `json:"spec"`
}

type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func (s *server) oboVolume(secret string) map[string]interface{} {
	return map[string]interface{}{"name": oboName, "secret": map[string]interface{}{
		"secretName": secret, "items": []interface{}{map[string]interface{}{"key": oboKey, "path": oboKey}},
		"defaultMode": 0o400}}
}

func (s *server) oboContainer() map[string]interface{} {
	sc := map[string]interface{}{"runAsNonRoot": true, "allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true, "capabilities": map[string]interface{}{"drop": []string{"ALL"}},
		"seccompProfile": map[string]interface{}{"type": "RuntimeDefault"}}
	if s.oboUser > 0 { // else the platform's (OpenShift's restricted-v2 gives the namespace's)
		sc["runAsUser"], sc["runAsGroup"] = s.oboUser, s.oboUser
	}
	// IfNotPresent: the node image is the DaemonSet's, on every node already
	return map[string]interface{}{"name": oboName, "image": s.oboImage, "imagePullPolicy": "IfNotPresent", "command": []string{oboCommand},
		"volumeMounts":    []interface{}{map[string]interface{}{"name": oboName, "mountPath": oboMount, "readOnly": true}},
		"securityContext": sc,
		"resources": map[string]interface{}{"requests": map[string]string{"cpu": "1m", "memory": "4Mi"},
			"limits": map[string]string{"memory": "16Mi"}}}
}

// oboVolumeWhy: why the pod's varek-obo volume is not the webhook's for secret, or ""
func oboVolumeWhy(v map[string]json.RawMessage, secret string) string {
	bad := fmt.Sprintf("its volume %s is not the webhook's (a Secret volume of %s, its key %s alone)", oboName, secret, oboKey)
	for k := range v {
		if k != "name" && k != "secret" {
			return bad
		}
	}
	var sv struct {
		SecretName string `json:"secretName"`
		Items      []struct {
			Key  string `json:"key"`
			Path string `json:"path"`
			Mode *int32 `json:"mode"`
		} `json:"items"`
		DefaultMode *int32 `json:"defaultMode"`
		Optional    *bool  `json:"optional"`
	}
	if json.Unmarshal(v["secret"], &sv) != nil || sv.SecretName != secret || len(sv.Items) != 1 ||
		sv.Items[0].Key != oboKey || sv.Items[0].Path != oboKey || (sv.Optional != nil && *sv.Optional) {
		return bad
	}
	return ""
}

// the fields the init container may have: the webhook's, and the API
// server's defaults
var oboFields = map[string]bool{"name": true, "image": true, "command": true, "volumeMounts": true,
	"securityContext": true, "resources": true, "imagePullPolicy": true, "terminationMessagePath": true,
	"terminationMessagePolicy": true}

// oboContainerWhy: why the init container named varek-obo is not the webhook's, or ""
func (s *server) oboContainerWhy(c map[string]json.RawMessage, pc *secCtx) string {
	why := func(f string, a ...interface{}) string {
		return fmt.Sprintf("its init container %s is not the webhook's: ", oboName) + fmt.Sprintf(f, a...)
	}
	for k := range c {
		if !oboFields[k] {
			return why("it has %s", k)
		}
	}
	var k struct {
		Image        string   `json:"image"`
		Command      []string `json:"command"`
		VolumeMounts []struct {
			Name             string  `json:"name"`
			MountPath        string  `json:"mountPath"`
			ReadOnly         bool    `json:"readOnly"`
			SubPath          string  `json:"subPath"`
			SubPathExpr      string  `json:"subPathExpr"`
			MountPropagation *string `json:"mountPropagation"`
		} `json:"volumeMounts"`
		SecurityContext *secCtx `json:"securityContext"`
	}
	raw, _ := json.Marshal(c)
	if err := json.Unmarshal(raw, &k); err != nil {
		return why("%v", err)
	}
	if !reflect.DeepEqual(k.Command, []string{oboCommand}) {
		return why("its command is not %s", oboCommand)
	}
	if s.oboImage != "" && k.Image != s.oboImage {
		return why("its image is not %s (the node image)", s.oboImage)
	}
	mounted := false
	for _, m := range k.VolumeMounts {
		if !m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" || (m.MountPropagation != nil && *m.MountPropagation != "None") {
			return why("its mount of %s is not read-only and plain", m.Name)
		}
		mounted = mounted || (m.Name == oboName && m.MountPath == oboMount)
	}
	if !mounted {
		return why("it does not mount %s at %s", oboName, oboMount)
	}
	cc := k.SecurityContext
	user := pick(cc, pc, func(x *secCtx) *int64 { return x.RunAsUser })
	group := pick(cc, pc, func(x *secCtx) *int64 { return x.RunAsGroup })
	if cc == nil || cc.AllowPrivilegeEscalation == nil || *cc.AllowPrivilegeEscalation ||
		(cc.Privileged != nil && *cc.Privileged) || cc.Capabilities == nil || !dropsAll(cc.Capabilities.Drop) ||
		len(cc.Capabilities.Add) > 0 || cc.RunAsNonRoot == nil || !*cc.RunAsNonRoot ||
		(user != nil && *user == 0) || (group != nil && *group == 0) ||
		cc.ReadOnlyRootFilesystem == nil || !*cc.ReadOnlyRootFilesystem ||
		cc.SeccompProfile == nil || cc.SeccompProfile.Type != "RuntimeDefault" {
		return why("its securityContext is not the webhook's (not root, no privilege, every capability dropped, a " +
			"read-only root, the runtime's default seccomp profile)")
	}
	return ""
}

// mutate: the pod's patch, or why it is refused
func (s *server) mutate(req *request) ([]patchOp, string) {
	if req.Operation != "CREATE" {
		return nil, ""
	}
	var p pod
	var r rawPod
	if err := json.Unmarshal(req.Object, &p); err != nil {
		return nil, "the pod does not read: " + err.Error()
	}
	if err := json.Unmarshal(req.Object, &r); err != nil {
		return nil, "the pod does not read: " + err.Error()
	}
	secret, acting := p.Metadata.Annotations[oboAnnotation]
	if _, ok := p.Metadata.Annotations[annotation]; !ok || !acting {
		return nil, ""
	}
	if !secretName.MatchString(secret) {
		return nil, fmt.Sprintf("its %s %q is not a Secret's name", oboAnnotation, secret)
	}
	if s.oboImage == "" {
		return nil, fmt.Sprintf("it acts for a user (%s), and the webhook was given no image for the init container "+
			"that mounts the token's volume (-obo-image)", oboAnnotation)
	}
	var ops []patchOp
	have := false
	for _, v := range r.Spec.Volumes {
		var n string
		json.Unmarshal(v["name"], &n)
		if n == oboName {
			if why := oboVolumeWhy(v, secret); why != "" {
				return nil, why
			}
			have = true
		}
	}
	if !have {
		if r.Spec.Volumes == nil {
			ops = append(ops, patchOp{"add", "/spec/volumes", []interface{}{s.oboVolume(secret)}})
		} else {
			ops = append(ops, patchOp{"add", "/spec/volumes/-", s.oboVolume(secret)})
		}
	}
	have = false
	for _, c := range r.Spec.InitContainers {
		var n string
		json.Unmarshal(c["name"], &n)
		if n == oboName {
			if why := s.oboContainerWhy(c, p.Spec.SecurityContext); why != "" {
				return nil, why
			}
			have = true
		}
	}
	for _, c := range p.Spec.Containers {
		if c.Name == oboName {
			return nil, fmt.Sprintf("its container %s: the name is the webhook's init container's", oboName)
		}
	}
	if !have {
		if r.Spec.InitContainers == nil {
			ops = append(ops, patchOp{"add", "/spec/initContainers", []interface{}{s.oboContainer()}})
		} else {
			ops = append(ops, patchOp{"add", "/spec/initContainers/0", s.oboContainer()})
		}
	}
	return ops, ""
}

// oboWhys: what refuses a pod acting for a user (secret its Secret), or
// one whose policy requires it and that does not; skip is the index of
// its init container among the pod's, then not checked as the agent's are
func (s *server) oboWhys(req *request, p *pod, policy string) (whys []string, skip int) {
	skip = -1
	secret, acting := p.Metadata.Annotations[oboAnnotation]
	if !acting {
		if requireOBO.MatchString(policy) {
			whys = append(whys, fmt.Sprintf("its policy says `require on-behalf-of`, and it names no user's token (%s: "+
				"the Secret it is in)", oboAnnotation))
		}
		return whys, skip
	}
	if !secretName.MatchString(secret) {
		return []string{fmt.Sprintf("its %s %q is not a Secret's name", oboAnnotation, secret)}, skip
	}
	var r rawPod
	if err := json.Unmarshal(req.Object, &r); err != nil {
		return []string{"the pod does not read: " + err.Error()}, skip
	}
	vols := 0
	for _, v := range r.Spec.Volumes {
		var n string
		json.Unmarshal(v["name"], &n)
		if n == oboName {
			vols++
			if why := oboVolumeWhy(v, secret); why != "" {
				whys = append(whys, why)
			}
		}
	}
	for i, c := range r.Spec.InitContainers {
		var n string
		json.Unmarshal(c["name"], &n)
		if n != oboName {
			continue
		}
		if why := s.oboContainerWhy(c, p.Spec.SecurityContext); why != "" {
			whys = append(whys, why)
		} else if skip < 0 {
			skip = i
		}
	}
	if vols != 1 || skip < 0 {
		whys = append(whys, fmt.Sprintf("it acts for a user (%s), and has not the token's volume and init container "+
			"(%s) once each as the webhook gives them (its mutating hook, %s)", oboAnnotation, oboName, "/pod-mutate"))
	}
	whys = append(whys, oboMounts(p, skip)...)
	return whys, skip
}

// oboMounts: the containers, but the init container at skip, that mount the
// token's volume (ephemeral ones too, for an update)
func oboMounts(p *pod, skip int) []string {
	var whys []string
	check := func(kind string, cs []container, skip int) {
		for i, c := range cs {
			if i == skip {
				continue
			}
			for _, m := range c.VolumeMounts {
				if m.Name == oboName {
					whys = append(whys, fmt.Sprintf("%scontainer %s mounts %s (the user's token is the node agent's to read, "+
						"not the agent's)", kind, c.Name, oboName))
				}
			}
		}
	}
	check("init ", p.Spec.InitContainers, skip)
	check("", p.Spec.Containers, -1)
	check("ephemeral ", p.Spec.EphemeralContainers, -1)
	return whys
}

// oboUpdate: on an update, the annotation fixed, and no container added that mounts the volume
func oboUpdate(p, old *pod) string {
	was, wasActing := old.Metadata.Annotations[oboAnnotation]
	if is, acting := p.Metadata.Annotations[oboAnnotation]; is != was || acting != wasActing {
		return fmt.Sprintf("its %s annotation is set when the pod is created, and not added, changed or removed after", oboAnnotation)
	}
	if !wasActing {
		return ""
	}
	var whys []string
	check := func(cs, olds []container) {
		seen := map[string]bool{}
		for _, c := range olds {
			seen[c.Name] = true
		}
		for _, c := range cs {
			if seen[c.Name] {
				continue
			}
			for _, m := range c.VolumeMounts {
				if m.Name == oboName {
					whys = append(whys, fmt.Sprintf("container %s, added, mounts %s (the user's token is the node agent's to read)", c.Name, oboName))
				}
			}
		}
	}
	check(p.Spec.EphemeralContainers, old.Spec.EphemeralContainers)
	return strings.Join(whys, "; ")
}
