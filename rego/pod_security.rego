# Same 6 controls as kyverno/, as OPA Rego for conftest (CI-time, shift-left; also reusable in Gatekeeper with small changes).
package main
import rego.v1

pod_spec := input.spec if input.kind == "Pod"
pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers
containers contains c if some c in pod_spec.initContainers

name := sprintf("%s/%s", [input.kind, input.metadata.name])

deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("%s: container %q is privileged", [name, c.name])
}

deny contains msg if {
	not pod_spec.securityContext.runAsNonRoot == true
	some c in containers
	not c.securityContext.runAsNonRoot == true
	msg := sprintf("%s: container %q may run as root (set runAsNonRoot)", [name, c.name])
}

image_unpinned(img) if endswith(img, ":latest")
image_unpinned(img) if {
	not contains(img, "@sha256:")
	parts := split(img, "/")
	not contains(parts[count(parts) - 1], ":")
}

deny contains msg if {
	some c in containers
	image_unpinned(c.image)
	msg := sprintf("%s: container %q image %q is not pinned", [name, c.name, c.image])
}

deny contains msg if {
	some c in pod_spec.containers
	some f in ["requests.cpu", "requests.memory", "limits.memory"]
	p := split(f, ".")
	not c.resources[p[0]][p[1]]
	msg := sprintf("%s: container %q missing resources.%s", [name, c.name, f])
}

deny contains msg if {
	some k in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[k] == true
	msg := sprintf("%s: %s=true is not allowed", [name, k])
}

deny contains msg if {
	some v in pod_spec.volumes
	v.hostPath
	msg := sprintf("%s: hostPath volume %q is not allowed", [name, v.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s: container %q must set allowPrivilegeEscalation=false", [name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("%s: container %q must drop ALL capabilities", [name, c.name])
}
