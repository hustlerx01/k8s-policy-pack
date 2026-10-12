package main
import rego.v1

good := {"kind": "Pod", "metadata": {"name": "g"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{
	"name": "c", "image": "nginx:1.27",
	"resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}},
	"securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}},
}]}}

with_container(patch) := object.union(good, {"spec": {"containers": [object.union(good.spec.containers[0], patch)]}})

test_good_pod_clean if count(deny) == 0 with input as good

test_good_deployment_clean if {
	count(deny) == 0 with input as {"kind": "Deployment", "metadata": {"name": "d"}, "spec": {"template": {"spec": good.spec}}}
}

test_privileged if count(deny) == 1 with input as with_container({"securityContext": {"privileged": true, "allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}})

test_latest if count(deny) == 1 with input as with_container({"image": "nginx:latest"})

test_untagged if count(deny) == 1 with input as with_container({"image": "nginx"})

test_registry_port_untagged if count(deny) == 1 with input as with_container({"image": "localhost:5000/app"})

test_digest_ok if count(deny) == 0 with input as with_container({"image": "nginx@sha256:abc"})

test_hostpath_hostnetwork if {
	count(deny) == 2 with input as object.union(good, {"spec": {"hostNetwork": true, "volumes": [{"name": "r", "hostPath": {"path": "/"}}]}})
}

test_root if {
	count(deny) == 1 with input as object.union(good, {"spec": {"securityContext": {"runAsNonRoot": false}}})
}
