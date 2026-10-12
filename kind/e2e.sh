#!/usr/bin/env bash
# Live admission test on kind. NOT RUN on the authoring box (no Docker). Runs in CI job `kind-e2e`.
set -euo pipefail; cd "$(dirname "$0")/.."
kind create cluster --name policy-pack --wait 120s
helm repo add kyverno https://kyverno.github.io/kyverno/ && helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --wait
kubectl apply -f kyverno/ && sleep 10
kubectl create ns app
kubectl apply -f tests/resources/good.yaml                       # must be admitted
fails=0
for n in $(python3 -c "import yaml;print(' '.join(d['metadata']['name'] for d in yaml.safe_load_all(open('tests/resources/bad.yaml'))))"); do
  python3 -c "import yaml,sys;[print(yaml.safe_dump(d)) for d in yaml.safe_load_all(open('tests/resources/bad.yaml')) if d['metadata']['name']=='$n']" > /tmp/$n.yaml
  if kubectl apply -f /tmp/$n.yaml 2>/dev/null; then echo "NOT BLOCKED: $n"; fails=$((fails+1)); else echo "blocked: $n"; fi
done
kind delete cluster --name policy-pack
exit $fails
