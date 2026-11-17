#!/usr/bin/env bash
set -euo pipefail

TETRAGON_VERSION="${TETRAGON_VERSION:-1.8.0}"

helm repo add cilium https://helm.cilium.io --force-update
helm repo update
helm upgrade --install tetragon cilium/tetragon \
  --version "${TETRAGON_VERSION}" \
  --namespace kube-system \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --wait \
  --timeout 4m

kubectl rollout status --namespace kube-system daemonset/tetragon --timeout=180s
kubectl apply -f "$(dirname "$0")/../manifests/tetragon-tcp-connect.yaml"

echo "Tetragon ${TETRAGON_VERSION} is running; pbl-security tcp_connect monitoring is enabled."
