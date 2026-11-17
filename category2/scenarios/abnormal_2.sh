#!/usr/bin/env bash
# Scenario abnormal_2: attack. Discovery burst across Pods, Services and nodes.
# Safe simulation: no malware, scanner, miner or real C2 is executed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"
BACKEND="$(ready_pod "${NS}" app=backend)"
DB="$(ready_pod "${NS}" app=db)"
TARGETS=(
  frontend
  backend
  db
  kubernetes.default.svc
  "$(kubectl -n "${NS}" get pod "${FRONTEND}" -o jsonpath='{.status.podIP}')"
  "$(kubectl -n "${NS}" get pod "${BACKEND}" -o jsonpath='{.status.podIP}')"
  "$(kubectl -n "${NS}" get pod "${DB}" -o jsonpath='{.status.podIP}')"
)
while IFS= read -r node_ip; do
  [[ -n "${node_ip}" ]] && TARGETS+=("${node_ip}")
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')

echo "[abnormal_2] Rapid discovery across Pods, Services, and nodes."
for round in 1 2; do
  for target in "${TARGETS[@]}"; do
    echo "round=${round} target=${target}:80"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${target}" 80 >/dev/null 2>&1 || true
  done
done
echo "Discovery burst completed; compare destination count and frequency in Hubble."
