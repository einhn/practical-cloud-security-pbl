#!/usr/bin/env bash
# Scenario abnormal_3: attack. Probes sensitive ports (22, 443, 2379, 10250, 3306, 6379) on several targets.
# Safe simulation: no malware, scanner, miner or real C2 is executed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"
BACKEND="$(ready_pod "${NS}" app=backend)"
DB="$(ready_pod "${NS}" app=db)"
TARGETS=(
  backend
  db
  "$(kubectl -n "${NS}" get pod "${BACKEND}" -o jsonpath='{.status.podIP}')"
  "$(kubectl -n "${NS}" get pod "${DB}" -o jsonpath='{.status.podIP}')"
)
while IFS= read -r node_ip; do
  [[ -n "${node_ip}" ]] && TARGETS+=("${node_ip}")
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
PORTS=(22 443 2379 10250 3306 6379)

echo "[abnormal_3] Multi-target, multi-port probing."
for target in "${TARGETS[@]}"; do
  for port in "${PORTS[@]}"; do
    echo "probe target=${target} port=${port}"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${target}" "${port}" >/dev/null 2>&1 || true
  done
done
echo "Probing completed; inspect destination and port fan-out in Hubble."
