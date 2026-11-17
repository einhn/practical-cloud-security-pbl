#!/usr/bin/env bash
# Scenario abnormal_4: attack. Connection attempts to cloud metadata addresses and IRC ports; no route exists, nothing is reached.
# Safe simulation: no malware, scanner, miner or real C2 is executed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[abnormal_4] Safe metadata/C2 egress simulation."
for target in 169.254.169.254 169.254.170.2 192.0.2.10; do
  for port in 80 443 6667 6697; do
    echo "probe target=${target} port=${port}"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- \
      nc -z -w 1 "${target}" "${port}" >/dev/null 2>&1 || true
  done
done

echo "The TEST-NET address is non-routable; NetworkPolicy should also block every attempt."
