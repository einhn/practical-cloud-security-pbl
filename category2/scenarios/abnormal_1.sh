#!/usr/bin/env bash
# Scenario abnormal_1: attack. frontend connects directly to db, outside the declared service graph.
# Safe simulation: no malware, scanner, miner or real C2 is executed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[abnormal_1] frontend -> db, a service outside the normal path."
if kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 3 http://db; then
  echo "Unexpected success: NetworkPolicy did not block frontend -> db." >&2
  exit 1
fi
echo "Blocked as expected; inspect the new destination in Hubble."
