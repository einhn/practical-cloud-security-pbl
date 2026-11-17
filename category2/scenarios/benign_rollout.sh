#!/usr/bin/env bash
# Scenario benign_rollout: benign. Rolling restart of frontend, then a request on the declared edge.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"

echo "[benign_rollout] Restart frontend and verify the declared service path."
kubectl -n "${NS}" rollout restart deployment/frontend >/dev/null
kubectl -n "${NS}" rollout status deployment/frontend --timeout=180s >/dev/null

FRONTEND="$(ready_pod "${NS}" app=frontend)"
kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- \
  wget -qO- -T 5 http://backend >/dev/null

echo "Rolling-update traffic completed on the normal frontend -> backend edge."
