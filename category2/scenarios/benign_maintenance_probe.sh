#!/usr/bin/env bash
# Scenario benign_maintenance_probe: benign, identical to abnormal_1 at L3/L4. An operator's pre-approved check that frontend cannot reach db.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[benign_maintenance_probe] Authorized operator checks frontend -> db reachability."
if kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- \
  wget -qO- -T 3 http://db; then
  echo "Unexpected success: the policy should still block this maintenance probe." >&2
  exit 1
fi

echo "The probe was authorized but is indistinguishable from abnormal_1 at L3/L4."
