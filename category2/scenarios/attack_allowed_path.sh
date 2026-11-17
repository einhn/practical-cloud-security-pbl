#!/usr/bin/env bash
# Scenario attack_allowed_path: attack, invisible at L3/L4. A credential-read HTTP request marker on the allowed frontend->backend:80 edge.
# Safe simulation: no malware, scanner, miner or real C2 is executed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[attack_allowed_path] Simulate an application-layer action on an allowed edge."
kubectl -n "${NS}" exec -c curl-client "${FRONTEND}" -- \
  curl -sS -o /dev/null \
  -H 'X-PBL-Simulated-Action: credential-read' \
  http://backend/pbl/simulated-credential-read

echo "No credential access occurs. L3/L4 sees only an allowed edge; optional Cilium L7 visibility records the HTTP path."
