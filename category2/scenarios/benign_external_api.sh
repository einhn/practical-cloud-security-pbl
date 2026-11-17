#!/usr/bin/env bash
# Scenario benign_external_api: benign. Request-driven calls to the declared external API with irregular, exponential gaps.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
REQUESTS="${REQUESTS:-8}"
MEAN_GAP="${MEAN_GAP:-4}"
TARGET="${TARGET:-http://ext-api.pbl-egress-sim.svc.cluster.local/v1/quote}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[benign_external_api] ${REQUESTS} user-driven API calls, mean gap ${MEAN_GAP}s."
kubectl -n "${NS}" exec -c curl-client "${FRONTEND}" -- sh -c '
  n="$1"; mean="$2"; url="$3"
  gaps="$(awk -v n="$n" -v m="$mean" "BEGIN{srand(); for(i=1;i<n;i++){g=-m*log(1-rand()); if(g<0.3)g=0.3; if(g>12)g=12; printf \"%.3f \", g}}")"
  for s in $gaps; do
    curl -s -o /dev/null -m 2 "$url" || true
    echo "api gap=${s}s"
    sleep "$s"
  done
  curl -s -o /dev/null -m 2 "$url" || true
' sh "${REQUESTS}" "${MEAN_GAP}" "${TARGET}"
echo "API calls completed on the same declared edge as abnormal_5."
