#!/usr/bin/env bash
# Scenario normal_burst: benign. Concurrent requests on the declared frontend->backend edge (load).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
REQUESTS="${REQUESTS:-40}"
CONCURRENCY="${CONCURRENCY:-8}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[normal_burst] ${REQUESTS} frontend -> backend requests, concurrency=${CONCURRENCY}"
seq "${REQUESTS}" | xargs -P "${CONCURRENCY}" -I{} \
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- \
  wget -qO- -T 5 http://backend >/dev/null

echo "A rate-only detector may alert here; the identity/service-graph detector should not."
