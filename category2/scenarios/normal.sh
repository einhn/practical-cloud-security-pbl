#!/usr/bin/env bash
# Scenario normal: benign. Declared service traffic: frontend->backend, backend->db, DNS, a local health check and one retry.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
ROUNDS="${ROUNDS:-3}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"
BACKEND="$(ready_pod "${NS}" app=backend)"

for i in $(seq 1 "${ROUNDS}"); do
  echo "[normal] round ${i}/${ROUNDS}: frontend -> backend"
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 5 http://backend

  echo "[normal] round ${i}/${ROUNDS}: backend -> db"
  kubectl -n "${NS}" exec "${BACKEND}" -- wget -qO- -T 5 http://db

  echo "[normal] round ${i}/${ROUNDS}: DNS and local health checks"
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nslookup backend.pbl-security.svc.cluster.local >/dev/null
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 5 http://127.0.0.1/ >/dev/null

  if ! kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 1 http://backend >/dev/null; then
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 5 http://backend >/dev/null
  fi
done

echo "Hubble: hubble observe --namespace ${NS} --since 10m --output compact"
