#!/usr/bin/env bash
# Scenario abnormal_5_beacon: attack. Fixed-period heartbeat to the declared external API, simulating a C2 beacon with a tiny HTTP GET.
# Safe simulation: no malware, scanner, miner or real C2 is executed.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/pod_helpers.sh"

NS="${NS:-pbl-security}"
BEACONS="${BEACONS:-8}"
INTERVAL="${INTERVAL:-4}"
JITTER="${JITTER:-0.1}"   # uniform +/- fraction of INTERVAL
TARGET="${TARGET:-http://ext-api.pbl-egress-sim.svc.cluster.local/hb/}"
FRONTEND="$(ready_pod "${NS}" app=frontend)"

echo "[abnormal_5_beacon] ${BEACONS} heartbeats every ${INTERVAL}s (jitter=${JITTER}) on the allowed frontend -> ext-api edge."
# One exec runs the whole loop inside the Pod so timing reflects the implant,
# not kubectl latency.
kubectl -n "${NS}" exec -c curl-client "${FRONTEND}" -- sh -c '
  n="$1"; base="$2"; jitter="$3"; url="$4"
  gaps="$(awk -v n="$n" -v b="$base" -v j="$jitter" "BEGIN{srand(); for(i=1;i<n;i++) printf \"%.3f \", b*(1+j*(2*rand()-1))}")"
  for s in $gaps; do
    curl -s -o /dev/null -m 2 "$url" || true
    echo "beacon gap=${s}s"
    sleep "$s"
  done
  curl -s -o /dev/null -m 2 "$url" || true
' sh "${BEACONS}" "${INTERVAL}" "${JITTER}" "${TARGET}"
echo "Heartbeat completed; every connection was FORWARDED on a declared edge."
