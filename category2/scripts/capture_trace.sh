#!/usr/bin/env bash
# Run one scenario and keep the full evidence chain for it:
# Hubble flows -> detector alerts -> Tetragon process attribution.
#
#   ./category2/scripts/capture_trace.sh category2/scenarios/abnormal_1.sh category2/results/runtime-trace/abnormal_1
#
# Requires `cilium hubble port-forward` (or a reachable Hubble Relay) and the
# Tetragon tcp_connect policy from install_tetragon.sh.
set -euo pipefail

SCENARIO="$1"
OUT="$2"
NS="${NS:-pbl-security}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "${OUT}"

START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
bash "${SCENARIO}" > "${OUT}/scenario.stdout.txt" 2>&1 || true
sleep 4
END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

hubble observe --namespace "${NS}" --since "${START}" --until "${END}" --output jsonpb > "${OUT}/hubble.jsonl"
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout \
  --since-time="${START}" --tail=-1 --max-log-requests=10 2>/dev/null \
  | grep "\"namespace\":\"${NS}\"" > "${OUT}/tetragon.jsonl" || true

python3 "${ROOT}/category2/detector/detect.py" "${OUT}/hubble.jsonl" --format json > "${OUT}/detector.json"
python3 "${ROOT}/category2/detector/runtime_join.py" "${OUT}/detector.json" "${OUT}/tetragon.jsonl" \
  > "${OUT}/runtime-attribution.json"

printf '{"scenario": "%s", "start": "%s", "end": "%s"}\n' "$(basename "${SCENARIO}")" "${START}" "${END}" > "${OUT}/window.json"
echo "trace written to ${OUT}"
