#!/usr/bin/env bash

# Select the newest Running Pod that is not being deleted, then wait until it
# is Ready. A phase-only selector can still return a terminating Pod during a
# rolling update, which made a few evaluation runs exit with code 137.
ready_pod() {
  local namespace="$1"
  local selector="$2"
  local pod

  pod="$(kubectl -n "${namespace}" get pods -l "${selector}" \
    --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{"\t"}{.metadata.name}{"\t"}{.metadata.deletionTimestamp}{"\n"}{end}' \
    | awk 'NF == 2 { print $1 "\t" $2 }' \
    | sort \
    | tail -n 1 \
    | cut -f 2)"

  if [[ -z "${pod}" ]]; then
    echo "No non-terminating Running Pod matched ${namespace}/${selector}" >&2
    return 1
  fi

  kubectl -n "${namespace}" wait --for=condition=Ready "pod/${pod}" --timeout=60s >/dev/null
  printf '%s\n' "${pod}"
}
