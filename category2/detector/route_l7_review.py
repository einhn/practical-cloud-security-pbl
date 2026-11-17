#!/usr/bin/env python3
"""Route Hubble HTTP deviations to semantic review without declaring an attack."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from detect import _workload_name


def _identity(endpoint: dict[str, Any]) -> str:
    namespace = endpoint.get("namespace")
    workloads = endpoint.get("workloads") or []
    workload = workloads[0].get("name") if workloads else None
    pod = endpoint.get("pod_name") or endpoint.get("podName")
    if namespace and workload:
        return f"{namespace}/{workload}"
    if namespace and pod:
        return _workload_name(f"{namespace}/{pod}")
    return "unknown"


def _route_allowed(
    source: str, destination: str, method: str, path: str, policy: dict[str, Any]
) -> bool:
    for route in policy.get("allowed_http_routes", []):
        if route["source"] != source or route["destination"] != destination:
            continue
        if method not in {value.upper() for value in route.get("methods", [])}:
            continue
        if path in set(route.get("paths", [])):
            return True
    return False


def _safe_headers(headers: list[dict[str, str]], policy: dict[str, Any]) -> list[dict[str, str]]:
    redacted = {value.lower() for value in policy.get("redacted_header_names", [])}
    ignored = {value.lower() for value in policy.get("ignored_header_names", [])}
    result = []
    for header in headers:
        key = header.get("key", "")
        lowered = key.lower()
        if lowered in ignored:
            continue
        value = "[REDACTED]" if lowered in redacted else header.get("value", "")
        result.append({"key": key, "value": value})
    return result


def route(lines: Iterable[str], policy: dict[str, Any]) -> dict[str, Any]:
    parsed_requests = 0
    parse_errors = 0
    candidates = []
    for line in lines:
        if not line.strip():
            continue
        try:
            envelope = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        flow = envelope.get("flow", envelope)
        l7 = flow.get("l7") or {}
        http = l7.get("http") or {}
        if str(l7.get("type", "")).upper() != "REQUEST" or not http:
            continue
        parsed_requests += 1
        source = _identity(flow.get("source") or {})
        destination = _identity(flow.get("destination") or {})
        method = str(http.get("method", "UNKNOWN")).upper()
        url = str(http.get("url", ""))
        path = urlsplit(url).path or "/"
        if _route_allowed(source, destination, method, path, policy):
            continue
        evidence = {
            "time": flow.get("time"),
            "source": source,
            "destination": destination,
            "method": method,
            "path": path,
            "headers": _safe_headers(http.get("headers") or [], policy),
        }
        evidence_id = hashlib.sha256(
            json.dumps(evidence, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
        candidates.append(
            {
                "evidence_id": evidence_id,
                "reason": "http-route-outside-declared-baseline",
                "disposition": "semantic-review-required",
                "evidence": evidence,
            }
        )
    return {
        "summary": {
            "parsed_http_requests": parsed_requests,
            "parse_errors": parse_errors,
            "semantic_review_candidates": len(candidates),
        },
        "candidates": candidates,
        "warning": (
            "A route deviation is not proof of attack. Correlate it with application "
            "ownership, change approval, Kubernetes Audit, and runtime lineage."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Hubble jsonpb L7 JSONL")
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).with_name("l7_policy.json"),
    )
    args = parser.parse_args(argv)
    with args.policy.open(encoding="utf-8") as handle:
        policy = json.load(handle)
    with args.input.open(encoding="utf-8") as handle:
        result = route(handle, policy)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
