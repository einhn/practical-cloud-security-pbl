#!/usr/bin/env python3
"""Measure how many runs are indistinguishable at the L3/L4 evidence level.

Each valid run is reduced to a canonical observation: deduplicated
workload-level connection edges, verdicts, counts, deterministic alerts, and
telemetry health. Timestamps and ephemeral ports are dropped as run-specific
noise. When runs with different ground-truth labels share one canonical
observation, no classifier that sees only that observation can label all of
them correctly, so the minority labels give a lower bound on errors.

    python3 category2/analysis/observation_collisions.py <results/live-...> [--out boundary-summary.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

DETECTOR_DIR = Path(__file__).resolve().parents[1] / "detector"
sys.path.insert(0, str(DETECTOR_DIR))

import detect  # noqa: E402


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def canonical_observation(hubble_path: Path, policy: dict[str, Any], detector_result: dict[str, Any]) -> dict[str, Any]:
    """Keep what the detector can see and drop per-run noise."""
    with hubble_path.open(encoding="utf-8") as handle:
        flows, loss_markers, parse_errors = detect.parse_lines(handle)
    attempts = detect.deduplicate(
        [f for f in flows if detect._is_connection_attempt(f) and detect._source_is_monitored(f.source, policy)],
        int(policy["dedup_milliseconds"]),
    )
    edge_counts = Counter((f.source, f.destination, f.destination_port, f.protocol, f.verdict) for f in attempts)
    edges = [
        {"source": s, "destination": d, "port": p, "protocol": proto, "verdict": v, "attempts": n}
        for (s, d, p, proto, v), n in sorted(edge_counts.items())
    ]
    alerts = sorted(
        (
            {"rule_id": a["rule_id"], "severity": a["severity"], "source": a["source"], "evidence": a.get("evidence", {})}
            for a in detector_result.get("alerts", [])
        ),
        key=lambda item: (item["rule_id"], item["source"]),
    )
    return {
        "edges": edges,
        "alerts": alerts,
        "telemetry": {"loss_markers": loss_markers, "parse_errors": parse_errors},
    }


def collision_groups(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Group runs by canonical observation and keep groups with mixed labels."""
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_hash[record["observation_hash"]].append(record)
    groups, unavoidable = [], 0
    for observation_hash, members in sorted(by_hash.items()):
        labels = Counter(m["truth_role"] for m in members)
        if len(labels) < 2:
            continue
        minimum_errors = len(members) - max(labels.values())
        unavoidable += minimum_errors
        groups.append(
            {
                "observation_hash": observation_hash,
                "runs": len(members),
                "label_counts": dict(sorted(labels.items())),
                "minimum_errors": minimum_errors,
                "scenarios": sorted({m["scenario"] for m in members}),
                "has_alert": bool(members[0]["observation"]["alerts"]),
            }
        )
    return groups, unavoidable


def analyze(results_dir: Path, policy_path: Path) -> dict[str, Any]:
    summary = json.loads((results_dir / "summary.json").read_text(encoding="utf-8"))
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    records = []
    # Invalid runs (failed script, failed capture, telemetry loss) are not
    # observations of the scenario and are scored neither way.
    for run in (r for r in summary["runs"] if r.get("valid", True)):
        run_dir = results_dir / run["artifact_dir"]
        observation = canonical_observation(
            run_dir / "hubble.jsonl", policy, json.loads((run_dir / "detector.json").read_text(encoding="utf-8"))
        )
        records.append(
            {
                "observation_hash": stable_hash(observation),
                "observation": observation,
                "scenario": run["scenario"],
                "truth_role": run["truth_role"],
            }
        )
    groups, unavoidable = collision_groups(records)
    total = len(records)
    return {
        "source_results": results_dir.name,
        "runs": total,
        "distinct_observations": len({r["observation_hash"] for r in records}),
        "collision_groups": len(groups),
        "collision_runs": sum(g["runs"] for g in groups),
        "minimum_errors": unavoidable,
        "maximum_accuracy": round((total - unavoidable) / total, 4) if total else None,
        "groups": groups,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--policy", type=Path, default=DETECTOR_DIR / "policy.json")
    parser.add_argument("--out", type=Path, help="write the summary JSON here")
    args = parser.parse_args(argv)
    result = analyze(args.results_dir, args.policy)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
