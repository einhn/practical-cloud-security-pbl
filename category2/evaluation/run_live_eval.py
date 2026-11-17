#!/usr/bin/env python3
"""Run randomized, repeated Category 2 experiments against live Hubble data.

Ground-truth labels are used only after the detector has produced its result.
Each run preserves raw Hubble JSONL, detector output, scenario output, timing,
and telemetry-quality metadata so missing observations are not scored as benign.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


CATEGORY_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = CATEGORY_DIR.parent
DETECTOR_DIR = CATEGORY_DIR / "detector"
SCENARIO_DIR = CATEGORY_DIR / "scenarios"
sys.path.insert(0, str(DETECTOR_DIR))

from detect import SEVERITY_ORDER, _load_policy, detect, parse_lines  # noqa: E402
from route_l7_review import route as route_l7  # noqa: E402


@dataclass(frozen=True)
class Scenario:
    id: str
    role: str
    script: Path
    description: str
    network_visible: bool
    expected_rules: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)


SCENARIOS = (
    Scenario(
        id="normal",
        role="benign",
        script=SCENARIO_DIR / "normal.sh",
        description="Declared frontend-to-backend and backend-to-db traffic, DNS, and health checks",
        network_visible=True,
        env={"ROUNDS": "2"},
    ),
    Scenario(
        id="normal_burst",
        role="benign",
        script=SCENARIO_DIR / "normal_burst.sh",
        description="Concurrent requests on the declared frontend-to-backend edge",
        network_visible=True,
        env={"REQUESTS": "24", "CONCURRENCY": "6"},
    ),
    Scenario(
        id="benign_rollout",
        role="benign",
        script=SCENARIO_DIR / "benign_rollout.sh",
        description="Rolling update changes Pod identity but preserves the service graph",
        network_visible=True,
    ),
    Scenario(
        id="benign_maintenance_probe",
        role="benign",
        script=SCENARIO_DIR / "benign_maintenance_probe.sh",
        description="Authorized troubleshooting probes a path outside the declared service graph",
        network_visible=True,
    ),
    Scenario(
        id="abnormal_1",
        role="attack",
        script=SCENARIO_DIR / "abnormal_1.sh",
        description="Frontend directly probes the database service",
        network_visible=True,
        expected_rules=("path-violation",),
    ),
    Scenario(
        id="abnormal_2",
        role="attack",
        script=SCENARIO_DIR / "abnormal_2.sh",
        description="Rapid destination fan-out across Pods and Services",
        network_visible=True,
        expected_rules=("destination-fanout",),
    ),
    Scenario(
        id="abnormal_3",
        role="attack",
        script=SCENARIO_DIR / "abnormal_3.sh",
        description="Multi-target probing of administrative and sensitive ports",
        network_visible=True,
        expected_rules=("port-sweep", "sensitive-service-probe"),
    ),
    Scenario(
        id="abnormal_4",
        role="attack",
        script=SCENARIO_DIR / "abnormal_4.sh",
        description="Safe cloud-metadata and IRC/C2 egress probes",
        network_visible=True,
        expected_rules=("cloud-metadata-access", "sensitive-service-probe"),
    ),
    Scenario(
        id="benign_external_api",
        role="benign",
        script=SCENARIO_DIR / "benign_external_api.sh",
        description="Request-driven calls with irregular gaps on the declared frontend-to-ext-api edge",
        network_visible=True,
    ),
    Scenario(
        id="abnormal_5_beacon",
        role="attack",
        script=SCENARIO_DIR / "abnormal_5_beacon.sh",
        description="Fixed-period implant heartbeat on the same declared egress edge",
        network_visible=True,
        expected_rules=("periodic-beacon",),
    ),
    Scenario(
        id="attack_allowed_path",
        role="attack",
        script=SCENARIO_DIR / "attack_allowed_path.sh",
        description="Application-layer abuse simulation on allowed frontend-to-backend TCP/80",
        network_visible=False,
    ),
)


def _run(
    command: list[str],
    *,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_DIR,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json_write(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    """Return a 95% Wilson score interval for a binomial proportion."""
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * ((proportion * (1 - proportion) / total + z * z / (4 * total * total)) ** 0.5)
        / denominator
    )
    return [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)]


def confusion(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    selected = [row for row in rows if row["valid"]]
    tp = sum(row["truth_role"] == "attack" and row["predicted_attack"] for row in selected)
    tn = sum(row["truth_role"] == "benign" and not row["predicted_attack"] for row in selected)
    fp = sum(row["truth_role"] == "benign" and row["predicted_attack"] for row in selected)
    fn = sum(row["truth_role"] == "attack" and not row["predicted_attack"] for row in selected)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "runs": len(selected),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "accuracy": _ratio(tp + tn, len(selected)),
        "confidence_intervals_95": {
            "precision": wilson_interval(tp, tp + fp),
            "recall": wilson_interval(tp, tp + fn),
            "specificity": wilson_interval(tn, tn + fp),
            "accuracy": wilson_interval(tp + tn, len(selected)),
        },
    }


def _command_version(command: list[str]) -> str:
    completed = _run(command, timeout=30)
    text = (completed.stdout or completed.stderr).strip()
    return text.splitlines()[0] if text else f"exit={completed.returncode}"


def _source_tree_sha256() -> str:
    digest = hashlib.sha256()
    candidates = [REPO_DIR / "install.sh"]
    candidates.extend((REPO_DIR / "workload").glob("*.yaml"))
    candidates.extend(SCENARIO_DIR.rglob("*.sh"))
    candidates.extend((CATEGORY_DIR / "manifests").glob("*.yaml"))
    candidates.extend(DETECTOR_DIR.glob("*.py"))
    candidates.extend(DETECTOR_DIR.glob("*.json"))
    candidates.extend((CATEGORY_DIR / "evaluation").glob("*.py"))
    for path in sorted({item.resolve() for item in candidates if item.is_file()}):
        relative = path.relative_to(REPO_DIR.resolve()).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def environment_snapshot(policy_path: Path) -> dict[str, Any]:
    policy_bytes = policy_path.read_bytes()
    commands = {
        "git_revision": ["git", "rev-parse", "HEAD"],
        "kind": ["kind", "version"],
        "kubectl": ["kubectl", "version", "--client"],
        "cilium_cli": ["cilium", "version", "--client"],
        "hubble": ["hubble", "version"],
    }
    snapshot = {name: _command_version(command) for name, command in commands.items()}
    snapshot["policy_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
    snapshot["source_tree_sha256"] = _source_tree_sha256()
    snapshot["git_status"] = _run(
        ["git", "status", "--short", "--untracked-files=all"], timeout=30
    ).stdout
    snapshot["nodes"] = _run(["kubectl", "get", "nodes", "-o", "wide"], timeout=30).stdout
    snapshot["pods"] = _run(
        ["kubectl", "get", "pods", "-n", "pbl-security", "-o", "wide"], timeout=30
    ).stdout
    return snapshot


def _hubble_ready() -> bool:
    return _run(["hubble", "status"], timeout=10).returncode == 0


def start_hubble_port_forward(log_path: Path) -> tuple[subprocess.Popen[str] | None, Any]:
    if _hubble_ready():
        return None, None
    stream = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        ["cilium", "hubble", "port-forward"],
        cwd=REPO_DIR,
        stdout=stream,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for _ in range(30):
        if process.poll() is not None:
            stream.flush()
            raise RuntimeError(f"Hubble port-forward exited early; inspect {log_path}")
        if _hubble_ready():
            return process, stream
        time.sleep(1)
    process.terminate()
    stream.close()
    raise RuntimeError("Hubble Relay did not become reachable within 30 seconds")


def collect_hubble(namespace: str, start: datetime, end: datetime) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "hubble",
            "observe",
            "--namespace",
            namespace,
            "--since",
            _rfc3339(start),
            "--until",
            _rfc3339(end),
            "--output",
            "jsonpb",
        ],
        timeout=120,
    )


def run_scenario(
    scenario: Scenario,
    *,
    repetition: int,
    sequence: int,
    namespace: str,
    minimum_severity: str,
    policy: dict[str, Any],
    run_root: Path,
    settle_seconds: float,
    l7_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    l7_policy = l7_policy or _load_policy(DETECTOR_DIR / "l7_policy.json")
    run_id = f"{sequence:03d}-{scenario.id}-r{repetition}"
    output_dir = run_root / "runs" / run_id
    output_dir.mkdir(parents=True)

    started = _utc_now()
    scenario_env = os.environ.copy()
    scenario_env.update(scenario.env)
    scenario_env["NS"] = namespace
    try:
        completed = _run(["bash", str(scenario.script)], timeout=240, env=scenario_env)
    except subprocess.TimeoutExpired as exc:
        completed = subprocess.CompletedProcess(
            args=exc.cmd,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\nscenario timed out",
        )
    scenario_ended = _utc_now()
    time.sleep(settle_seconds)
    capture_ended = _utc_now()
    capture = collect_hubble(namespace, started, capture_ended)

    (output_dir / "scenario.stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (output_dir / "scenario.stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (output_dir / "hubble.jsonl").write_text(capture.stdout, encoding="utf-8")
    (output_dir / "hubble.stderr.txt").write_text(capture.stderr, encoding="utf-8")

    flows, losses, parse_errors = parse_lines(capture.stdout.splitlines())
    result = detect(flows, policy, losses, parse_errors)
    detector_output = result.to_dict()
    _json_write(output_dir / "detector.json", detector_output)

    l7_result = route_l7(capture.stdout.splitlines(), l7_policy)
    _json_write(output_dir / "l7-review.json", l7_result)
    l7_candidates = l7_result["summary"]["semantic_review_candidates"]

    threshold = SEVERITY_ORDER[minimum_severity]
    selected_alerts = [
        alert for alert in result.alerts if SEVERITY_ORDER[alert.severity] >= threshold
    ]
    rules = sorted({alert.rule_id for alert in selected_alerts})
    valid = (
        completed.returncode == 0
        and capture.returncode == 0
        and result.parsed_flows > 0
        and result.telemetry_loss_markers == 0
    )
    predicted_attack = bool(selected_alerts) if valid else None
    # Tier 2: an L7 route deviation is routed to review, i.e. it raises a case.
    tiered_predicted_attack = (bool(selected_alerts) or l7_candidates > 0) if valid else None
    latency = None
    if selected_alerts:
        first_alert = min(alert.first_seen for alert in selected_alerts).replace(tzinfo=UTC)
        latency = round(max(0.0, (first_alert - started).total_seconds()), 3)

    row = {
        "run_id": run_id,
        "scenario": scenario.id,
        "repetition": repetition,
        "sequence": sequence,
        "truth_role": scenario.role,
        "network_visible": scenario.network_visible,
        "description": scenario.description,
        "expected_rules": list(scenario.expected_rules),
        "observed_rules": rules,
        "expected_rule_hits": sorted(set(scenario.expected_rules) & set(rules)),
        "predicted_attack": predicted_attack,
        "tiered_predicted_attack": tiered_predicted_attack,
        "l7_http_requests": l7_result["summary"]["parsed_http_requests"],
        "l7_review_candidates": l7_candidates,
        "valid": valid,
        "started_at": _rfc3339(started),
        "scenario_ended_at": _rfc3339(scenario_ended),
        "capture_ended_at": _rfc3339(capture_ended),
        "duration_seconds": round((scenario_ended - started).total_seconds(), 3),
        "detection_latency_seconds": latency,
        "script_exit": completed.returncode,
        "hubble_exit": capture.returncode,
        "parsed_flows": result.parsed_flows,
        "connection_attempts": result.connection_attempts,
        "telemetry_loss_markers": result.telemetry_loss_markers,
        "parse_errors": result.parse_errors,
        "alert_count": len(selected_alerts),
        "artifact_dir": str(output_dir.relative_to(run_root)),
    }
    _json_write(output_dir / "metadata.json", row)
    return row


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [row for row in rows if row["valid"]]
    visible = [
        row
        for row in valid
        if row["truth_role"] == "benign" or row["network_visible"]
    ]
    expected_total = sum(len(row["expected_rules"]) for row in valid)
    expected_hits = sum(len(row["expected_rule_hits"]) for row in valid)
    latencies = [
        row["detection_latency_seconds"]
        for row in valid
        if row["truth_role"] == "attack" and row["detection_latency_seconds"] is not None
    ]
    return {
        "requested_runs": len(rows),
        "valid_runs": len(valid),
        "invalid_runs": len(rows) - len(valid),
        "all_scenarios": confusion(valid),
        "network_visible_scenarios": confusion(visible),
        "tiered_l3l4_plus_l7_review": confusion(
            [
                {**row, "predicted_attack": row.get("tiered_predicted_attack", row["predicted_attack"])}
                for row in valid
            ]
        ),
        "expected_rule_coverage": _ratio(expected_hits, expected_total),
        "expected_rule_hits": expected_hits,
        "expected_rule_total": expected_total,
        "mean_detection_latency_seconds": (
            round(sum(latencies) / len(latencies), 3) if latencies else None
        ),
        "max_detection_latency_seconds": max(latencies) if latencies else None,
        "runs_with_telemetry_loss": sum(
            row["telemetry_loss_markers"] > 0 for row in rows
        ),
        "runs_with_parse_errors": sum(row["parse_errors"] > 0 for row in rows),
    }


def _fmt(value: Any) -> str:
    if value is None:
        return "N/A"
    return str(value)


def write_report(
    run_root: Path,
    rows: list[dict[str, Any]],
    summary: dict[str, Any],
    *,
    seed: int,
    repeats: int,
    minimum_severity: str,
) -> None:
    all_metrics = summary["all_scenarios"]
    visible_metrics = summary["network_visible_scenarios"]
    tiered_metrics = summary["tiered_l3l4_plus_l7_review"]
    lines = [
        "# Category 2 live evaluation",
        "",
        f"- seed: `{seed}`",
        f"- repetitions per scenario: `{repeats}`",
        f"- decision threshold: `{minimum_severity}`",
        f"- valid runs: `{summary['valid_runs']}/{summary['requested_runs']}`",
        "- detector input: Hubble JSONL only; scenario IDs and labels are applied after detection",
        "",
        "## Aggregate results",
        "",
        "| Scope | TP | TN | FP | FN | Precision | Recall | Specificity | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| All attacks, including the intentional L7 blind spot | {all_metrics['tp']} | "
            f"{all_metrics['tn']} | {all_metrics['fp']} | {all_metrics['fn']} | "
            f"{_fmt(all_metrics['precision'])} | {_fmt(all_metrics['recall'])} | "
            f"{_fmt(all_metrics['specificity'])} | {_fmt(all_metrics['f1'])} |"
        ),
        (
            f"| Network-visible attacks only | {visible_metrics['tp']} | "
            f"{visible_metrics['tn']} | {visible_metrics['fp']} | {visible_metrics['fn']} | "
            f"{_fmt(visible_metrics['precision'])} | {_fmt(visible_metrics['recall'])} | "
            f"{_fmt(visible_metrics['specificity'])} | {_fmt(visible_metrics['f1'])} |"
        ),
        (
            f"| Tiered: L3/L4 alert or L7 route-review case | {tiered_metrics['tp']} | "
            f"{tiered_metrics['tn']} | {tiered_metrics['fp']} | {tiered_metrics['fn']} | "
            f"{_fmt(tiered_metrics['precision'])} | {_fmt(tiered_metrics['recall'])} | "
            f"{_fmt(tiered_metrics['specificity'])} | {_fmt(tiered_metrics['f1'])} |"
        ),
        "",
        f"- Expected-rule coverage: `{_fmt(summary['expected_rule_coverage'])}` "
        f"({summary['expected_rule_hits']}/{summary['expected_rule_total']}).",
        f"- Mean/max detection latency: `{_fmt(summary['mean_detection_latency_seconds'])}` / "
        f"`{_fmt(summary['max_detection_latency_seconds'])}` seconds.",
        f"- Telemetry-loss runs: `{summary['runs_with_telemetry_loss']}`, "
        f"parse-error runs: `{summary['runs_with_parse_errors']}`.",
        "",
        "The JSON summary includes 95% Wilson intervals for precision, recall, "
        "specificity, and accuracy. These intervals quantify repeat variability within "
        "this scenario set; they do not establish production prevalence or external validity.",
        "",
        "## Per-run evidence",
        "",
        "| Run | Truth | Visible at L3/L4 | Prediction | Rules | L7 review | Flows | Loss | Latency(s) | Valid |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        prediction = (
            "attack" if row["predicted_attack"] else "benign"
            if row["predicted_attack"] is not None
            else "invalid"
        )
        lines.append(
            f"| {row['run_id']} | {row['truth_role']} | {row['network_visible']} | "
            f"{prediction} | {', '.join(row['observed_rules']) or '-'} | "
            f"{row.get('l7_review_candidates', 0)} | {row['parsed_flows']} | {row['telemetry_loss_markers']} | "
            f"{_fmt(row['detection_latency_seconds'])} | {row['valid']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "`attack_allowed_path` is deliberately labeled as an attack while using only the allowed "
            "frontend-to-backend TCP/80 edge. A correct L3/L4-only detector is expected to miss it; "
            "including it prevents an inflated claim that network telemetry detects every attack.",
            "",
            "`benign_maintenance_probe` is the opposite boundary: an authorized diagnostic action "
            "that is identical to a direct-path attack at L3/L4. It is expected to expose a false "
            "positive unless operator identity or a maintenance window is correlated.",
            "",
            "A run with a failed script, failed Hubble query, zero parsed flows, or an event-loss marker "
            "is invalid rather than benign. Raw Hubble JSONL, detector JSON, timing, and scenario "
            "stdout/stderr are retained below `runs/` for independent review.",
            "",
        ]
    )
    (run_root / "report.md").write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--namespace", default="pbl-security")
    parser.add_argument(
        "--minimum-severity", choices=tuple(SEVERITY_ORDER), default="medium"
    )
    parser.add_argument("--settle-seconds", type=float, default=2.0)
    parser.add_argument("--scenario", action="append", dest="scenarios")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--resume", action="store_true",
                        help="continue an interrupted run in --output-dir; runs with metadata.json are kept")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.repeats < 1:
        raise SystemExit("--repeats must be at least 1")
    missing = [name for name in ("kubectl", "cilium", "hubble") if not shutil.which(name)]
    if missing:
        raise SystemExit(f"missing required commands: {', '.join(missing)}")

    selected = list(SCENARIOS)
    if args.scenarios:
        wanted = set(args.scenarios)
        selected = [scenario for scenario in selected if scenario.id in wanted]
        unknown = wanted - {scenario.id for scenario in selected}
        if unknown:
            raise SystemExit(f"unknown scenario(s): {', '.join(sorted(unknown))}")
    for scenario in selected:
        if not scenario.script.is_file():
            raise SystemExit(f"scenario script not found: {scenario.script}")

    stamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_root = args.output_dir or CATEGORY_DIR / "results" / f"live-{stamp}"
    if args.resume and not args.output_dir:
        raise SystemExit("--resume needs --output-dir")
    run_root.mkdir(parents=True, exist_ok=args.resume)
    policy_path = DETECTOR_DIR / "policy.json"
    policy = _load_policy(policy_path)
    if not (run_root / "environment.json").exists():
        _json_write(run_root / "environment.json", environment_snapshot(policy_path))

    port_forward: subprocess.Popen[str] | None = None
    port_stream = None
    rows: list[dict[str, Any]] = []
    try:
        port_forward, port_stream = start_hubble_port_forward(
            run_root / "hubble-port-forward.log"
        )
        order = [
            (repetition, scenario)
            for repetition in range(1, args.repeats + 1)
            for scenario in selected
        ]
        random.Random(args.seed).shuffle(order)
        for sequence, (repetition, scenario) in enumerate(order, 1):
            run_dir = run_root / "runs" / f"{sequence:03d}-{scenario.id}-r{repetition}"
            if args.resume and (run_dir / "metadata.json").exists():
                rows.append(json.loads((run_dir / "metadata.json").read_text(encoding="utf-8")))
                continue
            if args.resume and run_dir.exists():
                shutil.rmtree(run_dir)  # interrupted mid-run: execute it again
            print(
                f"[{sequence}/{len(order)}] {scenario.id} repetition={repetition}",
                flush=True,
            )
            row = run_scenario(
                scenario,
                repetition=repetition,
                sequence=sequence,
                namespace=args.namespace,
                minimum_severity=args.minimum_severity,
                policy=policy,
                run_root=run_root,
                settle_seconds=args.settle_seconds,
            )
            rows.append(row)
            prediction = (
                "attack" if row["predicted_attack"] else "benign"
                if row["predicted_attack"] is not None
                else "invalid"
            )
            print(
                f"  truth={row['truth_role']} predicted={prediction} "
                f"rules={row['observed_rules']} flows={row['parsed_flows']} "
                f"valid={row['valid']}",
                flush=True,
            )
            time.sleep(1)
    finally:
        if port_forward is not None:
            port_forward.terminate()
            try:
                port_forward.wait(timeout=5)
            except subprocess.TimeoutExpired:
                port_forward.kill()
        if port_stream is not None:
            port_stream.close()

    summary = aggregate(rows)
    payload = {
        "configuration": {
            "seed": args.seed,
            "repeats": args.repeats,
            "minimum_severity": args.minimum_severity,
            "namespace": args.namespace,
            "scenarios": [scenario.id for scenario in selected],
        },
        "aggregate": summary,
        "runs": rows,
    }
    _json_write(run_root / "summary.json", payload)
    write_report(
        run_root,
        rows,
        summary,
        seed=args.seed,
        repeats=args.repeats,
        minimum_severity=args.minimum_severity,
    )
    print(f"wrote {run_root / 'report.md'}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["invalid_runs"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
