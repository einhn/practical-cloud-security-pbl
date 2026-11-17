#!/usr/bin/env python3
"""Evaluate the detector on the four labeled course scenarios."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from detect import _load_policy, detect, parse_lines


EXPECTED_RULES = {
    "normal.log": set(),
    "abnormal_1.log": {"path-violation"},
    "abnormal_2.log": {"destination-fanout"},
    "abnormal_3.log": {"port-sweep", "sensitive-service-probe"},
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--logs",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "logs",
        help="directory containing normal.log and abnormal_*.log",
    )
    parser.add_argument(
        "--policy", type=Path, default=Path(__file__).with_name("policy.json")
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args()

    policy = _load_policy(args.policy)
    rows = []
    tp = fp = tn = fn = 0
    expected_rule_hits = 0
    expected_rule_total = 0
    for filename, expected_rules in EXPECTED_RULES.items():
        path = args.logs / filename
        with path.open(encoding="utf-8") as handle:
            flows, losses, errors = parse_lines(handle)
        result = detect(flows, policy, losses, errors)
        observed_rules = {alert.rule_id for alert in result.alerts}
        expected_attack = bool(expected_rules)
        observed_attack = bool(observed_rules)
        if expected_attack and observed_attack:
            tp += 1
        elif expected_attack:
            fn += 1
        elif observed_attack:
            fp += 1
        else:
            tn += 1
        expected_rule_hits += len(expected_rules & observed_rules)
        expected_rule_total += len(expected_rules)
        rows.append(
            {
                "scenario": filename,
                "expected": sorted(expected_rules) or ["none"],
                "observed": sorted(observed_rules) or ["none"],
                "result": "PASS" if expected_rules <= observed_rules else "FAIL",
                "telemetry_loss_markers": losses,
            }
        )

    metrics = {
        "scenario_true_positive": tp,
        "scenario_false_positive": fp,
        "scenario_true_negative": tn,
        "scenario_false_negative": fn,
        "scenario_recall": tp / (tp + fn) if tp + fn else 0.0,
        "scenario_specificity": tn / (tn + fp) if tn + fp else 0.0,
        "expected_rule_coverage": (
            expected_rule_hits / expected_rule_total if expected_rule_total else 0.0
        ),
    }
    if args.json:
        print(json.dumps({"scenarios": rows, "metrics": metrics}, indent=2))
    else:
        print("scenario       result  expected                          observed")
        print("-------------  ------  --------------------------------  --------------------------------")
        for row in rows:
            print(
                f"{row['scenario']:<13}  {row['result']:<6}  "
                f"{','.join(row['expected']):<32}  {','.join(row['observed'])}"
            )
        print()
        for name, value in metrics.items():
            print(f"{name}={value}")
        print(
            "NOTE: these are scenario-level checks over four deterministic examples, not a claim of "
            "production statistical performance."
        )
    return 0 if all(row["result"] == "PASS" for row in rows) and fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
