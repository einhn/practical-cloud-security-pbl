#!/usr/bin/env python3
"""Monte Carlo sensitivity of the periodic-beacon rule to jitter and event count.

Uses the exact rule implementation from detect.py on synthetic timestamps:
* beacon: interval * (1 + U(-j, +j)) gaps (Cobalt-Strike-style uniform jitter)
* benign: exponential think time (mean = interval), clipped like the scenario
This is an offline characterization, not a live measurement.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "detector"))
from detect import _load_policy, interval_statistics  # noqa: E402


def fires(gaps: list[float], config: dict) -> bool:
    base = datetime(2026, 1, 1)
    stamps = [base]
    for gap in gaps:
        stamps.append(stamps[-1] + timedelta(seconds=gap))
    if len(stamps) < config["min_events"]:
        return False
    stats = interval_statistics(stamps)
    return (
        stats is not None
        and config["min_interval_seconds"] <= stats["median_interval_seconds"] <= config["max_interval_seconds"]
        and stats["interval_cv"] <= config["max_cv"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=5000)
    parser.add_argument("--interval", type=float, default=4.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    config = _load_policy(Path(__file__).resolve().parents[1] / "detector" / "policy.json")["beacon"]
    rng = random.Random(args.seed)
    jitters = [round(j * 0.05, 2) for j in range(0, 17)]
    result = {"config": config, "trials": args.trials, "interval": args.interval, "curves": {}}
    for events in (6, 8, 12, 20):
        curve = []
        for jitter in jitters:
            hits = sum(
                fires([args.interval * (1 + jitter * (2 * rng.random() - 1)) for _ in range(events - 1)], config)
                for _ in range(args.trials)
            )
            curve.append({"jitter": jitter, "detection_rate": hits / args.trials})
        benign_hits = sum(
            fires([min(12.0, max(0.3, rng.expovariate(1 / args.interval))) for _ in range(events - 1)], config)
            for _ in range(args.trials)
        )
        result["curves"][str(events)] = {"beacon": curve, "benign_false_positive_rate": benign_hits / args.trials}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
