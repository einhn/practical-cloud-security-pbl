from __future__ import annotations

import sys
import unittest
from pathlib import Path


EVALUATION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EVALUATION_DIR))

from run_live_eval import aggregate, confusion, wilson_interval  # noqa: E402


def row(
    role: str,
    predicted: bool | None,
    *,
    valid: bool = True,
    visible: bool = True,
    expected: tuple[str, ...] = (),
    hits: tuple[str, ...] = (),
    latency: float | None = None,
) -> dict:
    return {
        "truth_role": role,
        "predicted_attack": predicted,
        "valid": valid,
        "network_visible": visible,
        "expected_rules": list(expected),
        "expected_rule_hits": list(hits),
        "detection_latency_seconds": latency,
        "telemetry_loss_markers": 0,
        "parse_errors": 0,
    }


class MetricsTest(unittest.TestCase):
    def test_wilson_interval(self) -> None:
        self.assertIsNone(wilson_interval(0, 0))
        interval = wilson_interval(5, 10)
        self.assertIsNotNone(interval)
        assert interval is not None
        self.assertAlmostEqual(interval[0], 0.2366, places=4)
        self.assertAlmostEqual(interval[1], 0.7634, places=4)

    def test_confusion_metrics(self) -> None:
        rows = [
            row("attack", True),
            row("attack", False),
            row("benign", True),
            row("benign", False),
            row("attack", None, valid=False),
        ]
        metrics = confusion(rows)
        self.assertEqual((metrics["tp"], metrics["tn"]), (1, 1))
        self.assertEqual((metrics["fp"], metrics["fn"]), (1, 1))
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["f1"], 0.5)

    def test_aggregate_separates_intentional_blind_spot(self) -> None:
        rows = [
            row(
                "attack",
                True,
                expected=("path-violation",),
                hits=("path-violation",),
                latency=0.4,
            ),
            row("attack", False, visible=False),
            row("benign", False),
        ]
        summary = aggregate(rows)
        self.assertEqual(summary["all_scenarios"]["fn"], 1)
        self.assertEqual(summary["network_visible_scenarios"]["fn"], 0)
        self.assertEqual(summary["network_visible_scenarios"]["recall"], 1.0)
        self.assertEqual(summary["expected_rule_coverage"], 1.0)


if __name__ == "__main__":
    unittest.main()
