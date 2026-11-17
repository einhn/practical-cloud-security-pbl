from __future__ import annotations

import json
import random
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ANALYSIS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYSIS_DIR))

import llm_review  # noqa: E402
import observation_collisions  # noqa: E402


class CollisionTest(unittest.TestCase):
    def test_lower_bound_counts_minority_labels(self) -> None:
        records = [
            {"observation_hash": "same", "truth_role": label, "scenario": f"s{i}", "observation": {"alerts": []}}
            for i, label in enumerate(["attack", "attack", "benign"])
        ]
        records.append({"observation_hash": "other", "truth_role": "benign", "scenario": "x", "observation": {"alerts": []}})
        groups, unavoidable = observation_collisions.collision_groups(records)
        self.assertEqual(unavoidable, 1)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["runs"], 3)


class LlmReviewTest(unittest.TestCase):
    def test_response_must_carry_a_known_verdict(self) -> None:
        ok = llm_review.parse_response('Here: {"verdict": "insufficient_evidence", "evidence_ids": []}')
        self.assertEqual(ok["verdict"], "insufficient_evidence")
        with self.assertRaises(ValueError):
            llm_review.parse_response('{"verdict": "probably fine"}')

    def test_citations_must_exist_in_the_case(self) -> None:
        case_text = json.dumps({"edges": [{"evidence_id": "edge-1"}], "ticket": "[CHG-1234] check"})
        response = {"evidence_ids": ["edge-1", "CHG-1234", "edge-12", "ev-invented"]}
        self.assertEqual(llm_review.cited_ids_missing(response, case_text), ["edge-12", "ev-invented"])

    def test_env_file_is_parsed_without_exposing_other_variables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("# comment\nBAZE_API_KEY='abc'\nOTHER=1\n")
            values = llm_review.load_env(path)
        self.assertEqual(values["BAZE_API_KEY"], "abc")

    def test_only_authorized_runs_get_a_matching_ticket(self) -> None:
        start = datetime(2026, 11, 15, 12, 0, 0)
        decoys = llm_review._ticket_feed(random.Random(1), start, authorized=False)
        approved = llm_review._ticket_feed(random.Random(1), start, authorized=True)
        self.assertEqual(len(decoys) + 1, len(approved))
        self.assertTrue(all("sec-lead" not in t["ticket"] or "2026-11-14" in t["window_start"] for t in decoys))


class RuntimeJoinTest(unittest.TestCase):
    def test_alert_is_attributed_to_the_connecting_process(self) -> None:
        sys.path.insert(0, str(ANALYSIS_DIR.parent / "detector"))
        import runtime_join

        event = {
            "time": "2026-11-17T06:23:53.000000001Z",
            "process_kprobe": {
                "function_name": "tcp_connect",
                "process": {"binary": "/bin/wget", "arguments": "-qO- http://db",
                            "pod": {"namespace": "pbl-security", "workload": "frontend", "name": "frontend-x",
                                    "container": {"name": "frontend"}}},
                "args": [{"sock_arg": {"saddr": "10.0.0.1", "sport": 1, "daddr": "10.96.0.2", "dport": 80}}],
            },
        }
        alert = {"rule_id": "path-violation", "severity": "medium", "source": "pbl-security/frontend",
                 "first_seen": "2026-11-17T06:23:52.457", "last_seen": "2026-11-17T06:23:54.498",
                 "evidence": {"targets": ["pbl-security/db:80/TCP"]}}
        joined = runtime_join.join({"alerts": [alert]}, runtime_join.connect_events([json.dumps(event)]))
        self.assertTrue(joined[0]["attributed"])
        self.assertEqual(joined[0]["runtime_processes"][0]["binary"], "/bin/wget")


if __name__ == "__main__":
    unittest.main()
