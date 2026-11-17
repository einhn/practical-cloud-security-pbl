from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


DETECTOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DETECTOR_DIR))

from detect import (  # noqa: E402
    _load_policy,
    _workload_name,
    detect,
    parse_json_line,
    parse_lines,
)


class DetectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.category_dir = DETECTOR_DIR.parent
        cls.policy = _load_policy(DETECTOR_DIR / "policy.json")

    def analyze(self, filename: str):
        with (self.category_dir / "logs" / filename).open(encoding="utf-8") as handle:
            flows, losses, errors = parse_lines(handle)
        return detect(flows, self.policy, losses, errors)

    def test_pod_name_normalization(self) -> None:
        self.assertEqual(
            _workload_name("pbl-security/frontend-5d9977c59f-gk4cs"),
            "pbl-security/frontend",
        )
        self.assertEqual(_workload_name("10.96.0.1"), "10.96.0.1")

    def test_hubble_json_line(self) -> None:
        line = json.dumps(
            {
                "flow": {
                    "time": "2026-11-08T01:02:03.456Z",
                    "verdict": "DROPPED",
                    "IP": {"source": "10.0.0.2", "destination": "10.0.0.3"},
                    "l4": {
                        "TCP": {
                            "source_port": 43123,
                            "destination_port": 10250,
                            "flags": {"SYN": True},
                        }
                    },
                    "source": {
                        "namespace": "pbl-security",
                        "pod_name": "frontend-5d9977c59f-gk4cs",
                    },
                    "destination": {},
                }
            }
        )
        flow = parse_json_line(line)
        self.assertIsNotNone(flow)
        assert flow is not None
        self.assertEqual(flow.source, "pbl-security/frontend")
        self.assertEqual(flow.destination, "10.0.0.3")
        self.assertEqual(flow.destination_port, 10250)
        self.assertTrue(flow.syn)

    def test_normal_has_no_alert(self) -> None:
        self.assertEqual(self.analyze("normal.log").alerts, [])

    def test_out_of_scope_coredns_udp_responses_do_not_alert(self) -> None:
        flows = []
        for index, destination_port in enumerate((34841, 36789, 43791, 47828)):
            line = json.dumps(
                {
                    "flow": {
                        "time": f"2026-11-08T01:02:{index:02d}.000Z",
                        "verdict": "FORWARDED",
                        "IP": {"source": "10.0.0.10", "destination": "10.0.0.20"},
                        "l4": {
                            "UDP": {
                                "source_port": 53,
                                "destination_port": destination_port,
                            }
                        },
                        "source": {
                            "namespace": "kube-system",
                            "pod_name": "coredns-7db6d8ff4d-abcde",
                        },
                        "destination": {
                            "namespace": "pbl-security",
                            "pod_name": "frontend-5d9977c59f-gk4cs",
                        },
                    }
                }
            )
            flow = parse_json_line(line)
            self.assertIsNotNone(flow)
            flows.append(flow)

        result = detect([flow for flow in flows if flow is not None], self.policy)
        self.assertEqual(result.alerts, [])
        self.assertEqual(result.connection_attempts, 0)

    def test_json_lost_event_is_coverage_failure_not_parse_error(self) -> None:
        flows, losses, errors = parse_lines(
            [
                json.dumps(
                    {
                        "lost_events": {
                            "source": "PERF_EVENT_RING_BUFFER",
                            "num_events_lost": "12",
                        }
                    }
                )
            ]
        )
        self.assertEqual(flows, [])
        self.assertEqual(losses, 1)
        self.assertEqual(errors, 0)

    def test_direct_db_access(self) -> None:
        rules = {alert.rule_id for alert in self.analyze("abnormal_1.log").alerts}
        self.assertIn("path-violation", rules)

    def test_destination_discovery(self) -> None:
        rules = {alert.rule_id for alert in self.analyze("abnormal_2.log").alerts}
        self.assertIn("destination-fanout", rules)

    def test_multi_port_probe(self) -> None:
        rules = {alert.rule_id for alert in self.analyze("abnormal_3.log").alerts}
        self.assertIn("port-sweep", rules)
        self.assertIn("sensitive-service-probe", rules)

    @staticmethod
    def syn(offset_seconds: float, destination_pod: str, port: int, verdict: str, sport: int,
            destination_namespace: str = "pbl-egress-sim"):
        base = datetime(2026, 11, 15, 0, 0, 0)
        stamp = (base + timedelta(seconds=offset_seconds)).isoformat(timespec="milliseconds") + "Z"
        return parse_json_line(
            json.dumps(
                {
                    "flow": {
                        "time": stamp,
                        "verdict": verdict,
                        "l4": {"TCP": {"source_port": sport, "destination_port": port,
                                       "flags": {"SYN": True}}},
                        "source": {"namespace": "pbl-security",
                                   "pod_name": "frontend-677d8564b5-ttftm"},
                        "destination": {"namespace": destination_namespace,
                                        "pod_name": destination_pod},
                    }
                }
            )
        )

    def test_periodic_beacon_on_allowed_edge(self) -> None:
        flows = [
            self.syn(i * 4.0 + (0.1 if i % 2 else -0.1), "ext-api-6d8f7c9b5d-abcde", 80,
                     "FORWARDED", 40000 + i)
            for i in range(8)
        ]
        alerts = detect(flows, self.policy).alerts
        self.assertEqual([alert.rule_id for alert in alerts], ["periodic-beacon"])
        self.assertTrue(alerts[0].evidence["edge_in_service_graph"])

    def test_irregular_calls_on_same_edge_do_not_beacon(self) -> None:
        offsets = [0.0, 0.4, 7.5, 8.1, 15.0, 15.3, 22.9, 31.0]
        flows = [
            self.syn(offset, "ext-api-6d8f7c9b5d-abcde", 80, "FORWARDED", 41000 + i)
            for i, offset in enumerate(offsets)
        ]
        self.assertEqual(detect(flows, self.policy).alerts, [])

    def test_burst_is_not_a_beacon(self) -> None:
        flows = [
            self.syn(i * 0.2, "ext-api-6d8f7c9b5d-abcde", 80, "FORWARDED", 42000 + i)
            for i in range(30)
        ]
        self.assertEqual(detect(flows, self.policy).alerts, [])

    def test_forwarded_out_of_graph_edge_is_detected_without_enforcement(self) -> None:
        flows = [self.syn(0.0, "db-56975bfdbd-mmpng", 80, "FORWARDED", 43000, "pbl-security")]
        alerts = detect(flows, self.policy).alerts
        self.assertEqual([alert.rule_id for alert in alerts], ["baseline-deviation"])
        self.assertEqual(alerts[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
