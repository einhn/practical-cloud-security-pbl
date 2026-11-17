import json
import sys
import unittest
from pathlib import Path


DETECTOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DETECTOR_DIR))

import route_l7_review


def _line(path: str, headers=None):
    return json.dumps(
        {
            "flow": {
                "time": "2026-11-14T00:00:00Z",
                "source": {
                    "namespace": "pbl-security",
                    "workloads": [{"name": "frontend"}],
                },
                "destination": {
                    "namespace": "pbl-security",
                    "pod_name": "backend-76999b64b9-9l7nq",
                },
                "l7": {
                    "type": "REQUEST",
                    "http": {
                        "method": "GET",
                        "url": f"http://backend{path}",
                        "headers": headers or [],
                    },
                },
            }
        }
    )


class L7RouterTest(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "allowed_http_routes": [
                {
                    "source": "pbl-security/frontend",
                    "destination": "pbl-security/backend",
                    "methods": ["GET"],
                    "paths": ["/"],
                }
            ],
            "redacted_header_names": ["authorization"],
            "ignored_header_names": ["x-request-id"],
        }

    def test_known_route_is_not_sent_to_llm(self):
        result = route_l7_review.route([_line("/")], self.policy)
        self.assertEqual(result["summary"]["semantic_review_candidates"], 0)

    def test_unknown_route_is_review_candidate_and_secrets_are_redacted(self):
        result = route_l7_review.route(
            [
                _line(
                    "/admin",
                    [
                        {"key": "Authorization", "value": "Bearer secret"},
                        {"key": "X-Request-Id", "value": "noise"},
                    ],
                )
            ],
            self.policy,
        )
        candidate = result["candidates"][0]
        self.assertEqual(candidate["disposition"], "semantic-review-required")
        self.assertEqual(
            candidate["evidence"]["headers"],
            [{"key": "Authorization", "value": "[REDACTED]"}],
        )


if __name__ == "__main__":
    unittest.main()
