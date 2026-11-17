#!/usr/bin/env python3
"""Attach the process that opened each alerted connection, using Tetragon events.

Hubble reports which workload connected where; Tetragon's tcp_connect kprobe
reports which binary and arguments opened the socket. This joins the two on
namespace/workload, time window and destination port.

    python3 category2/detector/runtime_join.py detector.json tetragon.jsonl > runtime-attribution.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SLACK = timedelta(seconds=2)


def _time(value: str) -> datetime:
    """Parse detector (ms, naive UTC) and Tetragon (ns, 'Z') timestamps as naive UTC."""
    value = value.rstrip("Z")
    if "." in value:
        head, fraction = value.split(".", 1)
        value = f"{head}.{fraction[:6]}"
    return datetime.fromisoformat(value)


def connect_events(lines) -> list[dict[str, Any]]:
    events = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        kprobe = record.get("process_kprobe")
        if not kprobe or kprobe.get("function_name") != "tcp_connect":
            continue
        process, pod = kprobe["process"], kprobe["process"].get("pod") or {}
        sock = next((a["sock_arg"] for a in kprobe.get("args", []) if "sock_arg" in a), {})
        events.append(
            {
                "time": record["time"],
                "workload": f"{pod.get('namespace')}/{pod.get('workload') or pod.get('name')}",
                "pod": pod.get("name"),
                "container": (pod.get("container") or {}).get("name"),
                "binary": process.get("binary"),
                "arguments": process.get("arguments"),
                "parent_binary": (kprobe.get("parent") or {}).get("binary"),
                "socket": f"{sock.get('saddr')}:{sock.get('sport')} -> {sock.get('daddr')}:{sock.get('dport')}",
                "dport": sock.get("dport"),
            }
        )
    return events


def _alert_ports(alert: dict[str, Any]) -> set[int]:
    evidence = alert.get("evidence", {})
    ports = set(evidence.get("ports", []))
    for target in evidence.get("targets", []) + ([evidence["edge"]] if "edge" in evidence else []):
        tail = str(target).rsplit(":", 1)[-1].split("/")[0]
        if tail.isdigit():
            ports.add(int(tail))
    return ports


def join(detector_result: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    joined = []
    for alert in detector_result.get("alerts", []):
        start, end = _time(alert["first_seen"]) - SLACK, _time(alert["last_seen"]) + SLACK
        ports = _alert_ports(alert)
        matches = [
            e for e in events
            if e["workload"] == alert["source"]
            and start <= _time(e["time"]) <= end
            and (not ports or e["dport"] in ports)
        ]
        processes: dict[tuple, dict[str, Any]] = {}
        for e in matches:
            key = (e["binary"], e["arguments"], e["container"])
            entry = processes.setdefault(key, {k: e[k] for k in ("binary", "arguments", "container", "parent_binary")} | {"connects": 0, "sockets": []})
            entry["connects"] += 1
            if len(entry["sockets"]) < 3:
                entry["sockets"].append(e["socket"])
        joined.append(
            {
                "rule_id": alert["rule_id"],
                "severity": alert["severity"],
                "source": alert["source"],
                "window": [alert["first_seen"], alert["last_seen"]],
                "runtime_processes": list(processes.values()),
                "attributed": bool(processes),
            }
        )
    return joined


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("detector_json", type=Path)
    parser.add_argument("tetragon_jsonl", type=Path)
    args = parser.parse_args(argv)
    detector_result = json.loads(args.detector_json.read_text(encoding="utf-8"))
    with args.tetragon_jsonl.open(encoding="utf-8") as handle:
        events = connect_events(handle)
    json.dump(join(detector_result, events), sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
