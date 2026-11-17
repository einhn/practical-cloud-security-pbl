#!/usr/bin/env python3
"""Identity- and time-aware detector for Hubble flow logs.

The detector accepts the compact text emitted by ``hubble observe`` and the
line-delimited JSON emitted by recent Hubble CLI versions.  It uses only the
Python standard library so it can run on the course VM without installing a
machine-learning stack.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import statistics
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, TextIO


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BLOCKED_VERDICTS = {"DROPPED", "DENIED", "ERROR"}
TIMESTAMP_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2}\.\d{3}):\s+"
)
ENDPOINT_RE = re.compile(
    r"^(?P<source>\S+):(?P<source_port>\d+)(?:\s+\(ID:[^)]+\))?\s+"
    r"(?P<arrow>->|<>|<-)\s+"
    r"(?P<destination>\S+):(?P<destination_port>\d+)(?:\s+\([^)]+\))?\s+"
)
REPLICASET_POD_RE = re.compile(r"^(?P<workload>.+)-[0-9a-f]{8,10}-[a-z0-9]{5}$")
STATEFUL_POD_RE = re.compile(r"^(?P<workload>.+)-\d+$")


@dataclass(frozen=True)
class Flow:
    timestamp: datetime
    source: str
    destination: str
    destination_port: int
    protocol: str
    verdict: str
    syn: bool
    source_port: int | None = None
    raw: str = field(default="", compare=False)

    def compact(self) -> dict[str, Any]:
        return {
            "time": self.timestamp.isoformat(timespec="milliseconds"),
            "source": self.source,
            "destination": self.destination,
            "port": self.destination_port,
            "protocol": self.protocol,
            "verdict": self.verdict,
        }


@dataclass
class Alert:
    rule_id: str
    severity: str
    source: str
    first_seen: datetime
    last_seen: datetime
    summary: str
    evidence: dict[str, Any]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["first_seen"] = self.first_seen.isoformat(timespec="milliseconds")
        value["last_seen"] = self.last_seen.isoformat(timespec="milliseconds")
        return value


@dataclass
class DetectionResult:
    parsed_flows: int
    connection_attempts: int
    telemetry_loss_markers: int
    alerts: list[Alert]
    parse_errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "parsed_flows": self.parsed_flows,
                "connection_attempts": self.connection_attempts,
                "telemetry_loss_markers": self.telemetry_loss_markers,
                "parse_errors": self.parse_errors,
                "alert_count": len(self.alerts),
                "coverage": "degraded" if self.telemetry_loss_markers else "complete",
            },
            "alerts": [alert.to_dict() for alert in self.alerts],
        }


def _workload_name(value: str) -> str:
    """Convert an endpoint into a stable namespace/workload identity."""
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if "/" not in value:
        return value
    namespace, pod = value.split("/", 1)
    match = REPLICASET_POD_RE.match(pod)
    if match:
        pod = match.group("workload")
    else:
        match = STATEFUL_POD_RE.match(pod)
        if match:
            pod = match.group("workload")
    return f"{namespace}/{pod}"


def _parse_compact_time(line: str) -> tuple[datetime, str] | None:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None
    value = f"2000 {match.group('month')} {match.group('day')} {match.group('clock')}"
    timestamp = datetime.strptime(value, "%Y %b %d %H:%M:%S.%f")
    return timestamp, line[match.end() :]


def parse_compact_line(line: str) -> Flow | None:
    parsed_time = _parse_compact_time(line)
    if not parsed_time:
        return None
    timestamp, remainder = parsed_time
    match = ENDPOINT_RE.search(remainder)
    if not match:
        return None

    arrow = match.group("arrow")
    if arrow == "<-":
        return None
    destination_port = match.group("destination_port")
    if destination_port is None:
        return None

    protocol_match = re.search(r"\((TCP|UDP)(?:\s+Flags:.*?)?\)\s*$", remainder)
    protocol = protocol_match.group(1) if protocol_match else "UNKNOWN"
    verdict = "UNKNOWN"
    for candidate in ("DROPPED", "DENIED", "FORWARDED", "ALLOWED", "ERROR"):
        if candidate in remainder:
            verdict = candidate
            break
    if "Policy denied DROPPED" in remainder or "EGRESS DENIED" in remainder:
        verdict = "DROPPED"

    return Flow(
        timestamp=timestamp,
        source=_workload_name(match.group("source")),
        destination=_workload_name(match.group("destination")),
        destination_port=int(destination_port),
        protocol=protocol,
        verdict=verdict,
        syn="TCP Flags: SYN" in remainder and "SYN, ACK" not in remainder,
        source_port=int(match.group("source_port")) if match.group("source_port") else None,
        raw=line.rstrip(),
    )


def _iso_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).replace(tzinfo=None)


def parse_json_line(line: str) -> Flow | None:
    try:
        root = json.loads(line)
    except json.JSONDecodeError:
        return None
    flow = root.get("flow", root)
    source = flow.get("source") or {}
    destination = flow.get("destination") or {}
    ip_data = flow.get("IP") or flow.get("ip") or {}
    l4 = flow.get("l4") or {}
    tcp = l4.get("TCP") or l4.get("tcp") or {}
    udp = l4.get("UDP") or l4.get("udp") or {}

    if tcp:
        protocol = "TCP"
        destination_port = tcp.get("destination_port") or tcp.get("destinationPort")
        source_port = tcp.get("source_port") or tcp.get("sourcePort")
        flags = tcp.get("flags") or {}
        syn = bool(flags.get("SYN") or flags.get("syn")) and not bool(
            flags.get("ACK") or flags.get("ack")
        )
    elif udp:
        protocol = "UDP"
        destination_port = udp.get("destination_port") or udp.get("destinationPort")
        source_port = udp.get("source_port") or udp.get("sourcePort")
        syn = False
    else:
        return None

    if destination_port is None:
        return None

    source_name = source.get("pod_name") or source.get("podName")
    source_namespace = source.get("namespace")
    destination_name = destination.get("pod_name") or destination.get("podName")
    destination_namespace = destination.get("namespace")
    source_identity = (
        f"{source_namespace}/{source_name}"
        if source_namespace and source_name
        else ip_data.get("source") or ip_data.get("source_ip") or "unknown"
    )
    destination_identity = (
        f"{destination_namespace}/{destination_name}"
        if destination_namespace and destination_name
        else ip_data.get("destination") or ip_data.get("destination_ip") or "unknown"
    )
    timestamp_value = flow.get("time") or root.get("time")
    if not timestamp_value:
        return None

    verdict = str(flow.get("verdict", "UNKNOWN")).upper()
    return Flow(
        timestamp=_iso_datetime(timestamp_value),
        source=_workload_name(source_identity),
        destination=_workload_name(destination_identity),
        destination_port=int(destination_port),
        protocol=protocol,
        verdict=verdict,
        syn=syn,
        source_port=int(source_port) if source_port is not None else None,
        raw=line.rstrip(),
    )


def parse_lines(lines: Iterable[str]) -> tuple[list[Flow], int, int]:
    flows: list[Flow] = []
    loss_markers = 0
    parse_errors = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("EVENTS LOST"):
            loss_markers += 1
            continue
        if line.startswith("{"):
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                envelope = {}
            if envelope.get("lost_events") or envelope.get("lostEvents"):
                loss_markers += 1
                continue
        flow = parse_json_line(line) if line.startswith("{") else parse_compact_line(line)
        if flow is None and "<-" not in line:
            parse_errors += 1
        elif flow is not None:
            flows.append(flow)
    return flows, loss_markers, parse_errors


def _is_pod_source(identity: str) -> bool:
    return "/" in identity and not identity.startswith("reserved:")


def _is_connection_attempt(flow: Flow) -> bool:
    if not _is_pod_source(flow.source):
        return False
    if flow.protocol == "TCP":
        return flow.syn
    return flow.protocol == "UDP"


def _source_is_monitored(source: str, policy: dict[str, Any]) -> bool:
    """Limit detections to workload namespaces owned by this experiment."""
    namespaces = set(policy.get("monitored_namespaces", []))
    if not namespaces:
        return True
    return "/" in source and source.split("/", 1)[0] in namespaces


def deduplicate(flows: Iterable[Flow], milliseconds: int) -> list[Flow]:
    """Collapse duplicate observations without hiding TCP retransmissions."""
    result: list[Flow] = []
    last_seen: dict[tuple[Any, ...], datetime] = {}
    threshold = milliseconds / 1000.0
    for flow in sorted(flows, key=lambda item: item.timestamp):
        key = (
            flow.source,
            flow.source_port,
            flow.destination,
            flow.destination_port,
            flow.protocol,
            flow.verdict,
        )
        previous = last_seen.get(key)
        if previous is not None and (flow.timestamp - previous).total_seconds() <= threshold:
            continue
        last_seen[key] = flow.timestamp
        result.append(flow)
    return result


def _load_policy(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _allowed_edge_set(policy: dict[str, Any]) -> set[tuple[str, str, int, str]]:
    return {
        (item["source"], item["destination"], int(item["port"]), item["protocol"].upper())
        for item in policy["allowed_edges"]
    }


def _flow_key(flow: Flow) -> tuple[str, str, int, str]:
    return flow.source, flow.destination, flow.destination_port, flow.protocol


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _sliding_windows(flows: list[Flow], seconds: int) -> Iterator[list[Flow]]:
    active: deque[Flow] = deque()
    for flow in sorted(flows, key=lambda item: item.timestamp):
        active.append(flow)
        while active and (flow.timestamp - active[0].timestamp).total_seconds() > seconds:
            active.popleft()
        yield list(active)


def _merge_window_alerts(alerts: list[Alert]) -> list[Alert]:
    """Merge repeated sliding-window alerts into one finding per source/rule."""
    merged: dict[tuple[str, str], Alert] = {}
    for alert in alerts:
        key = alert.rule_id, alert.source
        current = merged.get(key)
        if current is None:
            merged[key] = alert
            continue
        current.last_seen = max(current.last_seen, alert.last_seen)
        current.evidence = alert.evidence
    return sorted(merged.values(), key=lambda item: (item.first_seen, item.rule_id))


def interval_statistics(timestamps: list[datetime]) -> dict[str, float] | None:
    """Return inter-arrival statistics used by the beacon rule."""
    ordered = sorted(timestamps)
    deltas = [
        (later - earlier).total_seconds() for earlier, later in zip(ordered, ordered[1:])
    ]
    if not deltas:
        return None
    mean = statistics.fmean(deltas)
    if mean <= 0:
        return None
    return {
        "events": len(ordered),
        "mean_interval_seconds": round(mean, 3),
        "median_interval_seconds": round(statistics.median(deltas), 3),
        "interval_cv": round(statistics.pstdev(deltas) / mean, 4),
    }


def _periodic_beacon_alerts(
    attempts: list[Flow],
    policy: dict[str, Any],
    allowed: set[tuple[str, str, int, str]],
) -> list[Alert]:
    """Detect regular, repeated connection attempts on one edge.

    Heartbeats and C2 beacons are periodic even when their payload is encrypted
    and their edge is allowed, so timing alone is the signal. Interactive or
    request-driven traffic is bursty, so its inter-arrival times vary widely.
    """
    config = policy.get("beacon") or {}
    if not config:
        return []
    excluded_ports = {int(port) for port in config.get("exclude_ports", [])}
    declared = {
        (item["source"], item["destination"], int(item["port"]), item["protocol"].upper())
        for item in config.get("declared_periodic_edges", [])
    }
    series: dict[tuple[str, str, int, str], list[Flow]] = defaultdict(list)
    for flow in attempts:
        key = _flow_key(flow)
        if flow.destination_port in excluded_ports or key in declared:
            continue
        series[key].append(flow)

    alerts: list[Alert] = []
    for key, flows in series.items():
        if len(flows) < int(config["min_events"]):
            continue
        stats = interval_statistics([flow.timestamp for flow in flows])
        if stats is None:
            continue
        if not (
            float(config["min_interval_seconds"])
            <= stats["median_interval_seconds"]
            <= float(config["max_interval_seconds"])
        ):
            continue
        if stats["interval_cv"] > float(config["max_cv"]):
            continue
        source, destination, port, protocol = key
        alerts.append(
            Alert(
                rule_id="periodic-beacon",
                severity="high",
                source=source,
                first_seen=flows[0].timestamp,
                last_seen=flows[-1].timestamp,
                summary=(
                    f"{source} opened {stats['events']} connections to {destination}:{port}/{protocol} "
                    f"every {stats['median_interval_seconds']}s (CV={stats['interval_cv']})"
                ),
                evidence={
                    "edge": f"{destination}:{port}/{protocol}",
                    "edge_in_service_graph": key in allowed,
                    "verdicts": sorted({flow.verdict for flow in flows}),
                    **stats,
                },
                rationale=(
                    "Request-driven traffic is bursty; a fixed-period series of new connections on one "
                    "edge is consistent with an implant heartbeat or C2 beacon. Timing is observable "
                    "without decrypting payloads, including on an allowed edge."
                ),
            )
        )
    return alerts


def detect(flows: list[Flow], policy: dict[str, Any], loss_markers: int = 0, parse_errors: int = 0) -> DetectionResult:
    attempts = [
        flow
        for flow in flows
        if _is_connection_attempt(flow) and _source_is_monitored(flow.source, policy)
    ]
    attempts = deduplicate(attempts, int(policy["dedup_milliseconds"]))
    allowed = _allowed_edge_set(policy)
    sensitive_ports = {int(port) for port in policy["sensitive_ports"]}
    metadata_addresses = set(policy["metadata_addresses"])
    alerts: list[Alert] = []

    violations: dict[str, list[Flow]] = defaultdict(list)
    for flow in attempts:
        if _flow_key(flow) in allowed:
            continue
        if flow.verdict in {"DROPPED", "DENIED"}:
            violations[flow.source].append(flow)
    for source, matches in violations.items():
        targets = sorted(
            {f"{flow.destination}:{flow.destination_port}/{flow.protocol}" for flow in matches}
        )
        severity = (
            "high"
            if any(flow.destination_port in sensitive_ports for flow in matches) or len(matches) >= 3
            else "medium"
        )
        alerts.append(
            Alert(
                rule_id="path-violation",
                severity=severity,
                source=source,
                first_seen=matches[0].timestamp,
                last_seen=matches[-1].timestamp,
                summary=f"{source} attempted {len(targets)} non-baseline network path(s)",
                evidence={
                    "targets": targets,
                    "blocked_syn_or_datagram_count": len(matches),
                },
                rationale=(
                    "The workload-to-workload/port edge is absent from the declared service graph "
                    "and the network policy denied it. A single event remains medium severity because "
                    "misconfiguration can look identical to an attack."
                ),
            )
        )

    # Post-compromise traffic matters most when enforcement did NOT stop it: a
    # missing or over-broad policy, an AUDIT-mode policy, or a newly opened path.
    # Compare every successful attempt with the declared graph as well.
    deviations: dict[str, list[Flow]] = defaultdict(list)
    for flow in attempts:
        if _flow_key(flow) in allowed or flow.verdict in BLOCKED_VERDICTS:
            continue
        deviations[flow.source].append(flow)
    for source, matches in deviations.items():
        targets = sorted(
            {f"{flow.destination}:{flow.destination_port}/{flow.protocol}" for flow in matches}
        )
        severity = (
            "high"
            if any(flow.destination_port in sensitive_ports for flow in matches) or len(targets) >= 3
            else "medium"
        )
        alerts.append(
            Alert(
                rule_id="baseline-deviation",
                severity=severity,
                source=source,
                first_seen=matches[0].timestamp,
                last_seen=matches[-1].timestamp,
                summary=f"{source} reached {len(targets)} edge(s) outside the declared service graph",
                evidence={
                    "targets": targets,
                    "verdicts": sorted({flow.verdict for flow in matches}),
                    "attempt_count": len(matches),
                },
                rationale=(
                    "The network allowed a connection that the declared service graph does not contain. "
                    "Detection must not depend on enforcement: a permissive or audit-mode policy turns "
                    "an attack into FORWARDED traffic."
                ),
            )
        )

    alerts.extend(_periodic_beacon_alerts(attempts, policy, allowed))

    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in attempts:
        by_source[flow.source].append(flow)

    window_alerts: list[Alert] = []
    window_seconds = int(policy["window_seconds"])
    for source, source_flows in by_source.items():
        for window in _sliding_windows(source_flows, window_seconds):
            destinations = sorted({flow.destination for flow in window})
            ports = sorted({flow.destination_port for flow in window})
            if len(destinations) >= int(policy["destination_fanout_threshold"]):
                window_alerts.append(
                    Alert(
                        rule_id="destination-fanout",
                        severity="high",
                        source=source,
                        first_seen=window[0].timestamp,
                        last_seen=window[-1].timestamp,
                        summary=f"{source} contacted {len(destinations)} destinations in {window_seconds}s",
                        evidence={"destinations": destinations, "attempt_count": len(window)},
                        rationale=(
                            "Normal service calls stay on a small declared dependency graph. Rapid "
                            "fan-out across workload and infrastructure identities is consistent with discovery."
                        ),
                    )
                )
            if len(ports) >= int(policy["port_fanout_threshold"]):
                window_alerts.append(
                    Alert(
                        rule_id="port-sweep",
                        severity="high",
                        source=source,
                        first_seen=window[0].timestamp,
                        last_seen=window[-1].timestamp,
                        summary=f"{source} probed {len(ports)} destination ports in {window_seconds}s",
                        evidence={"ports": ports, "attempt_count": len(window)},
                        rationale=(
                            "A single workload role normally uses a small stable port set. A broad port "
                            "fan-out over a short window is consistent with service and kubelet probing."
                        ),
                    )
                )
    alerts.extend(_merge_window_alerts(window_alerts))

    sensitive_by_source: dict[str, list[Flow]] = defaultdict(list)
    metadata_by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in attempts:
        if flow.destination_port in sensitive_ports:
            sensitive_by_source[flow.source].append(flow)
        if flow.destination in metadata_addresses:
            metadata_by_source[flow.source].append(flow)
    for source, matches in sensitive_by_source.items():
        alerts.append(
            Alert(
                rule_id="sensitive-service-probe",
                severity="high",
                source=source,
                first_seen=matches[0].timestamp,
                last_seen=matches[-1].timestamp,
                summary=f"{source} probed Kubernetes/administrative or C2-associated ports",
                evidence={
                    "targets": sorted({f"{flow.destination}:{flow.destination_port}" for flow in matches}),
                    "attempt_count": len(matches),
                },
                rationale=(
                    "The observed ports include kubelet, etcd, API, SSH, or IRC endpoints that are not "
                    "part of this workload role's declared network behavior."
                ),
            )
        )
    for source, matches in metadata_by_source.items():
        alerts.append(
            Alert(
                rule_id="cloud-metadata-access",
                severity="critical",
                source=source,
                first_seen=matches[0].timestamp,
                last_seen=matches[-1].timestamp,
                summary=f"{source} attempted to access a cloud metadata endpoint",
                evidence={"targets": sorted({flow.destination for flow in matches})},
                rationale=(
                    "Cloud metadata access from this workload is not required by the application and is "
                    "a known credential-access step in Hildegard and later cloud-native intrusions."
                ),
            )
        )

    correlation_seconds = int(policy["correlation_window_seconds"])
    per_source_rules: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        per_source_rules[alert.source].append(alert)
    for source, source_alerts in per_source_rules.items():
        recon = [
            alert
            for alert in source_alerts
            if alert.rule_id in {"destination-fanout", "port-sweep", "sensitive-service-probe"}
        ]
        violations_for_source = [
            alert
            for alert in source_alerts
            if alert.rule_id in {"path-violation", "baseline-deviation"}
        ]
        candidates = recon + violations_for_source
        if recon and violations_for_source:
            first = min(alert.first_seen for alert in candidates)
            last = max(alert.last_seen for alert in candidates)
            if (last - first).total_seconds() <= correlation_seconds:
                alerts.append(
                    Alert(
                        rule_id="correlated-lateral-movement",
                        severity="critical",
                        source=source,
                        first_seen=first,
                        last_seen=last,
                        summary=f"{source} shows a reconnaissance-to-access sequence",
                        evidence={"constituent_rules": sorted({a.rule_id for a in candidates})},
                        rationale=(
                            "Multiple weak signals occur for the same Kubernetes identity within one "
                            "correlation window. This sequence is more discriminative than any isolated drop."
                        ),
                    )
                )

    alerts = sorted(alerts, key=lambda item: (item.first_seen, -SEVERITY_ORDER[item.severity], item.rule_id))
    return DetectionResult(
        parsed_flows=len(flows),
        connection_attempts=len(attempts),
        telemetry_loss_markers=loss_markers,
        alerts=alerts,
        parse_errors=parse_errors,
    )


def _render_text(result: DetectionResult, minimum_severity: str) -> str:
    lines = [
        "Hubble lateral-movement detection",
        f"parsed_flows={result.parsed_flows} connection_attempts={result.connection_attempts} "
        f"alerts={len(result.alerts)} telemetry_loss_markers={result.telemetry_loss_markers} "
        f"parse_errors={result.parse_errors}",
    ]
    if result.telemetry_loss_markers:
        lines.append(
            "WARNING: Hubble reported lost events; a clean result cannot prove that no attack occurred."
        )
    threshold = SEVERITY_ORDER[minimum_severity]
    selected = [alert for alert in result.alerts if SEVERITY_ORDER[alert.severity] >= threshold]
    if not selected:
        lines.append(f"No alerts at or above severity={minimum_severity}.")
        return "\n".join(lines)
    for alert in selected:
        lines.extend(
            [
                "",
                f"[{alert.severity.upper()}] {alert.rule_id}: {alert.summary}",
                f"  window: {alert.first_seen.isoformat(timespec='milliseconds')} .. "
                f"{alert.last_seen.isoformat(timespec='milliseconds')}",
                f"  evidence: {json.dumps(alert.evidence, ensure_ascii=False, sort_keys=True)}",
                f"  rationale: {alert.rationale}",
            ]
        )
    return "\n".join(lines)


def _open_input(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdin, False
    return Path(path).open(encoding="utf-8"), True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Hubble compact/JSONL log, or '-' for stdin")
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).with_name("policy.json"),
        help="detection policy JSON",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--min-severity", choices=tuple(SEVERITY_ORDER), default="medium"
    )
    args = parser.parse_args(argv)

    handle, should_close = _open_input(args.input)
    try:
        flows, loss_markers, parse_errors = parse_lines(handle)
    finally:
        if should_close:
            handle.close()
    result = detect(flows, _load_policy(args.policy), loss_markers, parse_errors)
    if args.format == "json":
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(_render_text(result, args.min_severity))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
