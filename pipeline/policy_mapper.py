#!/usr/bin/env python3
"""
Convert classified PCAP outputs into normalized policy jobs.

Input:
  The output directory produced by ddos_classifier_v5_2.py.

Output:
  A JSONL file. Each line is a policy job that can be reviewed or
  consumed by a downstream dispatcher.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


DATE_RE = re.compile(r"^\d{8}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class PolicyJob:
    job_id: str
    created_at: str
    source_pcap: str
    category: str
    ip_version: str
    victim_ip: str
    attack_suffix: str
    attack_type: str
    severity: str
    confidence: str
    action: str
    protocol: str
    target_ports: list[int]
    rate_limit_pps: int | None
    ttl_seconds: int
    need_review: bool
    rollback_hint: str
    evidence: dict


ATTACK_RULES = [
    {
        "match": "Volumetric Attack/TCP/SYN Flood",
        "attack_type": "SYN_FLOOD",
        "action": "huawei_acl_tcp_syn_drop",
        "protocol": "tcp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 20000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/TCP/SYN-ACK",
        "attack_type": "TCP_SYNACK_FLOOD",
        "action": "huawei_acl_tcp_flag_drop",
        "protocol": "tcp",
        "ports": [],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 15000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/TCP/ACK Flood",
        "attack_type": "ACK_FLOOD",
        "action": "huawei_acl_tcp_ack_drop",
        "protocol": "tcp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 25000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/TCP/TCP Flood",
        "attack_type": "TCP_FLOOD",
        "action": "huawei_acl_tcp_generic_drop",
        "protocol": "tcp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 25000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/UDP/UDP Flood",
        "attack_type": "UDP_FLOOD",
        "action": "huawei_acl_udp_drop",
        "protocol": "udp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 30000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/UDP/Reflection",
        "attack_type": "UDP_REFLECTION",
        "action": "huawei_acl_udp_reflection_drop",
        "protocol": "udp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 3600,
        "rate_limit_pps": 50000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/UDP/Amplification",
        "attack_type": "UDP_AMPLIFICATION",
        "action": "huawei_acl_udp_reflection_drop",
        "protocol": "udp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 3600,
        "rate_limit_pps": 50000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/UDP/Amplification Request",
        "attack_type": "AMPLIFICATION_REQUEST",
        "action": "huawei_review_only",
        "protocol": "udp",
        "ports": [],
        "severity": "medium",
        "confidence": "medium",
        "ttl_seconds": 900,
        "rate_limit_pps": None,
        "need_review": True,
        "rollback_hint": "review if local asset is the request initiator before any block",
    },
    {
        "match": "Volumetric Attack/ICMP/ICMP Flood",
        "attack_type": "ICMP_FLOOD",
        "action": "huawei_acl_icmp_drop",
        "protocol": "icmp",
        "ports": [],
        "severity": "high",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 20000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/IP Flood/GRE",
        "attack_type": "GRE_FLOOD",
        "action": "huawei_acl_gre_drop",
        "protocol": "gre",
        "ports": [],
        "severity": "high",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 10000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/IP Flood/IP Flood",
        "attack_type": "IP_FLOOD",
        "action": "huawei_acl_ip_drop",
        "protocol": "ip",
        "ports": [],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 10000,
        "need_review": False,
        "rollback_hint": "remove acl and detach traffic-policy after attack subsides",
    },
    {
        "match": "Volumetric Attack/IPv6 Tunnel Flood",
        "attack_type": "IP_FLOOD",
        "action": "huawei_acl_ip_drop",
        "protocol": "ip",
        "ports": [],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 10000,
        "need_review": True,
        "rollback_hint": "review tunnel traffic impact before block and remove acl after attack subsides",
    },
    {
        "match": "Volumetric Attack/TCP/TCP Replay Attack",
        "attack_type": "TCP_FLOOD",
        "action": "huawei_acl_tcp_generic_drop",
        "protocol": "tcp",
        "ports": [],
        "severity": "critical",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 25000,
        "need_review": True,
        "rollback_hint": "review replay-attack service impact before dispatch and remove acl after attack subsides",
    },
    {
        "match": "TCP State Exhaustion Attack",
        "attack_type": "TCP_STATE_EXHAUSTION",
        "action": "huawei_tcp_connection_protect",
        "protocol": "tcp",
        "ports": [],
        "severity": "critical",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 15000,
        "need_review": False,
        "rollback_hint": "disable connection protection override after attack subsides",
    },
    {
        "match": "Application Attack/HTTP",
        "attack_type": "HTTP_APP",
        "action": "huawei_app_layer_escalate",
        "protocol": "tcp",
        "ports": [80, 8080],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": None,
        "need_review": True,
        "rollback_hint": "prefer WAF or scrubbing rollback once app layer traffic normalizes",
    },
    {
        "match": "Application Attack/HTTPS",
        "attack_type": "HTTPS_APP",
        "action": "huawei_app_layer_escalate",
        "protocol": "tcp",
        "ports": [443, 8443],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": None,
        "need_review": True,
        "rollback_hint": "prefer WAF or scrubbing rollback once app layer traffic normalizes",
    },
    {
        "match": "Application Attack/QUIC",
        "attack_type": "QUIC_APP",
        "action": "huawei_quic_rate_limit",
        "protocol": "udp",
        "ports": [443],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 15000,
        "need_review": True,
        "rollback_hint": "remove quic rate-limit after traffic recovers",
    },
    {
        "match": "Application Attack/DNS/DNS Query Flood",
        "attack_type": "DNS_REQUEST_FLOOD",
        "action": "huawei_dns_request_tc_source_auth",
        "protocol": "udp",
        "ports": [53],
        "severity": "high",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 20000,
        "need_review": True,
        "rollback_hint": "review tcp-capable dns client compatibility before production push",
    },
    {
        "match": "Application Attack/DNS/DNS Response Flood",
        "attack_type": "DNS_REPLY_FLOOD",
        "action": "huawei_dns_reply_source_auth",
        "protocol": "udp",
        "ports": [53],
        "severity": "high",
        "confidence": "high",
        "ttl_seconds": 1800,
        "rate_limit_pps": 20000,
        "need_review": True,
        "rollback_hint": "review authoritative dns exposure before production push",
    },
    {
        "match": "Application Attack/DNS",
        "attack_type": "DNS_APP",
        "action": "huawei_acl_udp_dns_drop",
        "protocol": "udp",
        "ports": [53],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 20000,
        "need_review": True,
        "rollback_hint": "review against recursive and authoritative dns exposure before block",
    },
    {
        "match": "Application Attack/SIP",
        "attack_type": "SIP_APP",
        "action": "huawei_acl_udp_sip_drop",
        "protocol": "udp",
        "ports": [5060, 5061],
        "severity": "high",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 10000,
        "need_review": True,
        "rollback_hint": "review voice impact before block",
    },
    {
        "match": "Application Attack/DTLS",
        "attack_type": "DTLS_APP",
        "action": "huawei_acl_udp_dtls_drop",
        "protocol": "udp",
        "ports": [443, 4433, 5684],
        "severity": "medium",
        "confidence": "medium",
        "ttl_seconds": 1800,
        "rate_limit_pps": 10000,
        "need_review": True,
        "rollback_hint": "review dtls service impact before block",
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Map classified PCAPs to policy jobs")
    parser.add_argument("classified_root", help="Root directory generated by ddos_classifier_v5_2.py")
    parser.add_argument(
        "--output",
        default="./policy_jobs.jsonl",
        help="Output JSONL path (default: ./policy_jobs.jsonl)",
    )
    return parser.parse_args()


def pick_rule(category: str) -> dict:
    for rule in ATTACK_RULES:
        if category.startswith(rule["match"]):
            return rule
    return {
        "attack_type": "UNKNOWN_DDOS",
        "action": "huawei_review_only",
        "protocol": "ip",
        "ports": [],
        "severity": "medium",
        "confidence": "low",
        "ttl_seconds": 900,
        "rate_limit_pps": None,
        "need_review": True,
        "rollback_hint": "manual review required before dispatch",
    }


def parse_filename(path: Path) -> tuple[str, str, str]:
    stem = path.stem
    parts = stem.split("_")
    if len(parts) < 3:
        raise ValueError(f"unexpected filename format: {path.name}")

    seq = None
    if parts[-1].isdigit() and len(parts) >= 4 and DATE_RE.match(parts[-2]):
        seq = parts.pop()
    if not DATE_RE.match(parts[-1]):
        raise ValueError(f"missing YYYYMMDD token in filename: {path.name}")
    date = parts.pop()

    body = "_".join(parts)
    if IPV4_RE.match(parts[0]):
        victim_ip = parts[0]
        suffix = "_".join(parts[1:]) or "unknown"
    else:
        victim_ip = parts[0]
        suffix = "_".join(parts[1:]) or "unknown"
        if ":" not in victim_ip and "_" in victim_ip:
            victim_ip = victim_ip.replace("_", ":")

    if seq is not None:
        suffix = suffix or "unknown"
    return victim_ip, suffix, date


def classify_file(path: Path, root: Path) -> PolicyJob:
    rel = path.relative_to(root)
    if len(rel.parts) < 2:
        raise ValueError(f"unexpected classified path: {path}")

    category_parts = list(rel.parts[:-1])
    ip_version = "unknown"
    if category_parts and category_parts[-1] in {"IPv4", "IPv6"}:
        ip_version = category_parts[-1]
        category_parts = category_parts[:-1]
    category = "/".join(category_parts)
    victim_ip, suffix, capture_date = parse_filename(path)
    rule = pick_rule(category)

    digest = hashlib.sha1(str(rel).encode("utf-8")).hexdigest()[:12]
    job_id = f"job-{digest}"
    created_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

    return PolicyJob(
        job_id=job_id,
        created_at=created_at,
        source_pcap=str(path.resolve()),
        category=category,
        ip_version=ip_version,
        victim_ip=victim_ip,
        attack_suffix=suffix,
        attack_type=rule["attack_type"],
        severity=rule["severity"],
        confidence=rule["confidence"],
        action=rule["action"],
        protocol=rule["protocol"],
        target_ports=rule["ports"],
        rate_limit_pps=rule["rate_limit_pps"],
        ttl_seconds=rule["ttl_seconds"],
        need_review=rule["need_review"],
        rollback_hint=rule["rollback_hint"],
        evidence={
            "capture_date": capture_date,
            "relative_path": str(rel),
            "file_size_bytes": path.stat().st_size,
        },
    )


def main() -> None:
    args = parse_args()
    root = Path(args.classified_root).resolve()
    if not root.exists():
        raise SystemExit(f"classified root not found: {root}")

    pcap_files = sorted(root.rglob("*.pcap"))
    if not pcap_files:
        raise SystemExit(f"no pcap files found under: {root}")

    jobs = [classify_file(path, root) for path in pcap_files]

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for job in jobs:
            fh.write(json.dumps(asdict(job), ensure_ascii=False) + "\n")

    attack_summary: dict[str, int] = {}
    for job in jobs:
        attack_summary[job.attack_type] = attack_summary.get(job.attack_type, 0) + 1

    print(f"mapped {len(jobs)} policy jobs")
    print(f"output: {output}")
    for attack_type, count in sorted(attack_summary.items()):
        print(f"  {attack_type}: {count}")


if __name__ == "__main__":
    main()
