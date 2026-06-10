#!/usr/bin/env python3
"""
Generate AntiDDoS1908 DNS request flood template parameters from a classified pcap.

This module focuses on the user's TC source-auth cleaning logic:

1. Detection:
   - if udp_in_bps >= threshold_bps OR udp_in_pps >= threshold_pps
   - and destination port is 53
   - then classify/confirm as DNS request flood

2. Cleaning:
   - enable TC-based source authentication
   - answer with TC=1 to force a TCP retry
   - only whitelist clients that re-establish via TCP successfully

The current Huawei manual in the workspace documents the standard DNS request
flood source-detect knobs, but does not expose an exact CLI for this TC
source-auth variant. For that reason this module writes:

- machine-friendly JSON parameters
- a reviewable text summary
- a CLI-like draft with documented commands plus logical TC-auth fields
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class DnsRequestFloodProfile:
    source_pcap: str
    victim_ip: str
    attack_port: int
    capture_duration_s: float
    inbound_request_packets: int
    inbound_request_bytes: int
    inbound_response_packets: int
    inbound_tcp_syn_packets: int
    avg_udp_in_pps: float
    peak_udp_in_pps: float
    avg_udp_in_bps: float
    peak_udp_in_bps: float
    unique_src_ips: int
    unique_query_names: int
    query_dispersion_ratio: float
    top_src_ips: list[dict[str, Any]]
    top_query_names: list[dict[str, Any]]


def _safe_int(value: float, minimum: int = 1) -> int:
    return max(minimum, int(round(value)))


def _choose_victim_ip(parsed: list[dict[str, Any]], parse_dns) -> str | None:
    candidates: Counter[str] = Counter()
    for pkt in parsed:
        if pkt.get("proto") != 17 or not pkt.get("udp") or pkt.get("dport") != 53:
            continue
        dns = parse_dns(pkt["udp"]["payload"])
        if dns is None or dns.get("is_response"):
            continue
        if pkt.get("dst_ip"):
            candidates[pkt["dst_ip"]] += 1
    if not candidates:
        return None
    return candidates.most_common(1)[0][0]


def analyze_dns_request_flood(
    classifier_module,
    pcap_path: Path,
    victim_ip_hint: str | None = None,
) -> DnsRequestFloodProfile:
    parse_dns = classifier_module.parse_dns
    raw_packets = classifier_module.read_pcap(str(pcap_path))
    parsed = classifier_module.parse_all(raw_packets)
    if not parsed:
        raise ValueError(f"no parsed packets found in {pcap_path}")

    victim_ip = victim_ip_hint or _choose_victim_ip(parsed, parse_dns)
    if not victim_ip:
        raise ValueError(f"unable to infer DNS request flood victim from {pcap_path}")

    request_packets: list[dict[str, Any]] = []
    response_packets: list[dict[str, Any]] = []
    tcp_syn_packets: list[dict[str, Any]] = []
    top_src_ips: Counter[str] = Counter()
    top_query_names: Counter[str] = Counter()
    unique_query_names: set[str] = set()
    per_second_packets: defaultdict[int, int] = defaultdict(int)
    per_second_bytes: defaultdict[int, int] = defaultdict(int)

    start_ts = min(pkt["ts"] for pkt in parsed)
    end_ts = max(pkt["ts"] for pkt in parsed)
    duration_s = max(end_ts - start_ts, 1e-6)

    for pkt in parsed:
        proto = pkt.get("proto")
        if proto == 17 and pkt.get("udp"):
            udp = pkt["udp"]
            dns = parse_dns(udp["payload"])
            if dns is None:
                continue

            if pkt.get("dst_ip") == victim_ip and pkt.get("dport") == 53 and not dns.get("is_response"):
                request_packets.append(pkt)
                top_src_ips[pkt.get("src_ip") or "unknown"] += 1
                for q in dns.get("questions", []):
                    name = (q.get("name") or "").lower()
                    if name:
                        unique_query_names.add(name)
                        top_query_names[name] += 1
                sec_bucket = int(pkt["ts"] - start_ts)
                pkt_len = len(pkt.get("raw") or b"")
                per_second_packets[sec_bucket] += 1
                per_second_bytes[sec_bucket] += pkt_len

            elif pkt.get("src_ip") == victim_ip and pkt.get("sport") == 53 and dns.get("is_response"):
                response_packets.append(pkt)

        elif proto == 6 and pkt.get("tcp"):
            tcp = pkt["tcp"]
            if (
                pkt.get("dst_ip") == victim_ip
                and pkt.get("dport") == 53
                and tcp.get("SYN")
                and not tcp.get("ACK")
            ):
                tcp_syn_packets.append(pkt)

    inbound_request_packets = len(request_packets)
    if inbound_request_packets == 0:
        raise ValueError(f"no inbound DNS requests to port 53 found for victim {victim_ip}")

    inbound_request_bytes = sum(len(pkt.get("raw") or b"") for pkt in request_packets)
    avg_udp_in_pps = inbound_request_packets / duration_s
    avg_udp_in_bps = inbound_request_bytes / duration_s
    peak_udp_in_pps = float(max(per_second_packets.values(), default=0))
    peak_udp_in_bps = float(max(per_second_bytes.values(), default=0))
    query_dispersion_ratio = len(unique_query_names) / inbound_request_packets

    return DnsRequestFloodProfile(
        source_pcap=str(pcap_path.resolve()),
        victim_ip=victim_ip,
        attack_port=53,
        capture_duration_s=round(duration_s, 6),
        inbound_request_packets=inbound_request_packets,
        inbound_request_bytes=inbound_request_bytes,
        inbound_response_packets=len(response_packets),
        inbound_tcp_syn_packets=len(tcp_syn_packets),
        avg_udp_in_pps=round(avg_udp_in_pps, 3),
        peak_udp_in_pps=round(peak_udp_in_pps, 3),
        avg_udp_in_bps=round(avg_udp_in_bps, 3),
        peak_udp_in_bps=round(peak_udp_in_bps, 3),
        unique_src_ips=len(top_src_ips),
        unique_query_names=len(unique_query_names),
        query_dispersion_ratio=round(query_dispersion_ratio, 3),
        top_src_ips=[
            {"ip": ip, "packets": count}
            for ip, count in top_src_ips.most_common(10)
        ],
        top_query_names=[
            {"query_name": name, "packets": count}
            for name, count in top_query_names.most_common(10)
        ],
    )


def build_dns_request_template_params(profile: DnsRequestFloodProfile) -> dict[str, Any]:
    peak_pps = max(profile.peak_udp_in_pps, profile.avg_udp_in_pps)
    peak_bps = max(profile.peak_udp_in_bps, profile.avg_udp_in_bps)

    # Trigger below the observed peak so the sample can replay-trigger.
    udp_in_pps_threshold = _safe_int(max(5.0, math.floor(peak_pps * 0.8)))
    udp_in_bps_threshold = _safe_int(max(512.0, math.floor(peak_bps * 0.8)))

    # Aggressive leak-prevention-first rate for the observed source pattern.
    src_divisor = max(profile.unique_src_ips * 2, 2)
    source_ip_max_rate_pps = _safe_int(max(1.0, udp_in_pps_threshold / src_divisor))

    # If the traffic is heavily dispersed across domains, per-domain limit is not useful.
    enable_domain_limit = profile.query_dispersion_ratio < 0.3

    # Conservative default: use passive mode unless we later prove this is a clean
    # authoritative-DNS scenario with TCP-capable clients.
    tc_source_auth_mode = "passive-tc"

    return {
        "template_name": "antiddos1908_dns_request_flood_tc_source_auth",
        "attack_type": "DNS_REQUEST_FLOOD",
        "victim_ip": profile.victim_ip,
        "service": {
            "protocol": "udp",
            "dst_port": 53,
        },
        "detection_logic": {
            "match": "dst_port == 53 and (udp_in_bps >= udp_in_bps_threshold or udp_in_pps >= udp_in_pps_threshold)",
            "udp_in_pps_threshold": udp_in_pps_threshold,
            "udp_in_bps_threshold": udp_in_bps_threshold,
            "observed_peak_udp_in_pps": profile.peak_udp_in_pps,
            "observed_peak_udp_in_bps": profile.peak_udp_in_bps,
        },
        "defense_strategy": {
            "tc_source_auth_enabled": True,
            "tc_source_auth_mode": tc_source_auth_mode,
            "send_tc_response": True,
            "force_tcp_retry": True,
            "tcp_syn_authentication": True,
            "whitelist_on_tcp_auth_success": True,
            "whitelist_aging_seconds": 600,
            "auth_timeout_seconds": 3,
            "pending_auth_max_sources": 4096,
        },
        "rate_controls": {
            "source_ip_limit_enabled": True,
            "source_ip_limit_mode": "auto",
            "source_ip_max_rate_pps": source_ip_max_rate_pps,
            "domain_name_limit_enabled": enable_domain_limit,
            "domain_name_limit_reason": (
                "disabled because query names are highly dispersed"
                if not enable_domain_limit
                else "enabled because query concentration is high enough to benefit from per-domain throttling"
            ),
        },
        "profile_summary": asdict(profile),
        "review_flags": {
            "need_tcp_capable_dns_clients": True,
            "need_dns_cache_or_tcp_query_client_scenario": True,
            "safe_for_replay_validation": True,
            "safe_for_direct_production_push": False,
        },
    }


def render_dns_request_template_text(params: dict[str, Any]) -> str:
    detection = params["detection_logic"]
    defense = params["defense_strategy"]
    rate = params["rate_controls"]
    profile = params["profile_summary"]

    lines = [
        "AntiDDoS1908 DNS Request Flood template draft",
        f"victim_ip: {params['victim_ip']}",
        f"source_pcap: {profile['source_pcap']}",
        "",
        "Detection logic:",
        f"- dst_port == 53",
        f"- udp_in_pps threshold: {detection['udp_in_pps_threshold']} pps",
        f"- udp_in_bps threshold: {detection['udp_in_bps_threshold']} Bps",
        f"- trigger condition: udp_in_bps >= threshold OR udp_in_pps >= threshold",
        "",
        "TC source-auth strategy:",
        f"- tc_source_auth_enabled: {defense['tc_source_auth_enabled']}",
        f"- mode: {defense['tc_source_auth_mode']}",
        f"- send_tc_response: {defense['send_tc_response']}",
        f"- force_tcp_retry: {defense['force_tcp_retry']}",
        f"- tcp_syn_authentication: {defense['tcp_syn_authentication']}",
        f"- whitelist_on_tcp_auth_success: {defense['whitelist_on_tcp_auth_success']}",
        f"- whitelist_aging_seconds: {defense['whitelist_aging_seconds']}",
        f"- auth_timeout_seconds: {defense['auth_timeout_seconds']}",
        "",
        "Supporting controls:",
        f"- source_ip_limit_mode: {rate['source_ip_limit_mode']}",
        f"- source_ip_max_rate_pps: {rate['source_ip_max_rate_pps']}",
        f"- domain_name_limit_enabled: {rate['domain_name_limit_enabled']}",
        f"- domain_name_limit_reason: {rate['domain_name_limit_reason']}",
        "",
        "Observed pcap profile:",
        f"- capture_duration_s: {profile['capture_duration_s']}",
        f"- inbound_request_packets: {profile['inbound_request_packets']}",
        f"- inbound_response_packets: {profile['inbound_response_packets']}",
        f"- avg_udp_in_pps: {profile['avg_udp_in_pps']}",
        f"- peak_udp_in_pps: {profile['peak_udp_in_pps']}",
        f"- avg_udp_in_bps: {profile['avg_udp_in_bps']}",
        f"- peak_udp_in_bps: {profile['peak_udp_in_bps']}",
        f"- unique_src_ips: {profile['unique_src_ips']}",
        f"- unique_query_names: {profile['unique_query_names']}",
        f"- query_dispersion_ratio: {profile['query_dispersion_ratio']}",
    ]
    return "\n".join(lines) + "\n"


def render_dns_request_template_cfg(params: dict[str, Any]) -> str:
    detection = params["detection_logic"]
    defense = params["defense_strategy"]
    rate = params["rate_controls"]

    lines = [
        "# AntiDDoS1908 DNS request flood template draft",
        f"# victim_ip={params['victim_ip']}",
        f"# detection_logic: dst_port == 53 and (udp_in_bps >= {detection['udp_in_bps_threshold']} or udp_in_pps >= {detection['udp_in_pps_threshold']})",
        "system-view",
        "ddos-zone name dzone",
        f"anti-ddos confirm attack-type dns-request-flood ip {params['victim_ip']}",
        f"anti-ddos dns-request-flood source-detect mode passive alert-rate {detection['udp_in_pps_threshold']}",
        "anti-ddos dns-request-flood source-detect top-domain enable",
        f"anti-ddos dns-request-limit source-ip other auto max-rate {rate['source_ip_max_rate_pps']}",
        "",
        "# Logical TC source-auth fields below need mapping to the actual 1908 template/UI fields.",
        f"# tc_source_auth_enabled = {str(defense['tc_source_auth_enabled']).lower()}",
        f"# send_tc_response = {str(defense['send_tc_response']).lower()}",
        f"# force_tcp_retry = {str(defense['force_tcp_retry']).lower()}",
        f"# tcp_syn_authentication = {str(defense['tcp_syn_authentication']).lower()}",
        f"# whitelist_on_tcp_auth_success = {str(defense['whitelist_on_tcp_auth_success']).lower()}",
        f"# whitelist_aging_seconds = {defense['whitelist_aging_seconds']}",
        f"# auth_timeout_seconds = {defense['auth_timeout_seconds']}",
        f"# pending_auth_max_sources = {defense['pending_auth_max_sources']}",
        "return",
    ]
    return "\n".join(lines) + "\n"


def write_dns_request_template_bundle(
    classifier_module,
    pcap_path: Path,
    output_prefix: Path,
    victim_ip_hint: str | None = None,
) -> dict[str, Any]:
    profile = analyze_dns_request_flood(
        classifier_module=classifier_module,
        pcap_path=pcap_path,
        victim_ip_hint=victim_ip_hint,
    )
    params = build_dns_request_template_params(profile)

    json_path = Path(f"{output_prefix}.json")
    txt_path = Path(f"{output_prefix}.txt")
    cfg_path = Path(f"{output_prefix}.cfg")

    json_path.write_text(json.dumps(params, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    txt_path.write_text(render_dns_request_template_text(params), encoding="utf-8")
    cfg_path.write_text(render_dns_request_template_cfg(params), encoding="utf-8")

    return {
        "status": "generated",
        "json_path": str(json_path),
        "txt_path": str(txt_path),
        "cfg_path": str(cfg_path),
        "victim_ip": profile.victim_ip,
        "attack_type": "DNS_REQUEST_FLOOD",
        "udp_in_pps_threshold": params["detection_logic"]["udp_in_pps_threshold"],
        "udp_in_bps_threshold": params["detection_logic"]["udp_in_bps_threshold"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate DNS request flood template parameters from a pcap")
    parser.add_argument("pcap", help="Input pcap path")
    parser.add_argument("--classifier-module", required=True, help="Path to ddos_classifier_v5_2.py")
    parser.add_argument("--output-prefix", required=True, help="Output prefix without extension")
    parser.add_argument("--victim-ip", default=None, help="Optional victim IP override")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    import importlib.util

    module_path = Path(args.classifier_module).resolve()
    spec = importlib.util.spec_from_file_location("dns_request_flood_classifier_bridge", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load classifier module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    result = write_dns_request_template_bundle(
        classifier_module=module,
        pcap_path=Path(args.pcap).resolve(),
        output_prefix=Path(args.output_prefix).resolve(),
        victim_ip_hint=args.victim_ip,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
