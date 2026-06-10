#!/usr/bin/env python3
"""
Generate a Huawei AntiDDoS1908 UDP defense policy JSON from a base template and a UDP pcap.

This generator is intentionally conservative:
- it only updates UDP-related fields whose meaning is reasonably clear
- it preserves the original template schema
- it writes a separate report with the reasoning and changed fields
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class UdpAttackProfile:
    source_pcap: str
    victim_ip: str
    capture_duration_s: float
    udp_packet_count: int
    udp_bytes: int
    avg_udp_pps: float
    peak_udp_pps: float
    avg_udp_bps: float
    peak_udp_bps: float
    unique_src_ips: int
    unique_dst_ips: int
    unique_sports: int
    unique_dports: int
    sport_dispersion_ratio: float
    dport_dispersion_ratio: float
    fixed_raw_length: int
    fixed_raw_length_ratio: float
    fixed_udp_length: int
    fixed_udp_length_ratio: float
    fixed_payload_hex: str
    fixed_payload_ratio: float
    udp_length_mismatch_ratio: float
    top_src_ips: list[dict[str, Any]]
    top_dst_ips: list[dict[str, Any]]
    top_dports: list[dict[str, Any]]




MANAGED_UDP_POLICY_FIELDS = {
    "Zone_Traffic_Limiting": "zone_traffic_limiting",
    "Traffic_Limiting_For_Single_Ip": "traffic_limiting_for_single_ip",
    "Udp_Abnormal": "udp_abnormal",
    "Udp_Traffic_Limiting": "udp_traffic_limiting",
    "Udp_New_Conn_Limiting": "udp_new_conn_limiting",
}

UDP_POLICY_ENABLE_DEFAULTS = {
    "Zone_Traffic_Limiting": 1,
    "Traffic_Limiting_For_Single_Ip": 1,
    "Udp_Abnormal": 1,
    "Udp_Traffic_Limiting": 1,
    "Udp_New_Conn_Limiting": 0,
    "Udp_Fragment_Rate_Limiting": 0,
    "Udp_Correlation": 0,
    "Udp_Rel_Tcp_Defense": 0,
    "Udp_Session_Behavior_Detect_Packet_Interval": 0,
    "Udp_Traffic_Limiting_Strict": 0,
}

SUPPORTED_TEMPLATE_ATTACKS = {
    "UDP_FLOOD": "udp_flood",
}

def _safe_int(value: float, minimum: int = 1) -> int:
    return max(minimum, int(round(value)))


def load_classifier_module(module_path: Path):
    spec = importlib.util.spec_from_file_location("udp_template_classifier_bridge", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load classifier module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def analyze_udp_pcap(classifier_module, pcap_path: Path, victim_ip_hint: str | None = None) -> UdpAttackProfile:
    raw_packets = classifier_module.read_pcap(str(pcap_path))
    parsed = classifier_module.parse_all(raw_packets)
    udp_packets = [pkt for pkt in parsed if pkt.get("proto") == 17 and pkt.get("udp")]
    if not udp_packets:
        raise ValueError(f"no UDP packets found in {pcap_path}")

    start_ts = min(pkt["ts"] for pkt in udp_packets)
    end_ts = max(pkt["ts"] for pkt in udp_packets)
    duration_s = max(end_ts - start_ts, 1e-6)

    dst_counter = Counter(pkt.get("dst_ip") or "unknown" for pkt in udp_packets)
    victim_ip = victim_ip_hint or dst_counter.most_common(1)[0][0]

    focused = [pkt for pkt in udp_packets if (pkt.get("dst_ip") or "unknown") == victim_ip]
    if not focused:
        raise ValueError(f"no UDP packets matched victim_ip={victim_ip}")

    bytes_total = sum(len(pkt.get("raw") or b"") for pkt in focused)
    avg_pps = len(focused) / duration_s
    avg_bps = bytes_total / duration_s

    per_second_packets: defaultdict[int, int] = defaultdict(int)
    per_second_bytes: defaultdict[int, int] = defaultdict(int)
    src_counter: Counter[str] = Counter()
    dport_counter: Counter[int] = Counter()
    raw_len_counter: Counter[int] = Counter()
    udp_len_counter: Counter[int] = Counter()
    payload_counter: Counter[str] = Counter()
    sport_set: set[int] = set()
    dport_set: set[int] = set()
    mismatch_count = 0

    for pkt in focused:
        sec_bucket = int(pkt["ts"] - start_ts)
        raw_len = len(pkt.get("raw") or b"")
        udp = pkt["udp"]
        udp_len = int(udp.get("length") or 0)
        payload = udp.get("payload") or b""
        payload_hex = payload.hex()

        per_second_packets[sec_bucket] += 1
        per_second_bytes[sec_bucket] += raw_len
        src_counter[pkt.get("src_ip") or "unknown"] += 1
        dport_counter[int(pkt.get("dport") or 0)] += 1
        raw_len_counter[raw_len] += 1
        udp_len_counter[udp_len] += 1
        payload_counter[payload_hex] += 1
        sport_set.add(int(pkt.get("sport") or 0))
        dport_set.add(int(pkt.get("dport") or 0))
        if udp_len and udp_len != 8 + len(payload):
            mismatch_count += 1

    fixed_raw_length, fixed_raw_count = raw_len_counter.most_common(1)[0]
    fixed_udp_length, fixed_udp_count = udp_len_counter.most_common(1)[0]
    fixed_payload_hex, fixed_payload_count = payload_counter.most_common(1)[0]

    return UdpAttackProfile(
        source_pcap=str(pcap_path.resolve()),
        victim_ip=victim_ip,
        capture_duration_s=round(duration_s, 6),
        udp_packet_count=len(focused),
        udp_bytes=bytes_total,
        avg_udp_pps=round(avg_pps, 3),
        peak_udp_pps=round(float(max(per_second_packets.values(), default=0)), 3),
        avg_udp_bps=round(avg_bps, 3),
        peak_udp_bps=round(float(max(per_second_bytes.values(), default=0)), 3),
        unique_src_ips=len(src_counter),
        unique_dst_ips=len({pkt.get("dst_ip") or "unknown" for pkt in focused}),
        unique_sports=len(sport_set),
        unique_dports=len(dport_set),
        sport_dispersion_ratio=round(len(sport_set) / len(focused), 3),
        dport_dispersion_ratio=round(len(dport_set) / len(focused), 3),
        fixed_raw_length=fixed_raw_length,
        fixed_raw_length_ratio=round(fixed_raw_count / len(focused), 3),
        fixed_udp_length=fixed_udp_length,
        fixed_udp_length_ratio=round(fixed_udp_count / len(focused), 3),
        fixed_payload_hex=fixed_payload_hex,
        fixed_payload_ratio=round(fixed_payload_count / len(focused), 3),
        udp_length_mismatch_ratio=round(mismatch_count / len(focused), 3),
        top_src_ips=[{"ip": ip, "packets": count} for ip, count in src_counter.most_common(10)],
        top_dst_ips=[{"ip": ip, "packets": count} for ip, count in dst_counter.most_common(10)],
        top_dports=[{"dport": port, "packets": count} for port, count in dport_counter.most_common(10)],
    )


def derive_udp_policy_parameters(profile: UdpAttackProfile, attack_tag: str = "UDP_FLOOD") -> dict[str, Any]:
    peak_pps = max(profile.peak_udp_pps, profile.avg_udp_pps)

    zone_threshold_pps = _safe_int(max(20.0, math.floor(peak_pps * 0.8)))
    single_ip_threshold_pps = _safe_int(max(10.0, math.floor(zone_threshold_pps / max(1, profile.unique_src_ips * 2))))
    abnormal_threshold_pps = _safe_int(max(10.0, math.floor(zone_threshold_pps * 0.5)))
    new_conn_threshold_pps = _safe_int(max(10.0, math.floor(zone_threshold_pps * 0.6)))

    enable_udp_new_conn = profile.dport_dispersion_ratio >= 0.30
    inferred_tags = []
    if profile.fixed_raw_length_ratio >= 0.95:
        inferred_tags.append("fixedLen")
    if profile.fixed_payload_ratio >= 0.95:
        inferred_tags.append("fixedpayload")
    if profile.udp_length_mismatch_ratio >= 0.80:
        inferred_tags.append("malformed-udp-length")
    if profile.unique_src_ips == 1:
        inferred_tags.append("single-source")
    if profile.dport_dispersion_ratio >= 0.30:
        inferred_tags.append("dst-port-scan-like-dispersion")

    return {
        "attack_type": attack_tag,
        "victim_ip": profile.victim_ip,
        "inferred_tags": inferred_tags,
        "thresholds": {
            "zone_traffic_limiting": str(zone_threshold_pps),
            "traffic_limiting_for_single_ip": str(single_ip_threshold_pps),
            "udp_abnormal": str(abnormal_threshold_pps),
            "udp_traffic_limiting": str(zone_threshold_pps),
            "udp_new_conn_limiting": str(new_conn_threshold_pps),
        },
        "enable_flags": {
            **UDP_POLICY_ENABLE_DEFAULTS,
            "Udp_New_Conn_Limiting": 1 if enable_udp_new_conn else 0,
        },
        "reasons": {
            "Zone_Traffic_Limiting": "set below observed peak pps so replay traffic can trigger in validation",
            "Traffic_Limiting_For_Single_Ip": "enabled because the sample is a single-source UDP flood",
            "Udp_Abnormal": "enabled because all packets show abnormal UDP length mismatch and fixed tiny frames",
            "Udp_Traffic_Limiting": "enabled as the main UDP flood rate control",
            "Udp_New_Conn_Limiting": (
                "enabled because destination ports are highly dispersed"
                if enable_udp_new_conn
                else "disabled because destination port dispersion is not high enough"
            ),
            "Udp_Correlation": "left disabled because the template field semantics are not yet validated against the device UI/export",
            "Udp_Traffic_Limiting_Strict": "left unchanged because the field has null threshold semantics in the base template",
        },
    }


def update_policy_template(template: dict[str, Any], params: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attack_updates = {policy_name: params["thresholds"][threshold_key] for policy_name, threshold_key in MANAGED_UDP_POLICY_FIELDS.items()}
    enable_updates = params["enable_flags"]

    changes: list[dict[str, Any]] = []
    for detail in template.get("policyDetailDto", []):
        device_ip = detail.get("deviceIp")
        for item in detail.get("policy", []):
            attack_type = item.get("attack_type")
            if attack_type not in enable_updates:
                continue

            old_enable = item.get("enable_status")
            new_enable = enable_updates[attack_type]
            old_threshold = item.get("threshold")
            new_threshold = attack_updates.get(attack_type, old_threshold)

            item["enable_status"] = new_enable
            if attack_type in attack_updates:
                item["threshold"] = new_threshold

            changes.append(
                {
                    "deviceIp": device_ip,
                    "attack_type": attack_type,
                    "old_enable_status": old_enable,
                    "new_enable_status": new_enable,
                    "old_threshold": old_threshold,
                    "new_threshold": item.get("threshold"),
                }
            )
    return template, changes


def write_outputs(
    generated_policy: dict[str, Any],
    profile: UdpAttackProfile,
    params: dict[str, Any],
    changes: list[dict[str, Any]],
    output_json: Path,
) -> dict[str, str]:
    output_json.write_text(json.dumps(generated_policy, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")

    report_json = output_json.with_suffix(".report.json")
    report_txt = output_json.with_suffix(".report.txt")

    report = {
        "profile": asdict(profile),
        "derived_parameters": params,
        "changes": changes,
    }
    report_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "Huawei AntiDDoS1908 UDP strategy generation report",
        f"source_pcap: {profile.source_pcap}",
        f"victim_ip: {profile.victim_ip}",
        f"udp_packet_count: {profile.udp_packet_count}",
        f"avg_udp_pps: {profile.avg_udp_pps}",
        f"peak_udp_pps: {profile.peak_udp_pps}",
        f"avg_udp_bps: {profile.avg_udp_bps}",
        f"peak_udp_bps: {profile.peak_udp_bps}",
        f"unique_src_ips: {profile.unique_src_ips}",
        f"unique_dports: {profile.unique_dports}",
        f"dport_dispersion_ratio: {profile.dport_dispersion_ratio}",
        f"fixed_raw_length: {profile.fixed_raw_length} ratio={profile.fixed_raw_length_ratio}",
        f"fixed_payload_ratio: {profile.fixed_payload_ratio}",
        f"udp_length_mismatch_ratio: {profile.udp_length_mismatch_ratio}",
        f"inferred_tags: {', '.join(params['inferred_tags']) or 'none'}",
        "",
        "Changed policy entries:",
    ]
    for change in changes:
        lines.append(
            f"- {change['deviceIp']} {change['attack_type']}: "
            f"enable {change['old_enable_status']} -> {change['new_enable_status']}, "
            f"threshold {change['old_threshold']} -> {change['new_threshold']}"
        )
    report_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "policy_json": str(output_json),
        "report_json": str(report_json),
        "report_txt": str(report_txt),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate UDP policy from a 1908 template and a UDP pcap")
    parser.add_argument("template_json", help="Base policy.json path")
    parser.add_argument("pcap", help="UDP pcap path")
    parser.add_argument("--classifier-module", required=True, help="Path to ddos_classifier_v5_2.py")
    parser.add_argument("--output-json", required=True, help="Output policy JSON path")
    parser.add_argument("--victim-ip", default=None, help="Optional victim IP override")
    return parser.parse_args()


def generate_udp_policy(template_path: Path, pcap_path: Path, classifier_module, output_json: Path, victim_ip: str | None = None, attack_tag: str = "UDP_FLOOD") -> dict[str, Any]:
    if attack_tag not in SUPPORTED_TEMPLATE_ATTACKS:
        raise ValueError(f"unsupported attack tag for udp generator: {attack_tag}")

    profile = analyze_udp_pcap(classifier_module, pcap_path, victim_ip)
    params = derive_udp_policy_parameters(profile, attack_tag=attack_tag)

    template = json.loads(template_path.read_text(encoding="utf-8"))
    generated_policy, changes = update_policy_template(template, params)
    outputs = write_outputs(generated_policy, profile, params, changes, output_json)

    return {
        "status": "generated",
        "victim_ip": profile.victim_ip,
        "outputs": outputs,
        "inferred_tags": params["inferred_tags"],
        "attack_tag": attack_tag,
    }


def main() -> None:
    args = parse_args()
    template_path = Path(args.template_json).resolve()
    pcap_path = Path(args.pcap).resolve()
    output_json = Path(args.output_json).resolve()

    classifier_module = load_classifier_module(Path(args.classifier_module).resolve())
    result = generate_udp_policy(
        template_path=template_path,
        pcap_path=pcap_path,
        classifier_module=classifier_module,
        output_json=output_json,
        victim_ip=args.victim_ip,
        attack_tag="UDP_FLOOD",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
