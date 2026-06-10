#!/usr/bin/env python3
"""
Run the post-classification Huawei workflow end to end.

This wrapper keeps the existing fallback dispatcher intact:

classified pcaps -> policy jobs -> Huawei command bundle

When a benign baseline pcap is available, it also runs ConfScrub for the
Huawei attack families it natively supports and writes reviewable parameter
recommendations alongside the command bundle.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import socket
import struct
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from huawei_dispatcher import safe_name, write_bundle
from policy_mapper import classify_file
from dns_request_flood_template import write_dns_request_template_bundle
from udp_template_generator import generate_udp_policy


PROJECT_ROOT = Path(__file__).resolve().parents[1]


SUPPORTED_CONFSCRUB_ATTACKS = {
    "SYN_FLOOD": {
        "data_stub": "synflood",
        "family": "syn_defense",
    },
    "TCP_SYNACK_FLOOD": {
        "data_stub": "synack",
        "family": "synack_defense",
    },
    "ACK_FLOOD": {
        "data_stub": "ackflood",
        "family": "ack_defense",
    },
    "TCP_STATE_EXHAUSTION": {
        "data_stub": "connflood",
        "family": "conn_defense",
    },
}

HUAWEI_PARAM_MAPPING = {
    "TCP Countermeasures -> SYN Flood Defense: DstIP threshold": ("syn_defense", "dst_syn_threshold_pps"),
    "TCP Countermeasures -> SYN Flood Defense -> Abnormal srcIP detection -> SrcIP blocking: SYN-ratio threshold": (
        "syn_defense",
        "detect_ratio_threshold",
    ),
    "TCP Countermeasures -> SYN Flood Defense -> Abnormal srcIP detection -> SrcIP blocking: SYN packets threshold": (
        "syn_defense",
        "detect_syn_threshold",
    ),
    "TCP Countermeasures -> SYN Flood Defense -> Abnormal srcIP detection -> SrcIP blocking: Anomaly times threshold": (
        "syn_defense",
        "anomaly_times_threshold",
    ),
    "TCP Countermeasures -> SYN-ACK Flood Defense: DstIP threshold": ("synack_defense", "dst_synack_threshold_pps"),
    "TCP Countermeasures -> SYN-ACK Flood Defense -> Abnormal srcIP detection -> SrcIP blocking: Packets per connection threshold": (
        "synack_defense",
        "detect_ack_threshold",
    ),
    "TCP Countermeasures -> SYN-ACK Flood Defense -> Abnormal srcIP detection -> SrcIP blocking: Abnormal connections threshold": (
        "synack_defense",
        "abnormal_connections_threshold",
    ),
    "TCP Countermeasures -> ACK Flood Defense: DstIP threshold": ("ack_defense", "dst_ack_threshold_pps"),
    "TCP Countermeasures -> ACK Flood Defense -> Source high speed requests detection: SrcIP threshold": (
        "ack_defense",
        "src_ack_threshold_pps",
    ),
    "TCP Countermeasures -> ACK Flood Defense -> Abnormal ACK connection detection: Large pkt length": (
        "ack_defense",
        "large_packet_length",
    ),
    "TCP Countermeasures -> ACK Flood Defense -> Abnormal ACK connection detection: Pkt per connection": (
        "ack_defense",
        "packets_per_connection_threshold",
    ),
    "TCP Countermeasures -> ACK Flood Defense -> Abnormal ACK connection detection: Large pkt proportion": (
        "ack_defense",
        "large_packet_ratio_threshold",
    ),
    "TCP Countermeasures -> ACK Flood Defense -> Abnormal ACK connection detection: Abnormal connections threshold": (
        "ack_defense",
        "abnormal_connections_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense: DstIP ConcurConn threshold": (
        "conn_defense",
        "dst_concur_conn_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense: DstIP NewConn threshold": (
        "conn_defense",
        "dst_new_conn_threshold_cps",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense -> SrcIP ConcurConn blocking: ConcurConn threshold": (
        "conn_defense",
        "src_concur_conn_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense -> SrcIP NewConn blocking: NewConn threshold": (
        "conn_defense",
        "src_new_conn_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense -> SrcIP abnormal connections detection -> Null connections detection: Packets per connection threshold": (
        "conn_defense",
        "null_conn_packets_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense -> SrcIP abnormal connections detection -> Null connections detection: Abnormal connections threshold": (
        "conn_defense",
        "null_conn_abnormal_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense -> SrcIP behavior-analysis -> Abnormal SYN connection detection: SYN packets per connection": (
        "conn_defense",
        "abnormal_syn_packets_threshold",
    ),
    "TCP Countermeasures -> TCP Connection Flood Defense -> SrcIP behavior-analysis -> Abnormal SYN connection detection: Abnormal connections threshold": (
        "conn_defense",
        "abnormal_syn_abnormal_threshold",
    ),
}

HUAWEI_DEFAULTS = {
    "syn_defense": {
        "dst_syn_threshold_pps": 2000,
        "detect_ratio_threshold": 90,
        "detect_syn_threshold": 20,
        "anomaly_times_threshold": 3,
    },
    "ack_defense": {
        "dst_ack_threshold_pps": 50000,
        "src_ack_threshold_pps": 500,
        "large_packet_length": 1000,
        "packets_per_connection_threshold": 20,
        "large_packet_ratio_threshold": 90,
        "abnormal_connections_threshold": 3,
    },
    "synack_defense": {
        "dst_synack_threshold_pps": 2000,
        "detect_ack_threshold": 1,
        "abnormal_connections_threshold": 3,
    },
    "conn_defense": {
        "dst_concur_conn_threshold": 20000,
        "dst_new_conn_threshold_cps": 5000,
        "src_concur_conn_threshold": 200,
        "src_new_conn_threshold": 100,
        "null_conn_packets_threshold": 1,
        "null_conn_abnormal_threshold": 3,
        "abnormal_syn_packets_threshold": 5,
        "abnormal_syn_abnormal_threshold": 3,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bridge classified DDoS pcaps into Huawei command bundles and optional ConfScrub recommendations"
    )
    parser.add_argument("classified_root", help="Root directory generated by ddos_classifier_v5_2.py")
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "workdir/policy_done"),
        help="Directory for generated Huawei command bundles (default: project workdir/policy_done)",
    )
    parser.add_argument(
        "--jobs-output",
        default=None,
        help="Optional JSONL output path for normalized policy jobs",
    )
    parser.add_argument(
        "--acl-start",
        type=int,
        default=39000,
        help="Starting ACL number for fallback command templates (default: 39000)",
    )
    parser.add_argument(
        "--confscrub-root",
        default=str(PROJECT_ROOT / "ConfScrub"),
        help="ConfScrub root directory (default: project ConfScrub)",
    )
    parser.add_argument(
        "--classifier-module",
        default=str(PROJECT_ROOT / "核心脚本/攻击分类/ddos_classifier_v5_5.py"),
        help="Path to the classifier module used for dependency-free pcap parsing",
    )
    parser.add_argument(
        "--python-bin",
        default=sys.executable,
        help="Python interpreter used to invoke ConfScrub stages (default: current interpreter)",
    )
    parser.add_argument(
        "--benign-pcap-dir",
        default=None,
        help="Directory containing benign baseline pcaps; victim-IP match is tried before default.pcap",
    )
    parser.add_argument(
        "--default-benign-pcap",
        default=None,
        help="Fallback benign baseline pcap used when victim-specific benign traffic is unavailable",
    )
    parser.add_argument(
        "--skip-confscrub",
        action="store_true",
        help="Only generate the fallback Huawei command bundle and skip ConfScrub enrichment",
    )
    parser.add_argument(
        "--base-template-json",
        default=str(PROJECT_ROOT / "华为antiddos1908/模板/policy.json"),
        help="Base AntiDDoS1908 policy JSON used by template generators",
    )
    return parser.parse_args()


def default_jobs_output(output_dir: Path) -> Path:
    if output_dir.name == "policy_done":
        return output_dir.parent / "policy_jobs" / "policy_jobs.jsonl"
    return output_dir / "policy_jobs.jsonl"


def build_jobs(root: Path) -> list[dict[str, Any]]:
    pcap_files = sorted(root.rglob("*.pcap"))
    if not pcap_files:
        raise SystemExit(f"no pcap files found under: {root}")
    return [asdict(classify_file(path, root)) for path in pcap_files]


def write_jobs_file(jobs: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for job in jobs:
            fh.write(json.dumps(job, ensure_ascii=False) + "\n")


def load_module_from_path(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ip_to_hypervision_int(ip_str: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except OSError:
        return 0


def build_protocol_state(pkt: dict[str, Any]) -> int:
    proto = pkt.get("proto")
    state = 0
    if proto == 1:
        state |= 1 << 2
    elif proto == 2:
        state |= 1 << 3
    elif proto == 17:
        state |= 1 << 8
    elif proto != 6:
        state |= 1 << 9

    tcp = pkt.get("tcp")
    if proto == 6 and tcp:
        if tcp.get("SYN"):
            state |= 1 << 4
        if tcp.get("ACK"):
            state |= 1 << 5
        if tcp.get("FIN"):
            state |= 1 << 6
        if tcp.get("RST"):
            state |= 1 << 7
    return state


def process_pcap_to_hypervision_lines(classifier_module, pcap_path: Path, label_value: int) -> tuple[list[str], list[str]]:
    raw_packets = classifier_module.read_pcap(str(pcap_path))
    parsed_packets = classifier_module.parse_all(raw_packets)
    if not parsed_packets:
        return [], []

    packets_info: list[tuple[int, int, int, int, int, int, int, int]] = []
    for pkt in parsed_packets:
        ts_us = int(pkt["ts"] * 1_000_000)
        ip_ver = 6 if pkt.get("ip_ver") == 6 else 4
        src_ip = ip_to_hypervision_int(pkt.get("src_ip") or "0.0.0.0")
        dst_ip = ip_to_hypervision_int(pkt.get("dst_ip") or "0.0.0.0")
        sport = int(pkt.get("sport") or 0)
        dport = int(pkt.get("dport") or 0)
        state = build_protocol_state(pkt)
        pkt_len = len(pkt.get("raw") or b"")
        packets_info.append((ts_us, ip_ver, src_ip, dst_ip, sport, dport, state, pkt_len))

    packets_info.sort(key=lambda item: item[0])
    base_ts = packets_info[0][0]

    data_lines: list[str] = []
    labels: list[str] = []
    for abs_ts, ip_ver, src_ip, dst_ip, sport, dport, state, pkt_len in packets_info:
        rel_ts = abs_ts - base_ts
        data_lines.append(f"{ip_ver} {src_ip} {dst_ip} {sport} {dport} {rel_ts} {state} {pkt_len}\n")
        labels.append(str(label_value))
    return data_lines, labels


def write_hypervision_inputs(
    classifier_module,
    benign_pcap: Path,
    attack_pcap: Path,
    output_prefix: Path,
) -> tuple[Path, Path]:
    benign_data, benign_labels = process_pcap_to_hypervision_lines(classifier_module, benign_pcap, 0)
    attack_data, attack_labels = process_pcap_to_hypervision_lines(classifier_module, attack_pcap, 1)

    combined: list[tuple[int, str, str]] = []
    for data_line, label in zip(benign_data + attack_data, benign_labels + attack_labels):
        timestamp = int(data_line.split()[5])
        combined.append((timestamp, data_line, label))
    combined.sort(key=lambda item: item[0])

    data_path = Path(f"{output_prefix}.data")
    label_path = Path(f"{output_prefix}.label")
    data_path.write_text("".join(item[1] for item in combined), encoding="utf-8")
    label_path.write_text("".join(item[2] for item in combined), encoding="utf-8")
    return data_path, label_path


def find_benign_pcap(job: dict[str, Any], benign_dir: Path | None, default_benign: Path | None) -> Path | None:
    victim_ip = str(job["victim_ip"])
    victim_file_key = victim_ip.replace(":", "_")

    candidates: list[Path] = []
    if benign_dir is not None:
        candidates.extend(
            [
                benign_dir / f"{victim_ip}.pcap",
                benign_dir / f"{victim_file_key}.pcap",
                benign_dir / f"{victim_file_key}_benign.pcap",
                benign_dir / "default.pcap",
            ]
        )

    if default_benign is not None:
        candidates.append(default_benign)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def run_logged_command(cmd: list[str], cwd: Path, log_path: Path) -> None:
    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    log_text = [
        "$ " + " ".join(shlex.quote(part) for part in cmd),
        "",
        "[stdout]",
        result.stdout.rstrip(),
        "",
        "[stderr]",
        result.stderr.rstrip(),
        "",
        f"[exit_code] {result.returncode}",
        "",
    ]
    log_path.write_text("\n".join(log_text), encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(cmd)}")


def build_review_report(job: dict[str, Any], final_conf_path: Path, benign_pcap: Path) -> dict[str, Any]:
    final_conf = json.loads(final_conf_path.read_text(encoding="utf-8"))
    recommendations = []
    unmapped = []

    for para_path, recommended_value in sorted(final_conf.items()):
        mapping = HUAWEI_PARAM_MAPPING.get(para_path)
        if mapping is None:
            unmapped.append(para_path)
            continue
        family, config_key = mapping
        default_value = HUAWEI_DEFAULTS.get(family, {}).get(config_key)
        recommendations.append(
            {
                "policy_path": para_path,
                "config_section": family,
                "config_key": config_key,
                "recommended_value": recommended_value,
                "default_value": default_value,
                "changed_from_default": default_value != recommended_value,
            }
        )

    return {
        "job_id": job["job_id"],
        "attack_type": job["attack_type"],
        "victim_ip": job["victim_ip"],
        "source_pcap": job["source_pcap"],
        "benign_pcap": str(benign_pcap),
        "final_conf_path": str(final_conf_path),
        "recommendations": recommendations,
        "unmapped_parameters": unmapped,
    }


def write_review_files(report: dict[str, Any], json_path: Path, txt_path: Path) -> None:
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "Huawei scrubber parameter review",
        f"job_id: {report['job_id']}",
        f"attack_type: {report['attack_type']}",
        f"victim_ip: {report['victim_ip']}",
        f"source_pcap: {report['source_pcap']}",
        f"benign_pcap: {report['benign_pcap']}",
        f"final_conf_path: {report['final_conf_path']}",
        "",
        "Recommended parameters:",
    ]

    if report["recommendations"]:
        for item in report["recommendations"]:
            default_value = item["default_value"]
            if default_value is None:
                default_text = "unknown"
            else:
                default_text = str(default_value)
            lines.append(
                f"- {item['config_section']}.{item['config_key']} = {item['recommended_value']} "
                f"(default={default_text}; policy={item['policy_path']})"
            )
    else:
        lines.append("- None")

    if report["unmapped_parameters"]:
        lines.extend(
            [
                "",
                "Unmapped ConfScrub parameters:",
            ]
        )
        for para_path in report["unmapped_parameters"]:
            lines.append(f"- {para_path}")

    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def enrich_job_with_dns_request_template(
    job: dict[str, Any],
    output_dir: Path,
    classifier_module,
) -> dict[str, Any]:
    stem = safe_name(f"{job['job_id']}_{job['attack_type']}_{job['victim_ip']}")
    prefix = output_dir / f"{stem}.dns_request_template"
    result = write_dns_request_template_bundle(
        classifier_module=classifier_module,
        pcap_path=Path(job['source_pcap']),
        output_prefix=prefix,
        victim_ip_hint=str(job['victim_ip']),
    )
    return {
        'job_id': job['job_id'],
        'attack_type': job['attack_type'],
        'victim_ip': job['victim_ip'],
        **result,
    }


def enrich_job_with_udp_template(
    job: dict[str, Any],
    output_dir: Path,
    classifier_module,
    base_template_json: Path,
) -> dict[str, Any]:
    stem = safe_name(f"{job['job_id']}_{job['attack_type']}_{job['victim_ip']}")
    output_json = output_dir / f"{stem}.udp_template.policy.json"
    result = generate_udp_policy(
        template_path=base_template_json,
        pcap_path=Path(job['source_pcap']),
        classifier_module=classifier_module,
        output_json=output_json,
        victim_ip=str(job['victim_ip']),
        attack_tag="UDP_FLOOD",
    )
    return {
        'job_id': job['job_id'],
        'attack_type': job['attack_type'],
        'victim_ip': job['victim_ip'],
        **result,
    }


def enrich_job_with_confscrub(
    job: dict[str, Any],
    output_dir: Path,
    confscrub_root: Path,
    classifier_module,
    python_bin: str,
    benign_pcap: Path,
) -> dict[str, Any]:
    attack_profile = SUPPORTED_CONFSCRUB_ATTACKS[job["attack_type"]]
    stem = safe_name(f"{job['job_id']}_{job['attack_type']}_{job['victim_ip']}")
    job_dir = output_dir / "confscrub" / stem
    job_dir.mkdir(parents=True, exist_ok=True)

    trace_prefix = job_dir / attack_profile["data_stub"]
    data_path, label_path = write_hypervision_inputs(
        classifier_module=classifier_module,
        benign_pcap=benign_pcap,
        attack_pcap=Path(job["source_pcap"]),
        output_prefix=trace_prefix,
    )

    json_path = (confscrub_root / "JSONs" / "gt_huawei.json").resolve()
    inter_conf = job_dir / f"{attack_profile['data_stub']}_huawei_multipath_inter_conf.json"
    final_conf = job_dir / f"{attack_profile['data_stub']}_huawei_multipath_final_conf.json"

    run_logged_command(
        [python_bin, "stage_2_1.py", "--data_path", str(trace_prefix), "--json_path", str(json_path)],
        cwd=confscrub_root,
        log_path=job_dir / "stage_2_1.log",
    )
    run_logged_command(
        [
            python_bin,
            "stage_2_2_and_stage_3.py",
            "--data_path",
            str(trace_prefix),
            "--json_path",
            str(json_path),
            "--output_path",
            str(inter_conf),
        ],
        cwd=confscrub_root,
        log_path=job_dir / "stage_2_2_and_stage_3.log",
    )
    run_logged_command(
        [
            python_bin,
            "stage_4.py",
            "--data_path",
            str(trace_prefix),
            "--json_path",
            str(json_path),
            "--conf_path",
            str(inter_conf),
            "--output_path",
            str(final_conf),
        ],
        cwd=confscrub_root,
        log_path=job_dir / "stage_4.log",
    )

    review_json = output_dir / f"{stem}.confscrub_review.json"
    review_txt = output_dir / f"{stem}.confscrub_review.txt"
    report = build_review_report(job, final_conf, benign_pcap)
    write_review_files(report, review_json, review_txt)

    return {
        "job_id": job["job_id"],
        "attack_type": job["attack_type"],
        "victim_ip": job["victim_ip"],
        "status": "synthesized",
        "source_pcap": job["source_pcap"],
        "benign_pcap": str(benign_pcap),
        "hypervision_data": str(data_path),
        "hypervision_label": str(label_path),
        "intermediate_conf": str(inter_conf),
        "final_conf": str(final_conf),
        "review_json": str(review_json),
        "review_txt": str(review_txt),
    }


def main() -> None:
    args = parse_args()

    classified_root = Path(args.classified_root).resolve()
    if not classified_root.exists():
        raise SystemExit(f"classified root not found: {classified_root}")

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    jobs_output = Path(args.jobs_output).resolve() if args.jobs_output else default_jobs_output(output_dir)
    jobs = build_jobs(classified_root)
    write_jobs_file(jobs, jobs_output)
    write_bundle(jobs, output_dir, args.acl_start)

    classifier_module = None
    template_manifest: list[dict[str, Any]] = []
    base_template_json = Path(args.base_template_json).resolve()
    dns_request_jobs_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for job in jobs:
        if job["attack_type"] != "DNS_REQUEST_FLOOD":
            continue
        key = (str(job["victim_ip"]), str(job["attack_type"]))
        current = dns_request_jobs_by_key.get(key)
        if current is None or int(job["evidence"]["file_size_bytes"]) > int(current["evidence"]["file_size_bytes"]):
            dns_request_jobs_by_key[key] = job

    udp_jobs_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for job in jobs:
        if job["attack_type"] != "UDP_FLOOD":
            continue
        key = (str(job["victim_ip"]), str(job["attack_type"]))
        current = udp_jobs_by_key.get(key)
        if current is None or int(job["evidence"]["file_size_bytes"]) > int(current["evidence"]["file_size_bytes"]):
            udp_jobs_by_key[key] = job

    dns_request_jobs = list(dns_request_jobs_by_key.values())
    udp_jobs = list(udp_jobs_by_key.values())
    if dns_request_jobs or (udp_jobs and base_template_json.exists()):
        classifier_module = load_module_from_path(
            Path(args.classifier_module).resolve(),
            "ddos_classifier_v5_2_bridge",
        )
        for job in dns_request_jobs:
            try:
                template_manifest.append(
                    enrich_job_with_dns_request_template(
                        job=job,
                        output_dir=output_dir,
                        classifier_module=classifier_module,
                    )
                )
            except Exception as exc:
                template_manifest.append(
                    {
                        "job_id": job["job_id"],
                        "attack_type": job["attack_type"],
                        "victim_ip": job["victim_ip"],
                        "status": "failed",
                        "reason": str(exc),
                    }
                )

        if udp_jobs and not base_template_json.exists():
            for job in udp_jobs:
                template_manifest.append(
                    {
                        "job_id": job["job_id"],
                        "attack_type": job["attack_type"],
                        "victim_ip": job["victim_ip"],
                        "status": "skipped",
                        "reason": f"base template json not found: {base_template_json}",
                    }
                )
        else:
            for job in udp_jobs:
                try:
                    template_manifest.append(
                        enrich_job_with_udp_template(
                            job=job,
                            output_dir=output_dir,
                            classifier_module=classifier_module,
                            base_template_json=base_template_json,
                        )
                    )
                except Exception as exc:
                    template_manifest.append(
                        {
                            "job_id": job["job_id"],
                            "attack_type": job["attack_type"],
                            "victim_ip": job["victim_ip"],
                            "status": "failed",
                            "reason": str(exc),
                        }
                    )

    template_manifest_path = output_dir / "template_manifest.json"
    template_manifest_path.write_text(json.dumps(template_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest: list[dict[str, Any]] = []
    confscrub_root = Path(args.confscrub_root).resolve()
    benign_dir = Path(args.benign_pcap_dir).resolve() if args.benign_pcap_dir else None
    default_benign = Path(args.default_benign_pcap).resolve() if args.default_benign_pcap else None

    if args.skip_confscrub:
        for job in jobs:
            manifest.append(
                {
                    "job_id": job["job_id"],
                    "attack_type": job["attack_type"],
                    "victim_ip": job["victim_ip"],
                    "status": "skipped",
                    "reason": "ConfScrub disabled by --skip-confscrub",
                }
            )
    elif not confscrub_root.exists():
        for job in jobs:
            manifest.append(
                {
                    "job_id": job["job_id"],
                    "attack_type": job["attack_type"],
                    "victim_ip": job["victim_ip"],
                    "status": "skipped",
                    "reason": f"ConfScrub root not found: {confscrub_root}",
                }
            )
    else:
        if classifier_module is None:
            classifier_module = load_module_from_path(
                Path(args.classifier_module).resolve(),
                "ddos_classifier_v5_2_bridge",
            )
        for job in jobs:
            if job["attack_type"] not in SUPPORTED_CONFSCRUB_ATTACKS:
                manifest.append(
                    {
                        "job_id": job["job_id"],
                        "attack_type": job["attack_type"],
                        "victim_ip": job["victim_ip"],
                        "status": "skipped",
                        "reason": "attack type not supported by ConfScrub Huawei path",
                    }
                )
                continue

            benign_pcap = find_benign_pcap(job, benign_dir, default_benign)
            if benign_pcap is None:
                manifest.append(
                    {
                        "job_id": job["job_id"],
                        "attack_type": job["attack_type"],
                        "victim_ip": job["victim_ip"],
                        "status": "skipped",
                        "reason": "no benign baseline pcap matched this victim",
                    }
                )
                continue

            try:
                manifest.append(
                    enrich_job_with_confscrub(
                        job=job,
                        output_dir=output_dir,
                        confscrub_root=confscrub_root,
                        classifier_module=classifier_module,
                        python_bin=args.python_bin,
                        benign_pcap=benign_pcap,
                    )
                )
            except Exception as exc:  # pragma: no cover - surfaced in manifest
                manifest.append(
                    {
                        "job_id": job["job_id"],
                        "attack_type": job["attack_type"],
                        "victim_ip": job["victim_ip"],
                        "status": "failed",
                        "reason": str(exc),
                    }
                )

    manifest_path = output_dir / "confscrub_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    synthesized = sum(1 for item in manifest if item["status"] == "synthesized")
    print(f"mapped {len(jobs)} policy jobs")
    print(f"jobs_output: {jobs_output}")
    print(f"bundle_output: {output_dir}")
    print(f"template_manifest: {template_manifest_path}")
    print(f"confscrub_manifest: {manifest_path}")
    print(f"confscrub_synthesized: {synthesized}")


if __name__ == "__main__":
    main()
