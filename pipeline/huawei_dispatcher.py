#!/usr/bin/env python3
"""
Generate Huawei-oriented command bundles from policy jobs.

This script does not log in to devices. It produces auditable command files
that can be reviewed and then executed by an existing transport layer.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Huawei command bundles from policy jobs")
    parser.add_argument("jobs_file", help="JSONL file produced by policy_mapper.py")
    parser.add_argument(
        "--output-dir",
        default="./dispatch_bundle",
        help="Directory for generated command files (default: ./dispatch_bundle)",
    )
    parser.add_argument(
        "--acl-start",
        type=int,
        default=39000,
        help="Starting ACL number (default: 39000)",
    )
    return parser.parse_args()


def load_jobs(path: Path) -> list[dict]:
    jobs = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                jobs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid JSON on line {line_no}: {exc}") from exc
    if not jobs:
        raise SystemExit(f"no jobs found in: {path}")
    return jobs


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def build_acl_rule(job: dict) -> str:
    protocol = job["protocol"]
    victim = job["victim_ip"]
    ports = job.get("target_ports") or []

    if protocol == "tcp":
        if ports:
            return f" rule 5 deny tcp destination {victim} 0 destination-port eq {ports[0]}"
        return f" rule 5 deny tcp destination {victim} 0"
    if protocol == "udp":
        if ports:
            return f" rule 5 deny udp destination {victim} 0 destination-port eq {ports[0]}"
        return f" rule 5 deny udp destination {victim} 0"
    if protocol == "icmp":
        return f" rule 5 deny icmp destination {victim} 0"
    if protocol == "gre":
        return f" rule 5 deny gre destination {victim} 0"
    return f" rule 5 deny ip destination {victim} 0"


def build_commands(job: dict, acl_number: int) -> tuple[list[str], list[str]]:
    job_name = safe_name(job["job_id"])
    action = job["action"]
    victim = job["victim_ip"]
    rate_limit = job.get("rate_limit_pps") or 10000

    header = [
        "# Review device model and interface binding before execution.",
        "# These commands are templates for Huawei VRP-style devices.",
        f"# job_id={job['job_id']}",
        f"# attack_type={job['attack_type']}",
        f"# source_pcap={job['source_pcap']}",
        "system-view",
    ]
    rollback = [
        "system-view",
        f"undo traffic policy TP_{job_name}",
        f"undo traffic behavior TB_{job_name}",
        f"undo traffic classifier TC_{job_name}",
        f"undo acl number {acl_number}",
    ]

    if action == "huawei_review_only":
        commands = header + [
            "# Manual review required.",
            "# Suggested next step: verify business impact and decide whether to",
            "# bind an ACL, a CAR policy, blackhole routing, or upstream scrubbing.",
        ]
        rollback += ["quit"]
        return commands, rollback

    if action == "huawei_app_layer_escalate":
        commands = header + [
            "# Application-layer event. Prefer WAF, reverse proxy, or scrubbing.",
            f"# Victim IP: {victim}",
            "# If a temporary network action is required, attach a reviewed ACL/CAR",
            "# policy on the service-facing interface instead of a permanent block.",
        ]
        rollback += ["quit"]
        return commands, rollback

    acl_rule = build_acl_rule(job)
    commands = header + [
        f"acl number {acl_number}",
        acl_rule,
        f"traffic classifier TC_{job_name} operator or",
        f" if-match acl {acl_number}",
        f"traffic behavior TB_{job_name}",
        f" car cir {rate_limit} cbs 800000 pbs 800000 green pass red discard",
        f"traffic policy TP_{job_name}",
        f" classifier TC_{job_name} behavior TB_{job_name}",
        "# Bind the traffic policy on the correct interface manually:",
        f"# interface <INGRESS-INTERFACE>",
        f"#  traffic-policy TP_{job_name} inbound",
        "quit",
    ]
    rollback += [
        "# Also remove the interface binding if it was applied.",
        "# interface <INGRESS-INTERFACE>",
        f"#  undo traffic-policy TP_{job_name} inbound",
        "quit",
    ]

    if action == "huawei_tcp_connection_protect":
        commands.insert(-1, "# Consider enabling device-specific SYN/connection protection as well.")
    if action == "huawei_quic_rate_limit":
        commands.insert(-1, "# QUIC traffic may share UDP/443 with real users. Review before bind.")

    return commands, rollback


def write_bundle(jobs: list[dict], output_dir: Path, acl_start: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = []

    for index, job in enumerate(jobs):
        acl_number = acl_start + index
        commands, rollback = build_commands(job, acl_number)
        stem = safe_name(f"{job['job_id']}_{job['attack_type']}_{job['victim_ip']}")
        command_path = output_dir / f"{stem}.cmd.txt"
        rollback_path = output_dir / f"{stem}.rollback.txt"
        meta_path = output_dir / f"{stem}.json"

        command_path.write_text("\n".join(commands) + "\n", encoding="utf-8")
        rollback_path.write_text("\n".join(rollback) + "\n", encoding="utf-8")
        meta_path.write_text(json.dumps(job, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        manifest.append(
            {
                "job_id": job["job_id"],
                "attack_type": job["attack_type"],
                "victim_ip": job["victim_ip"],
                "command_file": str(command_path.resolve()),
                "rollback_file": str(rollback_path.resolve()),
                "metadata_file": str(meta_path.resolve()),
                "need_review": job["need_review"],
            }
        )

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(jobs)} command bundles")
    print(f"output_dir: {output_dir.resolve()}")
    print(f"manifest: {manifest_path.resolve()}")


def main() -> None:
    args = parse_args()
    jobs_file = Path(args.jobs_file).resolve()
    if not jobs_file.exists():
        raise SystemExit(f"jobs file not found: {jobs_file}")
    jobs = load_jobs(jobs_file)
    write_bundle(jobs, Path(args.output_dir).resolve(), args.acl_start)


if __name__ == "__main__":
    main()
