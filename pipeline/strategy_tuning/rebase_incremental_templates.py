#!/usr/bin/env python3
"""Rebase incremental AntiDDoS templates against a new default policy JSON."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import shutil
from pathlib import Path
from typing import Any

from pipeline_settings import DEFAULT_TEMPLATE_DIR, PROJECT_ROOT


DEFAULT_BASELINE = PROJECT_ROOT / "policy_t.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE), help="New default policy JSON")
    parser.add_argument("--template-dir", default=str(DEFAULT_TEMPLATE_DIR), help="Incremental template directory")
    parser.add_argument("--report", default=None, help="Optional output report path")
    parser.add_argument("--backup-dir", default=None, help="Optional backup directory before rewriting templates")
    parser.add_argument(
        "--keep-unknown-devices",
        action="store_true",
        help="Keep device entries that do not exist in the new baseline",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def baseline_policy_index(baseline: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    index: dict[str, dict[str, dict[str, Any]]] = {}
    for device in baseline.get("policyDetailDto", []):
        device_ip = device.get("deviceIp")
        if not isinstance(device_ip, str):
            continue
        index[device_ip] = {
            policy["attack_type"]: policy
            for policy in device.get("policy", [])
            if isinstance(policy, dict) and isinstance(policy.get("attack_type"), str)
        }
    return index


def rebase_policy_item(policy: dict[str, Any], baseline_policy: dict[str, Any] | None) -> dict[str, Any]:
    if baseline_policy is None:
        return copy.deepcopy(policy)

    rebased = copy.deepcopy(baseline_policy)
    for key, value in policy.items():
        if key == "threshold":
            continue
        rebased[key] = value
    return rebased


def policy_counts(payload: dict[str, Any]) -> dict[str, int]:
    return {
        str(device.get("deviceIp")): len(device.get("policy", []))
        for device in payload.get("policyDetailDto", [])
        if isinstance(device, dict)
    }


def rebase_template(
    path: Path,
    baseline_path: Path,
    index: dict[str, dict[str, dict[str, Any]]],
    backup_dir: Path,
    keep_unknown_devices: bool,
) -> dict[str, Any]:
    payload = load_json(path)
    before_counts = policy_counts(payload)

    new_devices: list[dict[str, Any]] = []
    removed_equal = 0
    dropped_unknown_devices = 0
    missing_baseline_policies = 0

    for device in payload.get("policyDetailDto", []):
        device_ip = device.get("deviceIp")
        policies = device.get("policy", [])
        baseline_policies = index.get(device_ip)

        if baseline_policies is None:
            if keep_unknown_devices:
                new_devices.append(copy.deepcopy(device))
            else:
                dropped_unknown_devices += 1
            continue

        new_policies = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            attack_type = policy.get("attack_type")
            baseline_policy = baseline_policies.get(attack_type) if isinstance(attack_type, str) else None
            if baseline_policy is None:
                missing_baseline_policies += 1
            rebased = rebase_policy_item(policy, baseline_policy)
            if baseline_policy is not None and rebased == baseline_policy:
                removed_equal += 1
                continue
            new_policies.append(rebased)

        if new_policies:
            new_device = copy.deepcopy(device)
            new_device["policy"] = new_policies
            new_devices.append(new_device)

    backup_path = backup_dir / path.name
    shutil.copy2(path, backup_path)

    payload["comparison_baseline"] = str(baseline_path.resolve())
    payload["policyDetailDto"] = new_devices
    write_json(path, payload)

    after_counts = policy_counts(payload)
    return {
        "template": str(path.resolve()),
        "backup": str(backup_path.resolve()),
        "normalized_attack_type": payload.get("normalized_attack_type"),
        "before_policy_count": sum(before_counts.values()),
        "after_policy_count": sum(after_counts.values()),
        "before_devices": before_counts,
        "after_devices": after_counts,
        "removed_equal_to_baseline": removed_equal,
        "dropped_unknown_device_entries": dropped_unknown_devices,
        "missing_baseline_policies": missing_baseline_policies,
    }


def main() -> int:
    args = parse_args()
    baseline_path = Path(args.baseline).expanduser().resolve()
    template_dir = Path(args.template_dir).expanduser().resolve()
    if not baseline_path.is_file():
        raise SystemExit(f"baseline not found: {baseline_path}")
    if not template_dir.is_dir():
        raise SystemExit(f"template dir not found: {template_dir}")

    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = (
        Path(args.backup_dir).expanduser().resolve()
        if args.backup_dir
        else template_dir / f"backup_before_policy_t_rebase_{timestamp}"
    )
    backup_dir.mkdir(parents=True, exist_ok=True)

    baseline = load_json(baseline_path)
    index = baseline_policy_index(baseline)
    reports = []
    for path in sorted(template_dir.glob("*.switch_template.incremental.json")):
        reports.append(
            rebase_template(
                path=path,
                baseline_path=baseline_path,
                index=index,
                backup_dir=backup_dir,
                keep_unknown_devices=bool(args.keep_unknown_devices),
            )
        )

    report = {
        "baseline": str(baseline_path),
        "template_dir": str(template_dir),
        "backup_dir": str(backup_dir),
        "template_count": len(reports),
        "total_before_policy_count": sum(item["before_policy_count"] for item in reports),
        "total_after_policy_count": sum(item["after_policy_count"] for item in reports),
        "templates": reports,
    }
    report_path = (
        Path(args.report).expanduser().resolve()
        if args.report
        else template_dir / "policy_t_rebase_report.json"
    )
    write_json(report_path, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
