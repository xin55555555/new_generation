#!/usr/bin/env python3
"""
Generate incremental AntiDDoS1908 switch templates per normalized attack type.

Design goals:
- reuse the real exported policy.json structure where useful
- emit only the entries that need to change from a default "all cleaning
  policies disabled" baseline
- keep existing threshold and mode fields from the base template
- record entries that are enabled but naturally have null thresholds

Default behavior:
- enable primary_entries + generic_entries
- keep secondary_entries disabled, but record them as optional candidates
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "华为antiddos1908/模板/switch_templates_incremental"
DEFAULT_BASE_TEMPLATE = PROJECT_ROOT / "华为antiddos1908/policy_init.json"
DEFAULT_MAPPING_JSON = PROJECT_ROOT / "华为antiddos1908/模板/attack_type_parameter_map.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def collect_managed_entries(mapping_payload: dict[str, Any]) -> set[str]:
    managed = set(mapping_payload.get("common_generic_entries", []))
    for rule in mapping_payload.get("attack_type_mapping", {}).values():
        for key in ("primary_entries", "secondary_entries", "generic_entries"):
            managed.update(entry for entry in rule.get(key, []) if entry)
    return {entry for entry in managed if entry}


def build_switch_plan(
    normalized_attack_type: str,
    mapping_payload: dict[str, Any],
    enable_secondary: bool,
) -> dict[str, Any]:
    attack_map = mapping_payload["attack_type_mapping"][normalized_attack_type]

    primary_entries = [entry for entry in attack_map.get("primary_entries", []) if entry]
    secondary_entries = [entry for entry in attack_map.get("secondary_entries", []) if entry]
    generic_entries = [entry for entry in attack_map.get("generic_entries", []) if entry]

    enabled_entries = []
    for entry in primary_entries + generic_entries:
        if entry not in enabled_entries:
            enabled_entries.append(entry)

    if enable_secondary:
        for entry in secondary_entries:
            if entry not in enabled_entries:
                enabled_entries.append(entry)

    optional_entries = [] if enable_secondary else secondary_entries

    return {
        "normalized_attack_type": normalized_attack_type,
        "protocol": attack_map.get("protocol"),
        "automation_ready": attack_map.get("automation_ready"),
        "enabled_entries": enabled_entries,
        "optional_entries": optional_entries,
        "notes": attack_map.get("notes", ""),
    }


def apply_switch_plan(
    base_template: dict[str, Any],
    managed_entries: set[str],
    switch_plan: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    enabled_entries = set(switch_plan["enabled_entries"])
    missing_entries: list[str] = []
    enabled_with_null_threshold: list[str] = []

    existing_attack_entries: set[str] = set()
    touched_changes: list[dict[str, Any]] = []
    incremental_policy_detail: list[dict[str, Any]] = []

    for detail in base_template.get("policyDetailDto", []):
        device_ip = detail.get("deviceIp")
        device_changes: list[dict[str, Any]] = []

        for item in detail.get("policy", []):
            attack_type = item.get("attack_type")
            if attack_type not in managed_entries:
                continue

            existing_attack_entries.add(attack_type)
            if attack_type not in enabled_entries:
                continue

            rendered_item = copy.deepcopy(item)
            rendered_item["enable_status"] = 1
            device_changes.append(rendered_item)
            touched_changes.append(
                {
                    "deviceIp": device_ip,
                    "attack_type": attack_type,
                    "new_enable_status": 1,
                    "threshold": item.get("threshold"),
                    "mode_type": item.get("mode_type"),
                }
            )

            if item.get("threshold") is None:
                enabled_with_null_threshold.append(attack_type)

        if device_changes:
            incremental_policy_detail.append(
                {
                    "deviceIp": device_ip,
                    "policy": device_changes,
                }
            )

    unresolved_enabled_entries = sorted(enabled_entries - existing_attack_entries)
    if unresolved_enabled_entries:
        missing_entries = sorted(set(missing_entries + unresolved_enabled_entries))

    rendered = {
        "template_mode": "incremental_patch",
        "comparison_baseline": "all managed cleaning policy entries disabled",
        "normalized_attack_type": switch_plan["normalized_attack_type"],
        "policyDetailDto": incremental_policy_detail,
    }

    manifest_entry = {
        "normalized_attack_type": switch_plan["normalized_attack_type"],
        "protocol": switch_plan["protocol"],
        "automation_ready": switch_plan["automation_ready"],
        "enabled_entries": switch_plan["enabled_entries"],
        "optional_entries": switch_plan["optional_entries"],
        "notes": switch_plan["notes"],
        "changed_entry_count": len(touched_changes),
        "changes": touched_changes,
        "enabled_with_null_threshold": sorted(set(enabled_with_null_threshold)),
        "missing_entries": missing_entries,
    }
    return rendered, manifest_entry


def generate_switch_templates(
    base_template_path: Path,
    mapping_json_path: Path,
    output_dir: Path,
    attack_type: str | None,
    enable_secondary: bool,
) -> dict[str, Any]:
    base_template = load_json(base_template_path)
    mapping_payload = load_json(mapping_json_path)
    managed_entries = collect_managed_entries(mapping_payload)
    all_attack_types = sorted(mapping_payload.get("attack_type_mapping", {}).keys())

    selected_attack_types = [attack_type] if attack_type else all_attack_types
    manifest_items: list[dict[str, Any]] = []

    for normalized_attack_type in selected_attack_types:
        if normalized_attack_type not in mapping_payload["attack_type_mapping"]:
            raise KeyError(f"unknown normalized attack type: {normalized_attack_type}")

        switch_plan = build_switch_plan(
            normalized_attack_type=normalized_attack_type,
            mapping_payload=mapping_payload,
            enable_secondary=enable_secondary,
        )
        rendered, manifest_entry = apply_switch_plan(
            base_template=base_template,
            managed_entries=managed_entries,
            switch_plan=switch_plan,
        )

        out_name = f"{normalized_attack_type.lower()}.switch_template.incremental.json"
        dump_json(output_dir / out_name, rendered)
        manifest_entry["output_json"] = str((output_dir / out_name).resolve())
        manifest_items.append(manifest_entry)

    summary = {
        "meta": {
            "base_template": str(base_template_path.resolve()),
            "mapping_json": str(mapping_json_path.resolve()),
            "output_dir": str(output_dir.resolve()),
            "strategy": {
                "template_mode": "incremental_patch",
                "comparison_baseline": "all managed cleaning policy entries disabled",
                "enable_primary_entries": True,
                "enable_generic_entries": True,
                "enable_secondary_entries": enable_secondary,
                "threshold_policy": "preserve base template thresholds and mode_type from the base template",
            },
        },
        "templates": manifest_items,
    }
    dump_json(output_dir / "switch_template_manifest.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-template-json",
        default=str(DEFAULT_BASE_TEMPLATE),
        help="Base AntiDDoS1908 policy.json export.",
    )
    parser.add_argument(
        "--mapping-json",
        default=str(DEFAULT_MAPPING_JSON),
        help="Attack-type to policy-entry mapping JSON.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory to write incremental switch policy templates.",
    )
    parser.add_argument(
        "--attack-type",
        help="Generate only one normalized attack type; default is all mapped types.",
    )
    parser.add_argument(
        "--enable-secondary",
        action="store_true",
        help="Also enable secondary_entries instead of leaving them as optional candidates.",
    )
    args = parser.parse_args()

    summary = generate_switch_templates(
        base_template_path=Path(args.base_template_json),
        mapping_json_path=Path(args.mapping_json),
        output_dir=Path(args.output_dir),
        attack_type=args.attack_type,
        enable_secondary=args.enable_secondary,
    )
    print(
        json.dumps(
            {
                "generated_templates": len(summary["templates"]),
                "manifest": str((Path(args.output_dir) / "switch_template_manifest.json").resolve()),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
