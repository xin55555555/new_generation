#!/usr/bin/env python3
"""One-command PCAP to AntiDDoS1908 incremental template pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from .pcap_policy_pipeline import generate_policy_result
    from .pipeline_settings import (
        DEFAULT_CLASSIFIER,
        DEFAULT_CLASSIFIER_CONFIG,
        DEFAULT_TEMPLATE_DIR,
        DEFAULT_WHITELIST,
        PROJECT_ROOT,
        SUPPORTED_PCAP_SUFFIXES,
        PipelineConfig,
    )
except ImportError:
    from pcap_policy_pipeline import generate_policy_result
    from pipeline_settings import (
        DEFAULT_CLASSIFIER,
        DEFAULT_CLASSIFIER_CONFIG,
        DEFAULT_TEMPLATE_DIR,
        DEFAULT_WHITELIST,
        PROJECT_ROOT,
        SUPPORTED_PCAP_SUFFIXES,
        PipelineConfig,
    )


DEFAULT_WORKDIR = PROJECT_ROOT / "workdir" / "pcap_pipeline_runs"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pcap classification and select Huawei AntiDDoS1908 incremental templates.",
    )
    parser.add_argument("pcap", help="Absolute or relative path to a .pcap/.pcapng file")
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR), help="Run output root directory")
    parser.add_argument("--classifier", default=str(DEFAULT_CLASSIFIER), help="Path to ddos classifier script")
    parser.add_argument("--classifier-config", default=str(DEFAULT_CLASSIFIER_CONFIG), help="Classifier YAML config")
    parser.add_argument("--whitelist", default=str(DEFAULT_WHITELIST), help="Classifier whitelist JSON")
    parser.add_argument("--template-dir", default=str(DEFAULT_TEMPLATE_DIR), help="Incremental template directory")
    parser.add_argument("--classifier-workers", type=int, default=1, help="Classifier worker count")
    parser.add_argument(
        "--fail-on-no-template",
        action="store_true",
        help="Exit non-zero if classification succeeds but no incremental template is selected",
    )
    return parser.parse_args()


def resolve_input_pcap(value: str) -> Path:
    pcap = Path(value).expanduser().resolve()
    if not pcap.is_file():
        raise SystemExit(f"pcap file not found: {pcap}")
    if pcap.suffix.lower() not in SUPPORTED_PCAP_SUFFIXES:
        raise SystemExit(f"unsupported pcap suffix: {pcap.suffix}")
    return pcap


def build_config(args: argparse.Namespace) -> PipelineConfig:
    return PipelineConfig(
        workdir=Path(args.workdir).expanduser().resolve(),
        classifier=Path(args.classifier).expanduser().resolve(),
        classifier_config=Path(args.classifier_config).expanduser().resolve(),
        whitelist=Path(args.whitelist).expanduser().resolve(),
        template_dir=Path(args.template_dir).expanduser().resolve(),
        classifier_workers=max(1, int(args.classifier_workers)),
    )


def summarize(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": result.get("status"),
        "pcapPath": result.get("pcapPath"),
        "resultJsonPath": result.get("resultJsonPath"),
        "manifestPath": result.get("manifestPath"),
        "jobsPath": result.get("jobsPath"),
        "classifiedDir": result.get("classifiedDir"),
        "incrementalJsonPaths": result.get("incrementalJsonPaths", []),
        "selectedTemplateCount": result.get("selectedTemplateCount", 0),
        "unsupportedJobCount": result.get("unsupportedJobCount", 0),
    }


def main() -> int:
    args = parse_args()
    pcap = resolve_input_pcap(args.pcap)
    payload = {
        "pcapDir": str(pcap.parent),
        "pcapName": pcap.name,
    }
    result = generate_policy_result(pcap, payload, build_config(args))
    summary = summarize(result)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if args.fail_on_no_template and not summary["incrementalJsonPaths"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
