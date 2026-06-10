"""Shared configuration for the DDoS policy pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


SUPPORTED_PCAP_SUFFIXES = {".pcap", ".pcapng"}

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_API_WORKDIR = PROJECT_ROOT / "workdir" / "api_runs"
DEFAULT_CLASSIFIER = PROJECT_ROOT / "核心脚本" / "攻击分类" / "ddos_classifier_v5_5.py"
DEFAULT_CLASSIFIER_CONFIG = PROJECT_ROOT / "pipeline" / "ddos_classifier.yaml"
DEFAULT_WHITELIST = PROJECT_ROOT / "核心脚本" / "攻击分类" / "whitelist.json"
DEFAULT_TEMPLATE_DIR = PROJECT_ROOT / "华为antiddos1908" / "模板" / "switch_templates_incremental"


@dataclass(frozen=True)
class PipelineConfig:
    workdir: Path
    classifier: Path
    classifier_config: Path
    whitelist: Path
    template_dir: Path
    classifier_workers: int
    downstream_api_module: Path | None = None
    downstream_server_ip: str | None = None
    downstream_token: str | None = None
    downstream_zone_account: str | None = None
    control_center_url: str | None = None
    control_center_timeout: float = 120.0
    downstream_required: bool = False


def default_pipeline_config() -> PipelineConfig:
    return PipelineConfig(
        workdir=DEFAULT_API_WORKDIR,
        classifier=DEFAULT_CLASSIFIER,
        classifier_config=DEFAULT_CLASSIFIER_CONFIG,
        whitelist=DEFAULT_WHITELIST,
        template_dir=DEFAULT_TEMPLATE_DIR,
        classifier_workers=1,
    )


def build_pipeline_config(args: Any) -> PipelineConfig:
    return PipelineConfig(
        workdir=Path(args.workdir).expanduser().resolve(),
        classifier=Path(args.classifier).expanduser().resolve(),
        classifier_config=Path(args.classifier_config).expanduser().resolve(),
        whitelist=Path(args.whitelist).expanduser().resolve(),
        template_dir=Path(args.template_dir).expanduser().resolve(),
        classifier_workers=max(1, int(args.classifier_workers)),
        downstream_api_module=Path(args.downstream_api_module).expanduser().resolve()
        if args.downstream_api_module
        else None,
        downstream_server_ip=args.downstream_server_ip,
        downstream_token=args.downstream_token,
        downstream_zone_account=args.downstream_zone_account,
        control_center_url=args.control_center_url,
        control_center_timeout=max(1.0, float(args.control_center_timeout)),
        downstream_required=bool(args.downstream_required),
    )
