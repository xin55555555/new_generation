import sys
from pathlib import Path
from typing import Any

from src.configs.index import (
    CLASSIFIER,
    CLASSIFIER_CONFIG,
    CLASSIFIER_WORKERS,
    DDOS_PROJECT_ROOT,
    TEMPLATE_DIR,
    WHITELIST,
    WORKDIR,
)


def _load_core():
    project_root = str(DDOS_PROJECT_ROOT)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from pipeline.strategy_tuning.pcap_policy_pipeline import generate_policy_result, resolve_requested_pcap
    from pipeline.strategy_tuning.pipeline_settings import PipelineConfig

    return generate_policy_result, resolve_requested_pcap, PipelineConfig


def resolve_pcap(pcap_dir: str, pcap_name: str) -> Path:
    _, resolve_requested_pcap, _ = _load_core()
    pcap_path = resolve_requested_pcap(pcap_dir, pcap_name)
    if pcap_path is None:
        candidate = Path(pcap_dir).expanduser() / pcap_name
        if not candidate.is_file():
            raise FileNotFoundError(candidate)
        raise ValueError("PCAP路径必须是绝对目录，文件名不能包含子目录，且后缀必须为.pcap或.pcapng")
    return pcap_path


def generate(pcap_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    generate_policy_result, _, PipelineConfig = _load_core()
    config = PipelineConfig(
        workdir=WORKDIR / "pipeline_runs",
        classifier=CLASSIFIER.resolve(),
        classifier_config=CLASSIFIER_CONFIG.resolve(),
        whitelist=WHITELIST.resolve(),
        template_dir=TEMPLATE_DIR.resolve(),
        classifier_workers=CLASSIFIER_WORKERS,
    )
    return generate_policy_result(pcap_path, payload, config)

