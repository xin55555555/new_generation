"""PCAP validation, attack classification, and incremental template selection."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

try:
    from .pipeline_settings import PipelineConfig, SUPPORTED_PCAP_SUFFIXES
except ImportError:
    from pipeline_settings import PipelineConfig, SUPPORTED_PCAP_SUFFIXES

from policy_mapper import classify_file
from run_incremental_template_pipeline import (
    dedupe_jobs,
    default_jobs_output,
    select_template_for_job,
    write_jobs_file,
)


def is_blank(value: Any) -> bool:
    return not isinstance(value, str) or not value.strip()


def resolve_requested_pcap(pcap_dir: str, pcap_name: str) -> Path | None:
    """Return a valid pcap path, or None if the request should be rejected."""
    if is_blank(pcap_dir) or is_blank(pcap_name):
        return None

    pcap_name = pcap_name.strip()
    pcap_dir_path = Path(pcap_dir.strip())

    if not pcap_dir_path.is_absolute():
        return None

    # pcapName is a file name from the control center, not a nested path.
    if Path(pcap_name).name != pcap_name:
        return None
    if Path(pcap_name).suffix.lower() not in SUPPORTED_PCAP_SUFFIXES:
        return None

    candidate = pcap_dir_path / pcap_name
    if not candidate.is_file():
        return None
    return candidate.resolve()


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "pcap"


def build_run_dir(pcap_path: Path, workdir: Path) -> Path:
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(f"{pcap_path}:{timestamp}".encode("utf-8")).hexdigest()[:12]
    return workdir / f"{safe_name(pcap_path.stem)}_{timestamp}_{digest}"


def run_classifier(pcap_path: Path, classified_dir: Path, log_dir: Path, config: PipelineConfig) -> dict[str, Any]:
    classified_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(config.classifier),
        str(pcap_path),
        "--output",
        str(classified_dir),
        "--config",
        str(config.classifier_config),
        "--whitelist",
        str(config.whitelist),
        "-j",
        str(config.classifier_workers),
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)

    stdout_path = log_dir / "classifier.stdout.log"
    stderr_path = log_dir / "classifier.stderr.log"
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")

    if completed.returncode != 0:
        raise RuntimeError(f"classifier failed with returncode={completed.returncode}, stderr={stderr_path}")

    return {
        "cmd": cmd,
        "returncode": completed.returncode,
        "stdoutPath": str(stdout_path.resolve()),
        "stderrPath": str(stderr_path.resolve()),
    }


def select_incremental_templates(classified_dir: Path, output_dir: Path, template_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_files = sorted(classified_dir.rglob("*.pcap"))
    all_jobs = [asdict(classify_file(path, classified_dir)) for path in pcap_files]
    selected_jobs = dedupe_jobs(all_jobs) if all_jobs else []

    jobs_output = default_jobs_output(output_dir)
    write_jobs_file(selected_jobs, jobs_output)

    selections: list[dict[str, Any]] = []
    unsupported_jobs: list[dict[str, Any]] = []
    for job in selected_jobs:
        try:
            selections.append(select_template_for_job(job, template_dir, output_dir))
        except FileNotFoundError as exc:
            unsupported_jobs.append({
                "job_id": job.get("job_id"),
                "attack_type": job.get("attack_type"),
                "victim_ip": job.get("victim_ip"),
                "source_pcap": job.get("source_pcap"),
                "reason": str(exc),
            })

    manifest = {
        "workflow": [
            "pcap -> ddos_classifier_v5_5 classified output",
            "classified pcap -> normalized attack_type",
            "normalized attack_type -> deduplicated job per victim_ip + attack_type",
            "deduplicated attack_type -> incremental template",
            "selected incremental template path -> API response data.incrementalJsonPaths",
        ],
        "classified_root": str(classified_dir.resolve()),
        "template_dir": str(template_dir.resolve()),
        "original_job_count": len(all_jobs),
        "selected_job_count": len(selected_jobs),
        "jobs_output": str(jobs_output.resolve()),
        "selected_template_count": len(selections),
        "unsupported_job_count": len(unsupported_jobs),
        "selections": selections,
        "unsupported_jobs": unsupported_jobs,
    }
    manifest_path = output_dir / "selected_template_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return {
        "manifestPath": str(manifest_path.resolve()),
        "jobsPath": str(jobs_output.resolve()),
        "incrementalJsonPaths": [item["template_output"] for item in selections],
        "selectedTemplateCount": len(selections),
        "unsupportedJobCount": len(unsupported_jobs),
    }


def generate_policy_result(pcap_path: Path, payload: dict[str, Any], config: PipelineConfig) -> dict[str, Any]:
    run_dir = build_run_dir(pcap_path, config.workdir)
    classified_dir = run_dir / "classified"
    log_dir = run_dir / "logs"
    incremental_output_dir = run_dir / "incremental_templates"

    classifier_result = run_classifier(pcap_path, classified_dir, log_dir, config)
    template_result = select_incremental_templates(classified_dir, incremental_output_dir, config.template_dir)

    result = {
        "status": "success" if template_result["incrementalJsonPaths"] else "no_incremental_template_generated",
        "request": {
            "pcapDir": payload.get("pcapDir"),
            "pcapName": payload.get("pcapName"),
        },
        "pcapPath": str(pcap_path),
        "runDir": str(run_dir.resolve()),
        "classifiedDir": str(classified_dir.resolve()),
        "incrementalOutputDir": str(incremental_output_dir.resolve()),
        "classifier": classifier_result,
        **template_result,
    }
    result_path = run_dir / "result.json"
    result["resultJsonPath"] = str(result_path.resolve())
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result
