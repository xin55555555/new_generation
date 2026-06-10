import datetime as dt
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from src.configs.index import CALLBACK_REQUIRED, JOB_WORKERS, WORKDIR
from src.services.control_center import dispatch_selected_templates
from src.services.demo_logger import fmt_json, log
from src.services.policy_generation import generate, resolve_pcap


_EXECUTOR = ThreadPoolExecutor(max_workers=JOB_WORKERS, thread_name_prefix="policy-generation")
_LOCK = threading.Lock()
_JOBS: dict[str, dict[str, Any]] = {}
JOB_DIR = WORKDIR / "jobs"


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _job_path(job_id: str) -> Path:
    return JOB_DIR / f"{job_id}.json"


def _save(job: dict[str, Any]) -> None:
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    path = _job_path(job["jobId"])
    temp_path = path.with_suffix(".json.tmp")
    temp_path.write_text(json.dumps(job, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(path)
    with _LOCK:
        _JOBS[job["jobId"]] = dict(job)


def get_job(job_id: str) -> dict[str, Any] | None:
    with _LOCK:
        cached = _JOBS.get(job_id)
    if cached is not None:
        return dict(cached)
    path = _job_path(job_id)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def submit_pcap_job(payload: dict[str, Any]) -> dict[str, Any]:
    pcap_path = resolve_pcap(payload["pcapDir"], payload["pcapName"])
    submitted_at = _now()
    digest = hashlib.sha256(f"{pcap_path}:{submitted_at}".encode()).hexdigest()[:12]
    job_id = f"job-{digest}"
    job = {
        "jobId": job_id,
        "status": "queued",
        "submittedAt": submitted_at,
        "pcapPath": str(pcap_path),
        "statusJsonPath": str(_job_path(job_id).resolve()),
    }
    _save(job)
    log("【步骤 3/5】收到控制中心 PCAP 通知", fmt_json(job))
    _EXECUTOR.submit(_run_job, job_id, pcap_path, dict(payload))
    return job


def _run_job(job_id: str, pcap_path: Path, payload: dict[str, Any]) -> None:
    job = get_job(job_id) or {"jobId": job_id}
    job.update({"status": "running", "startedAt": _now()})
    _save(job)
    log("【步骤 4/5】识别攻击并选择增量策略", [f"jobId: {job_id}", f"PCAP: {pcap_path}"])

    try:
        result = generate(pcap_path, payload)
        job.update(
            {
                "pipelineStatus": result.get("status"),
                "resultJsonPath": result.get("resultJsonPath"),
                "incrementalJsonPaths": result.get("incrementalJsonPaths", []),
                "selectedTemplateCount": result.get("selectedTemplateCount", 0),
                "unsupportedJobCount": result.get("unsupportedJobCount", 0),
            }
        )

        try:
            dispatch = dispatch_selected_templates(result)
            job["controlCenterDispatch"] = dispatch
            result["controlCenterDispatch"] = dispatch
            result_path = Path(result["resultJsonPath"])
            result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception as exc:
            job["controlCenterDispatch"] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            if CALLBACK_REQUIRED:
                raise

        job.update({"status": "success", "finishedAt": _now()})
        log("【步骤 5/5 完成】增量策略已生成并回传控制中心", fmt_json(job))
    except Exception as exc:
        job.update(
            {
                "status": "failed",
                "finishedAt": _now(),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        log("策略生成任务失败", fmt_json(job))
    finally:
        _save(job)

