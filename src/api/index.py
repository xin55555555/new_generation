from typing import Any

from fastapi import APIRouter, HTTPException

from src.services.job_service import get_job, submit_pcap_job


router = APIRouter(prefix="/api")


@router.get("/health")
def health() -> dict[str, Any]:
    return {"code": 200, "message": "策略调优系统运行正常"}


@router.post("/traffic/pcap/info")
def receive_pcap_info(payload: dict[str, Any]) -> dict[str, Any]:
    """Receive the absolute PCAP location sent by the control center."""
    pcap_dir = payload.get("pcapDir")
    pcap_name = payload.get("pcapName")
    if not isinstance(pcap_dir, str) or not pcap_dir.strip() or not isinstance(pcap_name, str) or not pcap_name.strip():
        raise HTTPException(status_code=400, detail="pcapDir、pcapName参数不能为空")

    try:
        job = submit_pcap_job(payload)
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail="对应PCAP文件不存在，请检查目录和文件名")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"查询PCAP文件信息失败，服务器内部异常: {exc}")

    return {
        "code": 200,
        "message": "获取PCAP文件信息成功",
        "data": job,
    }


@router.get("/traffic/jobs/{job_id}")
def query_job(job_id: str) -> dict[str, Any]:
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"code": 200, "message": "查询任务成功", "data": job}

