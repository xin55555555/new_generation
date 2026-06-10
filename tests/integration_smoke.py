#!/usr/bin/env python3
"""Run the generation API against a fake control-center callback endpoint."""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PCAP_VALUE = os.getenv("SMOKE_PCAP")
PCAP = Path(PCAP_VALUE).expanduser().resolve() if PCAP_VALUE else None
os.environ.setdefault("CONTROL_CENTER_URL", "http://127.0.0.1:18000")
os.environ.setdefault("GENERATION_WORKDIR", str(ROOT / "workdir" / "smoke"))
RECEIVED: list[dict] = []


class CallbackHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        RECEIVED.append(json.loads(self.rfile.read(length)))
        body = json.dumps({"code": 200, "message": "fake control center accepted"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


def main() -> int:
    if PCAP is None:
        raise SystemExit("请通过 SMOKE_PCAP 指定测试 PCAP 的绝对路径")
    if not PCAP.is_file():
        raise FileNotFoundError(PCAP)
    server = ThreadingHTTPServer(("127.0.0.1", 18000), CallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        from fastapi.testclient import TestClient
        from src.main import app
        from src.services.job_service import get_job

        with TestClient(app) as client:
            started = time.monotonic()
            response = client.post("/api/traffic/pcap/info", json={"pcapDir": str(PCAP.parent), "pcapName": PCAP.name})
            elapsed = time.monotonic() - started
            response.raise_for_status()
            accepted = response.json()["data"]
            assert elapsed < 10, f"acceptance took too long: {elapsed:.2f}s"
            deadline = time.monotonic() + 180
            job = get_job(accepted["jobId"])
            while job and job["status"] in {"queued", "running"} and time.monotonic() < deadline:
                time.sleep(0.5)
                job = get_job(accepted["jobId"])
            assert job is not None and job["status"] == "success", job
            assert job["incrementalJsonPaths"], job
            assert RECEIVED and isinstance(RECEIVED[0].get("policyDetailDto"), list), RECEIVED
            print(json.dumps({"acceptanceSeconds": round(elapsed, 3), "job": job, "callbackPayloadCount": len(RECEIVED), "callbackPolicyDetailCount": len(RECEIVED[0]["policyDetailDto"])}, ensure_ascii=False, indent=2))
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
