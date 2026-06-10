#!/usr/bin/env python3
"""
HTTP API for the strategy tuning system.

Implemented endpoint:
  POST /api/traffic/pcap/info

This module intentionally stays thin: it handles HTTP parsing and response
formatting, while PCAP processing and downstream dispatch live in separate
modules.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from json import JSONDecodeError
from typing import Any

try:
    from .downstream_dispatcher import dispatch_policy_result, write_result_json_if_available
    from .pcap_policy_pipeline import generate_policy_result, is_blank, resolve_requested_pcap
    from .pipeline_settings import (
        DEFAULT_API_WORKDIR,
        DEFAULT_CLASSIFIER,
        DEFAULT_CLASSIFIER_CONFIG,
        DEFAULT_TEMPLATE_DIR,
        DEFAULT_WHITELIST,
        PROJECT_ROOT,
        SUPPORTED_PCAP_SUFFIXES,
        PipelineConfig,
        build_pipeline_config,
        default_pipeline_config,
    )
except ImportError:
    from downstream_dispatcher import dispatch_policy_result, write_result_json_if_available
    from pcap_policy_pipeline import generate_policy_result, is_blank, resolve_requested_pcap
    from pipeline_settings import (
        DEFAULT_API_WORKDIR,
        DEFAULT_CLASSIFIER,
        DEFAULT_CLASSIFIER_CONFIG,
        DEFAULT_TEMPLATE_DIR,
        DEFAULT_WHITELIST,
        PROJECT_ROOT,
        SUPPORTED_PCAP_SUFFIXES,
        PipelineConfig,
        build_pipeline_config,
        default_pipeline_config,
    )


SUCCESS = {"code": 200, "message": "获取PCAP文件信息成功"}
MISSING_PARAM = {"code": 400, "message": "pcapDir、pcapName参数不能为空"}
FILE_NOT_FOUND = {"code": 400, "message": "对应PCAP文件不存在，请检查目录和文件名"}
SERVER_ERROR = {"code": 500, "message": "查询PCAP文件信息失败，服务器内部异常"}


def json_response(code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        response["data"] = data
    return response


def handle_pcap_info_request(payload: dict[str, Any], config: PipelineConfig | None = None) -> dict[str, Any]:
    """Business logic for POST /api/traffic/pcap/info."""
    if not isinstance(payload, dict):
        return MISSING_PARAM

    pcap_dir = payload.get("pcapDir")
    pcap_name = payload.get("pcapName")
    if is_blank(pcap_dir) or is_blank(pcap_name):
        return MISSING_PARAM

    pcap_path = resolve_requested_pcap(pcap_dir, pcap_name)
    if pcap_path is None:
        return FILE_NOT_FOUND

    effective_config = config or default_pipeline_config()
    policy_result = generate_policy_result(pcap_path, payload, effective_config)
    try:
        dispatch_result = dispatch_policy_result(policy_result, payload, effective_config)
        if dispatch_result is not None:
            policy_result["downstreamDispatch"] = dispatch_result
            write_result_json_if_available(policy_result)
    except Exception as exc:
        policy_result["downstreamDispatch"] = {
            "status": "failed",
            "target": (
                payload.get("controlCenterUrl")
                or payload.get("control_center_url")
                or effective_config.control_center_url
                or (str(effective_config.downstream_api_module.resolve()) if effective_config.downstream_api_module else None)
            ),
            "error": f"{type(exc).__name__}: {exc}",
        }
        write_result_json_if_available(policy_result)
        if effective_config.downstream_required:
            raise
    return json_response(SUCCESS["code"], SUCCESS["message"], policy_result)


class StrategyTuningRequestHandler(BaseHTTPRequestHandler):
    server_version = "StrategyTuningAPI/0.2"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/api/traffic/pcap/info":
            self.write_json(json_response(404, "接口不存在"), http_status=404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode("utf-8") or "{}")
            config = getattr(self.server, "pipeline_config", default_pipeline_config())
            result = handle_pcap_info_request(payload, config=config)
            self.write_json(result, http_status=int(result["code"]))
        except JSONDecodeError:
            self.write_json(MISSING_PARAM, http_status=400)
        except Exception:
            self.write_json(SERVER_ERROR, http_status=500)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.write_json(json_response(405, "请求方式不支持"), http_status=405)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def write_json(self, payload: dict[str, Any], http_status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(http_status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the strategy tuning API server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host, default: 0.0.0.0")
    parser.add_argument("--port", type=int, default=18080, help="Bind port, default: 18080")
    parser.add_argument("--workdir", default=str(DEFAULT_API_WORKDIR), help="API run output directory")
    parser.add_argument("--classifier", default=str(DEFAULT_CLASSIFIER), help="Path to ddos classifier script")
    parser.add_argument("--classifier-config", default=str(DEFAULT_CLASSIFIER_CONFIG), help="Classifier YAML config")
    parser.add_argument("--whitelist", default=str(DEFAULT_WHITELIST), help="Classifier whitelist JSON")
    parser.add_argument("--template-dir", default=str(DEFAULT_TEMPLATE_DIR), help="Incremental template directory")
    parser.add_argument("--classifier-workers", type=int, default=1, help="Classifier worker count")
    parser.add_argument(
        "--downstream-api-module",
        default=None,
        help="Optional Python module path defining json_to_api for downstream policy dispatch",
    )
    parser.add_argument("--downstream-server-ip", default=None, help="Default server_ip passed to json_to_api")
    parser.add_argument("--downstream-token", default=None, help="Default token passed to json_to_api")
    parser.add_argument("--downstream-zone-account", default=None, help="Default zone_account passed to json_to_api")
    parser.add_argument(
        "--control-center-url",
        default=None,
        help="Preferred control-center base URL, for example http://127.0.0.1:8000",
    )
    parser.add_argument(
        "--control-center-timeout",
        type=float,
        default=120.0,
        help="Control-center policy callback timeout in seconds",
    )
    parser.add_argument(
        "--downstream-required",
        action="store_true",
        help="Return a server error when downstream policy dispatch fails",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), StrategyTuningRequestHandler)
    server.pipeline_config = build_pipeline_config(args)  # type: ignore[attr-defined]
    print(f"strategy tuning API listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
