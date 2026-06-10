"""Dispatch selected incremental policies to the control center or a legacy hook."""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from .pipeline_settings import PipelineConfig
except ImportError:
    from pipeline_settings import PipelineConfig


def first_text_value(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def load_json_to_api(module_path: Path):
    module_path = module_path.resolve()
    module_dir = str(module_path.parent)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)

    spec = importlib.util.spec_from_file_location("downstream_policy_api", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load downstream API module: {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    json_to_api = getattr(module, "json_to_api", None)
    if not callable(json_to_api):
        raise RuntimeError(f"downstream API module must define callable json_to_api: {module_path}")
    return json_to_api


def json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return repr(value)


def write_result_json_if_available(policy_result: dict[str, Any]) -> None:
    result_json_path = policy_result.get("resultJsonPath")
    if isinstance(result_json_path, str) and result_json_path.strip():
        Path(result_json_path).write_text(
            json.dumps(policy_result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def selected_policy_paths(policy_result: dict[str, Any]) -> list[Path]:
    raw_paths = policy_result.get("incrementalJsonPaths", [])
    if not isinstance(raw_paths, list):
        raise RuntimeError("incrementalJsonPaths must be a list")

    paths = []
    for value in raw_paths:
        if not isinstance(value, str) or not value.strip():
            continue
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise RuntimeError(f"selected incremental policy not found: {path}")
        paths.append(path)
    return paths


def load_selected_policy(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"selected incremental policy must be a JSON object: {path}")
    if not isinstance(payload.get("policyDetailDto"), list):
        raise RuntimeError(f"selected incremental policy missing policyDetailDto: {path}")
    return payload


def clean_empty(value: Any) -> Any:
    if value is None or value == [] or value == {}:
        return None
    if isinstance(value, dict):
        cleaned = {key: clean_empty(item) for key, item in value.items()}
        result = {key: item for key, item in cleaned.items() if item is not None}
        return result or None
    if isinstance(value, list):
        result = [clean_empty(item) for item in value]
        result = [item for item in result if item is not None]
        return result or None
    return value


def selected_policy_to_control_center_payload(selected_policy: dict[str, Any]) -> dict[str, Any]:
    policy_in: list[dict[str, Any]] = []
    policy_in_advanced: dict[str, Any] = {}

    for policy_set in selected_policy.get("policyDetailDto", []):
        if not isinstance(policy_set, dict):
            continue

        policies = clean_empty(policy_set.get("policy"))
        if isinstance(policies, list):
            policy_in.extend(item for item in policies if isinstance(item, dict))

        advanced = clean_empty(policy_set.get("policyAdvanced"))
        if isinstance(advanced, dict):
            policy_in_advanced.update(advanced)

    defense_mode = clean_empty(selected_policy.get("defenseMode"))
    payload: dict[str, Any] = {}
    if policy_in:
        payload["policy_in_enable"] = "1"
        payload["policy_in"] = policy_in
    if policy_in_advanced:
        payload["policy_in_enable"] = "1"
        payload["policy_in_advanced"] = policy_in_advanced
    if isinstance(defense_mode, list):
        payload["defense_mode_in_enable"] = "1"
        payload["defense_mode_in"] = defense_mode

    if not payload:
        raise RuntimeError("selected incremental policy contains no dispatchable changes")

    metadata = clean_empty(selected_policy.get("selected_for_job"))
    if isinstance(metadata, dict):
        payload["tuning_metadata"] = metadata
    return payload


def control_center_update_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    if value.endswith("/api/defenseConfig/update"):
        return value
    return f"{value}/api/defenseConfig/update"


def post_control_center_policy(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8", "Accept": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw.strip() else None
            return {"httpStatus": response.status, "response": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"control center returned HTTP {exc.code}: {raw[:1000]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"control center request failed: {exc.reason}") from exc


def dispatch_to_control_center(
    paths: list[Path],
    control_center_url: str,
    timeout: float,
) -> dict[str, Any]:
    update_url = control_center_update_url(control_center_url)
    results = []
    for path in paths:
        selected_policy = load_selected_policy(path)
        request_payload = selected_policy_to_control_center_payload(selected_policy)
        response = post_control_center_policy(update_url, request_payload, timeout)
        results.append({
            "selectedPolicyPath": str(path),
            "attackType": selected_policy.get("normalized_attack_type"),
            "job": selected_policy.get("selected_for_job"),
            **response,
        })
    return {
        "status": "success",
        "mode": "control_center_callback",
        "url": update_url,
        "selectedPolicyCount": len(paths),
        "results": results,
    }


def dispatch_to_legacy_module(
    paths: list[Path],
    payload: dict[str, Any],
    config: PipelineConfig,
) -> dict[str, Any]:
    if config.downstream_api_module is None:
        raise RuntimeError("downstream API module is not configured")

    server_ip = first_text_value(payload, "server_ip", "serverIp") or config.downstream_server_ip
    token = first_text_value(payload, "token") or config.downstream_token
    zone_account = first_text_value(payload, "zone_account", "zoneAccount") or config.downstream_zone_account
    missing = [
        name
        for name, value in (
            ("server_ip", server_ip),
            ("token", token),
            ("zone_account", zone_account),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"downstream API config missing: {', '.join(missing)}")

    json_to_api = load_json_to_api(config.downstream_api_module)
    results = []
    for path in paths:
        selected_policy = load_selected_policy(path)
        api_response = json_to_api(
            server_ip=server_ip,
            token=token,
            zone_account=zone_account,
            policy_json=selected_policy,
        )
        results.append({
            "selectedPolicyPath": str(path),
            "attackType": selected_policy.get("normalized_attack_type"),
            "response": json_safe(api_response),
        })
    return {
        "status": "success",
        "mode": "legacy_json_to_api",
        "module": str(config.downstream_api_module.resolve()),
        "serverIp": server_ip,
        "zoneAccount": zone_account,
        "selectedPolicyCount": len(paths),
        "results": results,
    }


def dispatch_policy_result(
    policy_result: dict[str, Any],
    payload: dict[str, Any],
    config: PipelineConfig,
) -> dict[str, Any] | None:
    """Dispatch each selected incremental JSON, never the aggregate result.json."""
    control_center_url = (
        first_text_value(payload, "controlCenterUrl", "control_center_url")
        or config.control_center_url
    )
    if not control_center_url and config.downstream_api_module is None:
        return None

    paths = selected_policy_paths(policy_result)
    if control_center_url:
        return dispatch_to_control_center(paths, control_center_url, config.control_center_timeout)
    return dispatch_to_legacy_module(paths, payload, config)
