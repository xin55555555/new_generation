import json
from pathlib import Path
from typing import Any

import requests

from src.configs.index import CONTROL_CENTER_TIMEOUT, CONTROL_CENTER_URL


def load_selected_payloads(result: dict[str, Any]) -> list[dict[str, Any]]:
    payloads = []
    for value in result.get("incrementalJsonPaths") or []:
        template_path = Path(value).resolve()
        payloads.append(
            {
                "templatePath": str(template_path),
                "payload": json.loads(template_path.read_text(encoding="utf-8")),
            }
        )
    return payloads


def dispatch_selected_templates(
    result: dict[str, Any], selected_payloads: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Post each selected incremental JSON in the format expected by control-center-system."""
    selected_payloads = selected_payloads if selected_payloads is not None else load_selected_payloads(result)
    target = f"{CONTROL_CENTER_URL}/api/defenseConfig/update"
    if not selected_payloads:
        return {"status": "skipped", "target": target, "reason": "no incremental template generated", "items": []}

    session = requests.Session()
    session.trust_env = False
    items = []
    try:
        for selected in selected_payloads:
            template_path = Path(selected["templatePath"])
            payload = selected["payload"]
            response = session.post(target, json=payload, timeout=CONTROL_CENTER_TIMEOUT)
            response.raise_for_status()
            try:
                response_body: Any = response.json()
            except ValueError:
                response_body = response.text
            items.append(
                {
                    "templatePath": str(template_path),
                    "httpStatus": response.status_code,
                    "response": response_body,
                }
            )
    finally:
        session.close()

    return {"status": "success", "target": target, "items": items}

