import json
from pathlib import Path
from typing import Any

import requests

from src.configs.index import CONTROL_CENTER_TIMEOUT, CONTROL_CENTER_URL


def dispatch_selected_templates(result: dict[str, Any]) -> dict[str, Any]:
    """Post each selected incremental JSON in the format expected by control-center-system."""
    paths = result.get("incrementalJsonPaths") or []
    target = f"{CONTROL_CENTER_URL}/api/defenseConfig/update"
    if not paths:
        return {"status": "skipped", "target": target, "reason": "no incremental template generated", "items": []}

    session = requests.Session()
    session.trust_env = False
    items = []
    try:
        for value in paths:
            template_path = Path(value).resolve()
            payload = json.loads(template_path.read_text(encoding="utf-8"))
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

