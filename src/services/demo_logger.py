import datetime as dt
import json
import threading
from typing import Any, Iterable

from src.configs.index import LOG_DIR


_LOCK = threading.Lock()
LOG_FILE = LOG_DIR / "generation_system.log"


def fmt_json(value: Any) -> list[str]:
    return json.dumps(value, ensure_ascii=False, indent=2).splitlines()


def log(title: str, lines: Iterable[str] = ()) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block = [f"[{timestamp}] {title}", *(f"  {line}" for line in lines), ""]
    text = "\n".join(block)
    with _LOCK:
        with LOG_FILE.open("a", encoding="utf-8") as stream:
            stream.write(text)
    print(text, flush=True)

