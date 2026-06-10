import datetime as dt
import json
import threading
from typing import Any, Iterable

from src.configs.index import LOG_DIR

import json
import os
import datetime


_LOCK = threading.Lock()
# LOG_FILE = LOG_DIR / "generation_system.log"

DEMO_LOG_DIR = "logs"
DEMO_LOG_FILE = os.path.join(DEMO_LOG_DIR, "generation_system.log")

_DIVIDER = "=" * 80
_THIN = "-" * 80

def fmt_json(value: Any) -> list[str]:
    return json.dumps(value, ensure_ascii=False, indent=2).splitlines()

def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# def log(title: str, lines: Iterable[str] = ()) -> None:
#     LOG_DIR.mkdir(parents=True, exist_ok=True)
#     timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     block = [f"[{timestamp}] {title}", *(f"  {line}" for line in lines), ""]
#     text = "\n".join(block)
#     with _LOCK:
#         with LOG_FILE.open("a", encoding="utf-8") as stream:
#             stream.write(text)
#     print(text, flush=True)

def init() -> None:
    """系统启动时初始化演示日志文件（清空上次内容）。"""
    os.makedirs(DEMO_LOG_DIR, exist_ok=True)
    with open(DEMO_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(_DIVIDER + "\n")
        f.write(f"  DDoS 防御策略自动调优 - 演示日志  [{_now()}]\n")
        f.write(_DIVIDER + "\n\n")
    print(f"[demo] 演示日志已初始化: {os.path.abspath(DEMO_LOG_FILE)}")
    print(f"[demo] 终端实时查看命令: tail -f {os.path.abspath(DEMO_LOG_FILE)}")


def log(step: str, lines: list[str]) -> None:
    """向演示日志写入一个带分隔符的步骤块，同时打印到 stdout。"""
    os.makedirs(DEMO_LOG_DIR, exist_ok=True)
    parts = [
        "",
        _DIVIDER,
        f"[{_now()}]  {step}",
        _THIN,
    ]
    for line in lines:
        parts.append(f"  {line}")
    parts.append(_DIVIDER)
    parts.append("")
    text = "\n".join(parts) + "\n"
    print(text)
    with open(DEMO_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(text)