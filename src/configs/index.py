import os
from pathlib import Path


GENERATION_ROOT = Path(__file__).resolve().parents[2]
DDOS_PROJECT_ROOT = Path(os.getenv("DDOS_PROJECT_ROOT", str(GENERATION_ROOT))).expanduser().resolve()

API_HOST = os.getenv("GENERATION_API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("GENERATION_API_PORT", "8001"))
CONTROL_CENTER_URL = os.getenv("CONTROL_CENTER_URL", "http://127.0.0.1:8000").rstrip("/")
CONTROL_CENTER_TIMEOUT = float(os.getenv("CONTROL_CENTER_TIMEOUT", "120"))
CALLBACK_REQUIRED = os.getenv("CONTROL_CENTER_CALLBACK_REQUIRED", "true").lower() in {"1", "true", "yes"}
CLASSIFIER_WORKERS = max(1, int(os.getenv("CLASSIFIER_WORKERS", "1")))
JOB_WORKERS = max(1, int(os.getenv("GENERATION_JOB_WORKERS", "1")))

WORKDIR = Path(os.getenv("GENERATION_WORKDIR", str(GENERATION_ROOT / "workdir"))).expanduser().resolve()
LOG_DIR = Path(os.getenv("GENERATION_LOG_DIR", str(GENERATION_ROOT / "logs"))).expanduser().resolve()

CLASSIFIER = Path(os.getenv("DDOS_CLASSIFIER", str(DDOS_PROJECT_ROOT / "核心脚本/攻击分类/ddos_classifier_v5_5.py")))
CLASSIFIER_CONFIG = Path(os.getenv("DDOS_CLASSIFIER_CONFIG", str(DDOS_PROJECT_ROOT / "pipeline/ddos_classifier.yaml")))
WHITELIST = Path(os.getenv("DDOS_WHITELIST", str(DDOS_PROJECT_ROOT / "核心脚本/攻击分类/whitelist.json")))
TEMPLATE_DIR = Path(os.getenv("DDOS_TEMPLATE_DIR", str(DDOS_PROJECT_ROOT / "华为antiddos1908/模板/switch_templates_incremental")))

