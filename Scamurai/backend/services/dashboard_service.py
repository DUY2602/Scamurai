import json
from pathlib import Path
from threading import Lock


ROOT_DIR = Path(__file__).resolve().parents[3]

_stats_lock = Lock()
_stats = {
    "summary": {
        "total_scans": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "safe_count": 0,
    },
    "by_type": {
        "url": {
            "total_scans": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
        },
        "file": {
            "total_scans": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
        },
        "email": {
            "total_scans": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
        },
    },
}


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _build_model_section(report: dict, model_keys: list[str]) -> dict:
    section = {}

    for model_key in model_keys:
        model_metrics = report.get(model_key)

        if not isinstance(model_metrics, dict):
            continue

        section[model_key] = {
            key: value
            for key, value in model_metrics.items()
            if isinstance(value, (int, float))
        }

    return section


def get_dashboard_stats() -> dict:
    with _stats_lock:
        return {
            "summary": dict(_stats["summary"]),
            "by_type": {
                key: dict(values) for key, values in _stats["by_type"].items()
            },
        }


def get_dashboard_metrics() -> dict:
    url_report = _load_json(ROOT_DIR / "URL" / "models" / "training_report.json")
    file_report = _load_json(ROOT_DIR / "FILE" / "models" / "training_report.json")
    email_report = _load_json(ROOT_DIR / "Email" / "models" / "training_report.json")

    email_selected = email_report.get("selected_model", {})
    email_metrics = email_selected.get("metrics", {}) if isinstance(email_selected, dict) else {}

    return {
        "url": _build_model_section(url_report, ["lightgbm", "xgboost", "ensemble"]),
        "file": _build_model_section(file_report, ["lightgbm", "xgboost", "ensemble"]),
        "email": {
            "selected_model": {
                key: value
                for key, value in email_metrics.items()
                if isinstance(value, (int, float))
            }
        },
    }


def record_scan(scan_type: str, result: dict) -> None:
    if scan_type not in _stats["by_type"]:
        return

    status = str(result.get("status", "")).lower()
    is_malicious = status == "threat" or bool(result.get("is_malicious") or result.get("is_spam"))
    is_suspicious = status == "suspicious"

    summary_key = "safe_count"
    if is_malicious:
        summary_key = "malicious_count"
    elif is_suspicious:
        summary_key = "suspicious_count"

    with _stats_lock:
        _stats["summary"]["total_scans"] += 1
        _stats["summary"][summary_key] += 1
        _stats["by_type"][scan_type]["total_scans"] += 1
        _stats["by_type"][scan_type][summary_key] += 1
