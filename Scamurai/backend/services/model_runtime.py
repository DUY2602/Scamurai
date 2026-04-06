import json
from pathlib import Path

from backend.services.asset_paths import maybe_find_asset_path


def _load_json(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def derive_status_thresholds(threat_threshold: float) -> tuple[float, float]:
    normalized_threat = max(40.0, min(95.0, float(threat_threshold)))
    suspicious_threshold = max(30.0, min(normalized_threat - 10.0, round(normalized_threat * 0.6, 2)))
    return normalized_threat, suspicious_threshold


def classify_status(risk_score: float, threat_threshold: float, suspicious_threshold: float) -> str:
    if risk_score >= threat_threshold:
        return "threat"
    if risk_score >= suspicious_threshold:
        return "suspicious"
    return "safe"


def load_url_thresholds(start: Path) -> tuple[float, float]:
    report = _load_json(maybe_find_asset_path(start, "URL", "models", "training_report.json"))
    selected_threshold = (
        report.get("ensemble_soft_voting", {}).get("selected_threshold")
        if isinstance(report, dict)
        else None
    )
    if isinstance(selected_threshold, (int, float)):
        return derive_status_thresholds(float(selected_threshold) * 100.0)
    return 70.0, 40.0


def load_file_thresholds(start: Path) -> tuple[float, float]:
    report = _load_json(maybe_find_asset_path(start, "FILE", "models", "training_report.json"))
    selected_threshold = (
        report.get("ensemble_soft_voting", {}).get("selected_threshold")
        if isinstance(report, dict)
        else None
    )
    if isinstance(selected_threshold, (int, float)):
        threat_threshold = max(55.0, float(selected_threshold) * 100.0)
        suspicious_threshold = max(45.0, min(threat_threshold - 8.0, 55.0))
        return threat_threshold, suspicious_threshold
    return 70.0, 40.0


def load_email_thresholds(start: Path) -> tuple[float, float]:
    metadata = _load_json(maybe_find_asset_path(start, "Email", "models", "best_model_metadata.json"))
    threshold = metadata.get("selected_threshold") if isinstance(metadata, dict) else None
    if isinstance(threshold, (int, float)):
        threshold_value = float(threshold) * 100.0 if float(threshold) <= 1.0 else float(threshold)
        return derive_status_thresholds(threshold_value)
    return 70.0, 40.0
