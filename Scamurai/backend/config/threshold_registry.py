"""
Centralized threshold configuration - SINGLE SOURCE OF TRUTH for all detection thresholds.

All detection services (FILE, EMAIL, URL) should use thresholds from this registry
to ensure consistency and make debugging easier.

Version: 1.0
Last Updated: 2026-04-07
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.services.asset_paths import maybe_find_asset_path


class ThresholdConfig:
    """Immutable threshold configuration loaded from training report."""

    def __init__(
        self,
        detection_type: str,
        threat_threshold: float,
        suspicious_threshold: float,
        selected_threshold: float | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.detection_type = detection_type
        self.threat_threshold = float(threat_threshold)
        self.suspicious_threshold = float(suspicious_threshold)
        self.selected_threshold = float(selected_threshold) if selected_threshold else self.threat_threshold
        self.metadata = metadata or {}

    def classify_status(self, risk_score: float) -> str:
        """Classify detection status (threat/suspicious/safe) based on risk score."""
        if risk_score >= self.threat_threshold:
            return "threat"
        if risk_score >= self.suspicious_threshold:
            return "suspicious"
        return "safe"

    def to_dict(self) -> dict[str, Any]:
        """Export configuration as dict for API responses."""
        return {
            "detection_type": self.detection_type,
            "threat_threshold": self.threat_threshold,
            "suspicious_threshold": self.suspicious_threshold,
            "selected_threshold": self.selected_threshold,
        }

    def __repr__(self) -> str:
        return (
            f"ThresholdConfig(type={self.detection_type}, "
            f"threat={self.threat_threshold}, suspicious={self.suspicious_threshold})"
        )


class ThresholdRegistry:
    """
    Central registry for all detection thresholds.
    Loads from training reports and provides unified access.
    """

    # Default fallback thresholds if training reports unavailable
    DEFAULTS = {
        "file": ThresholdConfig("file", threat_threshold=70.0, suspicious_threshold=40.0),
        "email": ThresholdConfig("email", threat_threshold=60.0, suspicious_threshold=45.0),
        "url": ThresholdConfig("url", threat_threshold=70.0, suspicious_threshold=40.0),
    }

    _instance: ThresholdRegistry | None = None
    _configs: dict[str, ThresholdConfig] = {}

    def __new__(cls) -> ThresholdRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._configs = {}
        self._load_all_configs()
        self._initialized = True

    @staticmethod
    def _load_json(path: Path | None) -> dict:
        """Safely load JSON from path."""
        if path is None or not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _derive_thresholds(selected_threshold: float) -> tuple[float, float]:
        """
        Derive threat and suspicious thresholds from selected_threshold.
        This formula should be consistent across all detection types.
        """
        normalized_threat = max(40.0, min(95.0, float(selected_threshold)))
        suspicious_threshold = max(30.0, min(normalized_threat - 10.0, round(normalized_threat * 0.6, 2)))
        return normalized_threat, suspicious_threshold

    def _load_file_config(self) -> ThresholdConfig:
        """Load FILE detection thresholds from training report."""
        report = self._load_json(maybe_find_asset_path(Path(__file__), "FILE", "models", "training_report.json"))
        selected_threshold = (
            report.get("ensemble_soft_voting", {}).get("selected_threshold")
            if isinstance(report, dict)
            else None
        )

        if isinstance(selected_threshold, (int, float)):
            threat_threshold = max(55.0, float(selected_threshold) * 100.0)
            suspicious_threshold = max(45.0, min(threat_threshold - 8.0, 55.0))
        else:
            threat_threshold, suspicious_threshold = self._derive_thresholds(70.0)

        return ThresholdConfig(
            detection_type="file",
            threat_threshold=threat_threshold,
            suspicious_threshold=suspicious_threshold,
            selected_threshold=selected_threshold,
            metadata={"source": "FILE/models/training_report.json", "loaded_from": "ensemble_soft_voting"},
        )

    def _load_email_config(self) -> ThresholdConfig:
        """Load EMAIL detection thresholds from metadata."""
        metadata = self._load_json(
            maybe_find_asset_path(Path(__file__), "Email", "models", "best_model_metadata.json")
        )
        threshold = metadata.get("selected_threshold") if isinstance(metadata, dict) else None

        if isinstance(threshold, (int, float)):
            threshold_value = float(threshold) * 100.0 if float(threshold) <= 1.0 else float(threshold)
            threat_threshold, suspicious_threshold = self._derive_thresholds(threshold_value)
        else:
            threat_threshold, suspicious_threshold = self._derive_thresholds(60.0)

        return ThresholdConfig(
            detection_type="email",
            threat_threshold=threat_threshold,
            suspicious_threshold=suspicious_threshold,
            selected_threshold=threshold,
            metadata={"source": "Email/models/best_model_metadata.json", "loaded_from": "selected_threshold"},
        )

    def _load_url_config(self) -> ThresholdConfig:
        """Load URL detection thresholds from training report."""
        report = self._load_json(maybe_find_asset_path(Path(__file__), "URL", "models", "training_report.json"))
        selected_threshold = (
            report.get("ensemble_soft_voting", {}).get("selected_threshold")
            if isinstance(report, dict)
            else None
        )

        if isinstance(selected_threshold, (int, float)):
            threat_threshold, suspicious_threshold = self._derive_thresholds(float(selected_threshold) * 100.0)
        else:
            threat_threshold, suspicious_threshold = self._derive_thresholds(70.0)

        return ThresholdConfig(
            detection_type="url",
            threat_threshold=threat_threshold,
            suspicious_threshold=suspicious_threshold,
            selected_threshold=selected_threshold,
            metadata={"source": "URL/models/training_report.json", "loaded_from": "ensemble_soft_voting"},
        )

    def _load_all_configs(self) -> None:
        """Load all detection type configurations."""
        try:
            self._configs["file"] = self._load_file_config()
        except Exception:
            self._configs["file"] = self.DEFAULTS["file"]

        try:
            self._configs["email"] = self._load_email_config()
        except Exception:
            self._configs["email"] = self.DEFAULTS["email"]

        try:
            self._configs["url"] = self._load_url_config()
        except Exception:
            self._configs["url"] = self.DEFAULTS["url"]

    def get(self, detection_type: str) -> ThresholdConfig:
        """Get threshold config for a detection type."""
        detection_type = str(detection_type).lower()
        return self._configs.get(detection_type) or self.DEFAULTS.get(detection_type)

    def reload(self) -> None:
        """Reload all configurations from disk (useful for hot-reloading)."""
        self._configs = {}
        self._load_all_configs()

    def get_all(self) -> dict[str, ThresholdConfig]:
        """Get all threshold configurations."""
        return dict(self._configs)


def get_threshold_config(detection_type: str) -> ThresholdConfig:
    """Convenience function to get threshold config for a detection type."""
    return ThresholdRegistry().get(detection_type)
