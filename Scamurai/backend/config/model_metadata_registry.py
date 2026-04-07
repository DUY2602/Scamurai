"""
Model versioning and metrics registry - track which model/threshold/metrics are in use.

Each detection service maintains versioning info about the models being used.
When returning detection results, include this metadata for auditability.

Version: 1.0
Last Updated: 2026-04-07
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.services.asset_paths import maybe_find_asset_path


class ModelMetadata:
    """Immutable metadata about a deployed model."""

    def __init__(
        self,
        detection_type: str,
        model_version: str,
        threshold_version: str,
        trained_at: str | None = None,
        metrics: dict[str, Any] | None = None,
        features: list[str] | None = None,
        feature_importance: dict[str, Any] | None = None,
    ):
        self.detection_type = detection_type
        self.model_version = model_version
        self.threshold_version = threshold_version
        self.trained_at = trained_at or datetime.utcnow().isoformat()
        self.metrics = metrics or {}
        self.features = features or []
        self.feature_importance = feature_importance or {}

    def to_dict(self) -> dict[str, Any]:
        """Export as dict for API responses."""
        return {
            "model_version": self.model_version,
            "threshold_version": self.threshold_version,
            "trained_at": self.trained_at,
            "detection_type": self.detection_type,
            "metrics_available": bool(self.metrics),
            "feature_count": len(self.features),
            "feature_importance_available": bool(self.feature_importance),
        }

    def to_dict_full(self) -> dict[str, Any]:
        """Export full metadata including metrics and feature importance (for logging/debugging)."""
        result = self.to_dict()
        if self.metrics:
            result["metrics"] = self.metrics
        if self.features:
            result["features"] = self.features
        if self.feature_importance:
            result["feature_importance"] = self.feature_importance
        return result


class ModelMetadataRegistry:
    """
    Central registry for model metadata - provides version and metrics info.
    Each detection type loads metadata from its training artifacts.
    """

    _instance: ModelMetadataRegistry | None = None
    _metadata: dict[str, ModelMetadata] = {}

    def __new__(cls) -> ModelMetadataRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._metadata = {}
        self._load_all_metadata()
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
    def _generate_version_hash(data: dict) -> str:
        """Generate a version hash from report data."""
        import hashlib

        # Create a stable hash from key metrics
        hash_input = json.dumps(
            {
                "ensemble.accuracy": data.get("ensemble", {}).get("accuracy"),
                "ensemble.f1": data.get("ensemble", {}).get("f1"),
                "ensemble_soft_voting.selected": (
                    data.get("ensemble_soft_voting", {}).get("selected_threshold")
                ),
            },
            sort_keys=True,
        )
        hash_obj = hashlib.sha256(hash_input.encode())
        return hash_obj.hexdigest()[:12]

    def _load_file_metadata(self) -> ModelMetadata:
        """Load FILE model metadata from training report."""
        report = self._load_json(maybe_find_asset_path(Path(__file__), "FILE", "models", "training_report.json"))

        if not isinstance(report, dict):
            return ModelMetadata(
                detection_type="file",
                model_version="unknown",
                threshold_version="unknown",
            )

        version_hash = self._generate_version_hash(report)
        metrics = {
            "ensemble_accuracy": report.get("ensemble", {}).get("accuracy"),
            "ensemble_f1": report.get("ensemble", {}).get("f1"),
            "ensemble_roc_auc": report.get("ensemble", {}).get("roc_auc"),
            "lightgbm_accuracy": report.get("lightgbm", {}).get("accuracy"),
            "xgboost_accuracy": report.get("xgboost", {}).get("accuracy"),
        }
        selected_threshold = report.get("ensemble_soft_voting", {}).get("selected_threshold")
        feature_importance = report.get("feature_importance", {})

        return ModelMetadata(
            detection_type="file",
            model_version=f"file-{version_hash}",
            threshold_version=f"threshold-{selected_threshold}",
            trained_at=report.get("metadata", {}).get("trained_at"),
            metrics={k: v for k, v in metrics.items() if v is not None},
            features=report.get("metadata", {}).get("feature_columns", []),
            feature_importance=feature_importance,
        )

    def _load_email_metadata(self) -> ModelMetadata:
        """Load EMAIL model metadata from best_model_metadata."""
        metadata = self._load_json(
            maybe_find_asset_path(Path(__file__), "Email", "models", "best_model_metadata.json")
        )

        if not isinstance(metadata, dict):
            return ModelMetadata(
                detection_type="email",
                model_version="unknown",
                threshold_version="unknown",
            )

        version_hash = self._generate_version_hash(metadata)
        threshold = metadata.get("selected_threshold")

        return ModelMetadata(
            detection_type="email",
            model_version=f"email-{version_hash}",
            threshold_version=f"threshold-{threshold}",
            trained_at=metadata.get("trained_at"),
            metrics={k: v for k, v in metadata.items() if k not in ["selected_threshold", "trained_at"]},
        )

    def _load_url_metadata(self) -> ModelMetadata:
        """Load URL model metadata from training report."""
        report = self._load_json(maybe_find_asset_path(Path(__file__), "URL", "models", "training_report.json"))

        if not isinstance(report, dict):
            return ModelMetadata(
                detection_type="url",
                model_version="unknown",
                threshold_version="unknown",
            )

        version_hash = self._generate_version_hash(report)
        metrics = {
            "ensemble_accuracy": report.get("ensemble", {}).get("accuracy"),
            "ensemble_f1": report.get("ensemble", {}).get("f1"),
            "ensemble_roc_auc": report.get("ensemble", {}).get("roc_auc"),
            "lgbm_accuracy": report.get("lgbm", {}).get("accuracy"),
            "xgb_accuracy": report.get("xgb", {}).get("accuracy"),
        }
        selected_threshold = report.get("ensemble_soft_voting", {}).get("selected_threshold")
        feature_importance = report.get("feature_importance", {})

        return ModelMetadata(
            detection_type="url",
            model_version=f"url-{version_hash}",
            threshold_version=f"threshold-{selected_threshold}",
            trained_at=report.get("metadata", {}).get("trained_at"),
            metrics={k: v for k, v in metrics.items() if v is not None},
            features=report.get("metadata", {}).get("feature_columns", []),
            feature_importance=feature_importance,
        )

    def _load_all_metadata(self) -> None:
        """Load metadata for all detection types."""
        try:
            self._metadata["file"] = self._load_file_metadata()
        except Exception:
            self._metadata["file"] = ModelMetadata("file", "error", "error")

        try:
            self._metadata["email"] = self._load_email_metadata()
        except Exception:
            self._metadata["email"] = ModelMetadata("email", "error", "error")

        try:
            self._metadata["url"] = self._load_url_metadata()
        except Exception:
            self._metadata["url"] = ModelMetadata("url", "error", "error")

    def get(self, detection_type: str) -> ModelMetadata:
        """Get metadata for a detection type."""
        detection_type = str(detection_type).lower()
        return self._metadata.get(detection_type) or ModelMetadata(detection_type, "unknown", "unknown")

    def reload(self) -> None:
        """Reload all metadata from disk."""
        self._metadata = {}
        self._load_all_metadata()

    def get_all(self) -> dict[str, ModelMetadata]:
        """Get metadata for all detection types."""
        return dict(self._metadata)


def get_model_metadata(detection_type: str) -> ModelMetadata:
    """Convenience function to get model metadata."""
    return ModelMetadataRegistry().get(detection_type)
