"""Prediction helpers for the Email package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

try:
    from .pipeline import NUMERIC_FEATURES, build_feature_frame, extract_email_parts_from_path
except ImportError:  # pragma: no cover - direct script execution fallback
    REPO_ROOT = Path(__file__).resolve().parents[1]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from Email.pipeline import NUMERIC_FEATURES, build_feature_frame, extract_email_parts_from_path


ROOT_DIR = Path(__file__).resolve().parent
MODELS_DIR = ROOT_DIR / "models"
BEST_MODEL_PATH = MODELS_DIR / "best_model.pkl"
BEST_MODEL_META_PATH = MODELS_DIR / "best_model_metadata.json"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"

_ARTIFACT_CACHE: dict[str, Any] | None = None


def _load_optional_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_artifacts() -> dict[str, Any]:
    global _ARTIFACT_CACHE
    if _ARTIFACT_CACHE is not None:
        return _ARTIFACT_CACHE

    vectorizer = joblib.load(VECTORIZER_PATH)
    scaler = joblib.load(SCALER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    metadata = _load_optional_json(BEST_MODEL_META_PATH)
    inferred_feature_count = len(getattr(vectorizer, "vocabulary_", {})) + int(getattr(scaler, "n_features_in_", 0) or 0)
    if not BEST_MODEL_PATH.is_file():
        raise FileNotFoundError(
            "Email runtime requires models/best_model.pkl. "
            "Legacy lgb_model.pkl/xgb_model.pkl are archived artifacts and are not used in production."
        )

    model = joblib.load(BEST_MODEL_PATH)
    model_feature_count = getattr(model, "n_features_in_", None)
    if model_feature_count is not None and inferred_feature_count and int(model_feature_count) != inferred_feature_count:
        raise RuntimeError(
            f"best_model expects {int(model_feature_count)} features, "
            f"but vectorizer+scaler provide {inferred_feature_count}. "
            "Refusing to fall back to legacy Email models because that can silently serve the wrong classifier."
        )

    mode = "best_single_model"
    model_name = metadata.get("selected_model", type(model).__name__)

    _ARTIFACT_CACHE = {
        "mode": mode,
        "model": model,
        "model_name": model_name,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "label_encoder": label_encoder,
        "metadata": metadata,
    }
    return _ARTIFACT_CACHE


def reload_artifacts() -> dict[str, Any]:
    """Clear the in-process cache and reload Email artifacts from disk."""
    global _ARTIFACT_CACHE
    _ARTIFACT_CACHE = None
    return _load_artifacts()


def load_email_artifacts(verbose: bool = False) -> dict[str, Any]:
    """Backward-compatible wrapper for runtime callers."""
    artifacts = reload_artifacts()
    if verbose:
        description = describe_loaded_artifacts()
        print(json.dumps(description, indent=2))
    return artifacts


def describe_loaded_artifacts() -> dict[str, Any]:
    """Return a compact description of the currently active Email runtime artifacts."""
    artifacts = _load_artifacts()
    description = {
        "mode": artifacts["mode"],
        "model_name": artifacts["model_name"],
        "vectorizer_path": str(VECTORIZER_PATH),
        "scaler_path": str(SCALER_PATH),
        "label_encoder_path": str(LABEL_ENCODER_PATH),
        "numeric_features": list(NUMERIC_FEATURES),
        "label_classes": artifacts["label_encoder"].classes_.tolist(),
    }
    description["best_model_path"] = str(BEST_MODEL_PATH)
    description["model_type"] = type(artifacts["model"]).__name__
    return description


def _transform_frame(feature_frame, vectorizer, scaler):
    tfidf = vectorizer.transform(feature_frame["full_clean_text"])
    numeric = scaler.transform(feature_frame[NUMERIC_FEATURES])
    return hstack([tfidf, csr_matrix(numeric)]).tocsr()


def _positive_probability(model: Any, X_input) -> float:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X_input)[0]
        return float(probabilities[-1])
    if hasattr(model, "decision_function"):
        decision = float(np.ravel(model.decision_function(X_input))[0])
        return float(1.0 / (1.0 + np.exp(-decision)))
    prediction = model.predict(X_input)[0]
    return 1.0 if int(prediction) == 1 else 0.0


def _predict_probability(feature_frame) -> tuple[float, list[str]]:
    artifacts = _load_artifacts()
    X_input = _transform_frame(feature_frame, artifacts["vectorizer"], artifacts["scaler"])
    probability = _positive_probability(artifacts["model"], X_input)
    indicators = [f"Runtime model: {type(artifacts['model']).__name__} ({artifacts['model_name']})."]
    return probability, indicators


def predict_from_parts(subject: str, body: str, sender: str = "") -> dict[str, Any]:
    """Predict ham/spam from subject/body text using the current Email artifacts."""
    if not str(subject or "").strip() and not str(body or "").strip():
        raise ValueError("Provide at least one of subject or body for Email inference.")
    feature_frame = build_feature_frame(subject, body, sender=sender)
    spam_probability, indicators = _predict_probability(feature_frame)
    label_encoder = _load_artifacts()["label_encoder"]
    predicted_index = 1 if spam_probability >= 0.5 else 0
    predicted_label = str(label_encoder.inverse_transform([predicted_index])[0]).lower()
    confidence = spam_probability if predicted_label == "spam" else 1.0 - spam_probability
    return {
        "label": predicted_label,
        "confidence": float(confidence),
        "spam_probability": float(spam_probability),
        "subject": str(subject or ""),
        "sender": str(sender or ""),
        "indicators": indicators,
    }


def predict_from_text(subject: str, body: str) -> dict[str, Any]:
    """Convenience wrapper for subject/body-only callers."""
    return predict_from_parts(subject, body, sender="")


def predict_from_file(eml_path: str | Path) -> dict[str, Any]:
    """Parse a raw email file and run inference with the active Email model."""
    subject, body, sender = extract_email_parts_from_path(eml_path)
    result = predict_from_parts(subject, body, sender=sender)
    result["file_path"] = str(Path(eml_path))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Email inference on a raw .eml/.txt file.")
    parser.add_argument("email_file", type=Path, help="Path to the .eml or raw email file.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a human-readable summary.")
    args = parser.parse_args()

    result = predict_from_file(args.email_file)
    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("=" * 60)
    print("EMAIL PREDICTION RESULT")
    print("=" * 60)
    print(f"File:             {args.email_file}")
    print(f"Label:            {result['label'].upper()}")
    print(f"Confidence:       {result['confidence']:.4f}")
    print(f"Spam probability: {result['spam_probability']:.4f}")
    if result.get("sender"):
        print(f"Sender:           {result['sender']}")
    if result.get("subject"):
        print(f"Subject:          {result['subject']}")
    if result.get("indicators"):
        print("\nIndicators:")
        for indicator in result["indicators"]:
            print(f"- {indicator}")
    print("=" * 60)


if __name__ == "__main__":
    main()
