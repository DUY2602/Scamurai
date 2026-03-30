import asyncio
import importlib.util
import io
import sys
import threading
from pathlib import Path
from typing import Any

from fastapi import UploadFile


ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "WEEK-6-main" / "backend"
BACKEND_APP_PATH = BACKEND_DIR / "app.py"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _load_backend_app():
    module_name = "week6_email_backend_app"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing

    spec = importlib.util.spec_from_file_location(module_name, BACKEND_APP_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load backend app module from {BACKEND_APP_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_BACKEND_APP = _load_backend_app()
from schemas import AnalyzeTextRequest  # noqa: E402


def _initialize_backend_state() -> dict[str, Any]:
    artifact = _BACKEND_APP.load_model_artifact()
    _BACKEND_APP.app.state.vectorizer = artifact["vectorizer"]
    _BACKEND_APP.app.state.classifier = artifact["classifier"]
    _BACKEND_APP.app.state.label_map = artifact.get("label_map", {0: "ham", 1: "spam"})
    _BACKEND_APP.app.state.threshold = float(
        artifact.get("threshold", getattr(_BACKEND_APP, "DEFAULT_THRESHOLD", 0.5))
    )
    return artifact


MODEL_ARTIFACT = _initialize_backend_state()


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: dict[str, BaseException] = {}

    def runner():
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # pragma: no cover - passthrough helper
            error["value"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()

    if "value" in error:
        raise error["value"]
    return result["value"]


def _normalize_label(backend_result: dict[str, Any]) -> str:
    verdict = str(backend_result.get("verdict", "")).strip().upper()
    if verdict == "HAM":
        return "ham"
    if verdict in {"SPAM", "THREAT"}:
        return "spam"

    spam_probability = float(backend_result.get("spam_probability", 0.0))
    threshold = float(backend_result.get("threshold", 0.5))
    return "spam" if spam_probability >= threshold else "ham"


def _normalize_risk_score(raw_risk_score: Any) -> float:
    try:
        numeric_score = float(raw_risk_score)
    except (TypeError, ValueError):
        numeric_score = 0.0
    return max(0.0, min(numeric_score / 100.0, 1.0))


def _adapt_backend_result(backend_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": _normalize_label(backend_result),
        "confidence": float(backend_result.get("confidence", 0.0)),
        "spam_probability": float(backend_result.get("spam_probability", 0.0)),
        "risk_score": _normalize_risk_score(backend_result.get("risk_score", 0.0)),
        "indicators": list(backend_result.get("indicators", [])),
    }


def predict_from_file(eml_path: str) -> dict:
    """
    Accepts path to a .eml file.
    Returns dict with keys:
        label       : "spam" or "ham"
        confidence  : float 0-1
        spam_probability : float 0-1
        risk_score  : float 0-1
        indicators  : list of strings
    """
    file_path = Path(str(eml_path or "")).expanduser().resolve()
    if not file_path.is_file():
        raise FileNotFoundError(f"Email file not found: {file_path}")

    upload = UploadFile(filename=file_path.name, file=io.BytesIO(file_path.read_bytes()))
    backend_result = _run_async(_BACKEND_APP.analyze_email(upload))
    return _adapt_backend_result(backend_result)


def predict_from_text(subject: str, body: str) -> dict:
    """
    Accepts raw subject and body strings.
    Returns same dict schema as predict_from_file.
    """
    payload = AnalyzeTextRequest(subject=subject or "", body=body or "")
    backend_result = _run_async(_BACKEND_APP.analyze_text(payload))
    return _adapt_backend_result(backend_result)


if __name__ == "__main__":
    result = predict_from_text(
        subject="Urgent: Verify your account now",
        body="Click here to claim your reward immediately",
    )
    print(result)
