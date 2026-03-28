"""Model loading and top-level analysis orchestration service."""

from __future__ import annotations

from typing import Any

import joblib
from fastapi import HTTPException

from config import DEFAULT_THRESHOLD, MODEL_FALLBACK_PATHS
from services.analyzers import (
    analyze_attachments,
    analyze_headers,
    analyze_html_signals,
    analyze_language,
    analyze_urls,
)
from services.scoring import build_indicators, compute_confidence, compute_risk_score, determine_verdict
from services.text_processing import clean_preview_text, clean_text


def load_model_artifact() -> dict[str, Any]:
    """Load and validate the serialized model artifact."""
    checked_paths: list[str] = []
    resolved_model_path = None
    for candidate in MODEL_FALLBACK_PATHS:
        path = candidate.resolve()
        checked_paths.append(str(path))
        if path.is_file():
            resolved_model_path = path
            break

    if resolved_model_path is None:
        checked = "\n- ".join(checked_paths)
        raise RuntimeError(f"Model file not found. Checked paths:\n- {checked}")

    artifact = joblib.load(resolved_model_path)
    required_keys = {"vectorizer", "classifier", "label_map"}
    missing_keys = required_keys.difference(artifact.keys())
    if missing_keys:
        missing = ", ".join(sorted(missing_keys))
        raise RuntimeError(f"Invalid model artifact. Missing keys: {missing}")

    artifact["model_path"] = str(resolved_model_path)
    return artifact


def analyze_content(
    *,
    filename: str,
    subject: str,
    body: str,
    sender: str,
    reply_to: str,
    return_path: str,
    has_html: bool,
    attachment_names: list[str],
    attachment_extensions: list[str],
    vectorizer: Any,
    classifier: Any,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    """Run model inference + multi-signal static analysis and build response payload."""
    combined_text = f"{subject}\n{body}"  # Keep identical with training pipeline.
    cleaned_text = clean_text(combined_text)
    if not cleaned_text:
        raise HTTPException(status_code=400, detail="No usable text could be extracted from email.")

    if not hasattr(classifier, "predict_proba"):
        raise HTTPException(status_code=500, detail="Loaded classifier does not support predict_proba.")

    features = vectorizer.transform([cleaned_text])
    spam_probability = float(classifier.predict_proba(features)[0][1])

    header_analysis = analyze_headers(sender, reply_to, return_path)
    url_analysis = analyze_urls(combined_text)
    language_analysis = analyze_language(cleaned_text)
    html_analysis = analyze_html_signals(
        has_html=has_html,
        url_count=url_analysis["url_count"],
        has_phishing=language_analysis["has_phishing"],
        has_marketing=language_analysis["has_marketing"],
        cleaned_text=cleaned_text,
    )
    attachment_analysis = analyze_attachments(attachment_names, attachment_extensions)

    risk_score = compute_risk_score(
        spam_probability=spam_probability,
        threshold=threshold,
        header_analysis=header_analysis,
        url_analysis=url_analysis,
        html_analysis=html_analysis,
        attachment_analysis=attachment_analysis,
        language_analysis=language_analysis,
    )
    verdict = determine_verdict(risk_score, spam_probability)
    confidence = compute_confidence(verdict, spam_probability, risk_score)

    indicators = build_indicators(
        spam_probability=spam_probability,
        threshold=threshold,
        risk_score=risk_score,
        verdict=verdict,
        header_flags=header_analysis["header_flags"],
        url_flags=url_analysis["url_flags"],
        html_flags=html_analysis["html_flags"],
        attachment_flags=attachment_analysis["attachment_flags"],
        language_flags=language_analysis["language_flags"],
        newsletter_like=html_analysis["newsletter_like"],
        has_phishing=language_analysis["has_phishing"],
        has_suspicious_urls=bool(url_analysis["suspicious_urls"]),
        has_risky_attachments=bool(
            attachment_analysis["has_risky_exec"]
            or attachment_analysis["has_macro"]
            or attachment_analysis["has_compressed"]
        ),
        trusted_or_academic_sender=bool(header_analysis["is_official"] or header_analysis["is_academic"]),
    )

    preview = clean_preview_text(combined_text, max_length=400)

    return {
        "filename": filename,
        "subject": subject or "(no subject)",
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "verdict": verdict,
        "confidence": round(confidence, 6),
        "threshold": round(float(threshold), 6),
        "spam_probability": round(spam_probability, 6),
        "risk_score": round(risk_score, 2),
        "has_html": has_html,
        "url_count": url_analysis["url_count"],
        "extracted_urls": url_analysis["extracted_urls"],
        "suspicious_urls": url_analysis["suspicious_urls"],
        "attachment_count": attachment_analysis["attachment_count"],
        "attachment_names": attachment_analysis["attachment_names"],
        "attachment_extensions": attachment_analysis["attachment_extensions"],
        "header_flags": header_analysis["header_flags"],
        "url_flags": url_analysis["url_flags"],
        "html_flags": html_analysis["html_flags"],
        "attachment_flags": attachment_analysis["attachment_flags"],
        "language_flags": language_analysis["language_flags"],
        "indicators": indicators,
        "preview": preview,
    }
