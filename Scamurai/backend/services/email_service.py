import math

from backend.config.threshold_registry import get_threshold_config
from backend.services.predict_email import predict_email_bytes, predict_email_parts
from backend.services.url_service import predict_url

# Load from centralizedthreshold registry
THRESHOLD_CONFIG = get_threshold_config("email")


def _dedupe_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []

    for url in urls:
        normalized = str(url or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)

    return deduped


def _scan_embedded_urls(urls: list[str]) -> list[dict]:
    scans: list[dict] = []

    for url in _dedupe_urls(urls):
        try:
            scan_result = predict_url(url)
            scans.append(
                {
                    "url": url,
                    "status": scan_result.get("status", "unknown"),
                    "verdict": scan_result.get("verdict", "UNKNOWN"),
                    "risk_score": int(scan_result.get("risk_score", 0) or 0),
                    "confidence": float(scan_result.get("confidence", 0.0) or 0.0),
                    "is_malicious": bool(scan_result.get("is_malicious", False)),
                    "is_suspicious": bool(scan_result.get("is_suspicious", False)),
                }
            )
        except Exception as exc:
            scans.append(
                {
                    "url": url,
                    "status": "unknown",
                    "verdict": "UNKNOWN",
                    "risk_score": 0,
                    "confidence": 0.0,
                    "is_malicious": False,
                    "is_suspicious": False,
                    "error": str(exc),
                }
            )

    return scans


def _calculate_email_risk_score(result: dict, url_scans: list[dict]) -> tuple[int, dict]:
    spam_probability = float(result["spam_probability"])
    base_risk_score = int(max(0, min(100, math.ceil(spam_probability * 100))))

    malicious_urls = [scan for scan in url_scans if scan.get("status") == "threat" or scan.get("is_malicious")]
    suspicious_urls = [scan for scan in url_scans if scan.get("status") == "suspicious" or scan.get("is_suspicious")]
    safe_urls = [scan for scan in url_scans if scan.get("status") == "safe"]
    unknown_urls = [scan for scan in url_scans if scan.get("status") not in {"threat", "suspicious", "safe"}]
    max_url_risk = max((int(scan.get("risk_score", 0) or 0) for scan in url_scans), default=0)

    adjusted_risk_score = float(base_risk_score)
    adjustment_reasons: list[str] = []

    if malicious_urls:
        adjusted_risk_score += 18 + min(24, len(malicious_urls) * 8)
        if max_url_risk >= 90:
            adjusted_risk_score += 6
        adjustment_reasons.append(
            f"boosted_by_{len(malicious_urls)}_confirmed_malicious_url"
        )
    elif suspicious_urls:
        adjusted_risk_score += 8 + min(12, len(suspicious_urls) * 4)
        adjustment_reasons.append(
            f"boosted_by_{len(suspicious_urls)}_suspicious_url"
        )
    elif safe_urls:
        safe_url_discount = min(24, 10 + max(0, len(safe_urls) - 1) * 2)
        adjusted_risk_score -= safe_url_discount
        adjustment_reasons.append("safe_urls_do_not_increase_email_risk")
    elif unknown_urls:
        adjustment_reasons.append("url_scan_unavailable_no_url_risk_boost_applied")

    risk_score = int(max(0, min(100, round(adjusted_risk_score))))
    return risk_score, {
        "base_risk_score": base_risk_score,
        "max_url_risk_score": max_url_risk,
        "malicious_url_count": len(malicious_urls),
        "suspicious_url_count": len(suspicious_urls),
        "safe_url_count": len(safe_urls),
        "unknown_url_count": len(unknown_urls),
        "adjustment_reasons": adjustment_reasons,
    }


def _build_api_result(result: dict, source_value: str) -> dict:
    model_predicted_label = str(result["predicted_label"]).lower()
    spam_probability = float(result["spam_probability"])
    model_spam_probability = float(result.get("model_spam_probability", spam_probability))
    semantic_signals = result.get("semantic_signals", {})
    url_scans = _scan_embedded_urls(result.get("urls", []))
    risk_score, url_scan_summary = _calculate_email_risk_score(result, url_scans)
    confidence = spam_probability if model_predicted_label == "spam" else 1.0 - spam_probability
    
    # Use centralized thresholds for status determination
    status = THRESHOLD_CONFIG.classify_status(risk_score)
    
    # Map status to verdict
    if status == "threat":
        verdict = "SPAM"
        predicted_class = "spam"
        is_spam = True
        is_suspicious = False
    elif status == "suspicious":
        verdict = "SUSPICIOUS"
        predicted_class = "suspicious"
        is_spam = False
        is_suspicious = True
    else:
        verdict = "HAM"
        predicted_class = "ham"
        is_spam = False
        is_suspicious = False

    return {
        "detection_type": "email",
        "source_value": source_value or "email-input",
        "status": status,
        "verdict": verdict,
        "predicted_class": predicted_class,
        "model_predicted_class": model_predicted_label,
        "decision_threshold": THRESHOLD_CONFIG.threat_threshold,
        "decision_threshold_suspicious": THRESHOLD_CONFIG.suspicious_threshold,
        "signal_strength": "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low",
        "risk_score": risk_score,
        "confidence": round(confidence * 100, 2),
        "is_spam": is_spam,
        "is_malicious": is_spam,
        "is_suspicious": is_suspicious,
        "subject_preview": str(result.get("subject", ""))[:100],
        "key_features": {
            "subject_length": len(str(result.get("subject", ""))),
            "body_length": len(str(result.get("body", ""))),
            "url_count": len(result.get("urls", [])),
            "scanned_url_count": len(url_scans),
            "model_spam_probability": round(model_spam_probability, 4),
            "phishing_signal_score": semantic_signals.get("phishing_score", 0.0),
            "legitimate_signal_score": semantic_signals.get("legitimate_score", 0.0),
            "used_semantic_predict_logic": True,
            "base_email_risk_score": url_scan_summary["base_risk_score"],
            "max_embedded_url_risk_score": url_scan_summary["max_url_risk_score"],
            "malicious_url_count": url_scan_summary["malicious_url_count"],
            "suspicious_url_count": url_scan_summary["suspicious_url_count"],
            "safe_url_count": url_scan_summary["safe_url_count"],
            "unknown_url_count": url_scan_summary["unknown_url_count"],
            "url_risk_adjustment_reasons": url_scan_summary["adjustment_reasons"],
        },
        "spam_probability": round(spam_probability, 4),
        "embedded_url_analysis": url_scans,
        "reasons": [
            *result.get("reasons", []),
            *url_scan_summary["adjustment_reasons"],
        ],
    }


def predict_from_text(subject: str, body: str, sender: str = "") -> dict:
    result = predict_email_parts(subject, body, sender=sender)
    source_value = str(subject or sender or "email-input")[:100]
    return _build_api_result(result, source_value)


def predict_from_file(filename: str, raw: bytes) -> dict:
    result = predict_email_bytes(raw)
    response = _build_api_result(result, str(result.get("subject", "") or filename)[:100])
    response["filename"] = filename
    if not response.get("source_value") or response["source_value"] == "email-input":
        response["source_value"] = filename
    return response
