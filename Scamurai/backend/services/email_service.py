import math

from backend.services.predict_email import predict_email_bytes, predict_email_parts

SUSPICIOUS_LOWER_BOUND = 0.45
SUSPICIOUS_UPPER_BOUND = 0.6


def _build_api_result(result: dict, source_value: str) -> dict:
    predicted_label = str(result["predicted_label"]).lower()
    spam_probability = float(result["spam_probability"])
    model_spam_probability = float(result.get("model_spam_probability", spam_probability))
    semantic_signals = result.get("semantic_signals", {})
    risk_score = int(max(0, min(100, math.ceil(spam_probability * 100))))
    confidence = spam_probability if predicted_label == "spam" else 1.0 - spam_probability
    if spam_probability >= SUSPICIOUS_UPPER_BOUND:
        status = "threat"
        verdict = "SPAM"
        is_spam = True
        is_suspicious = False
    elif spam_probability >= SUSPICIOUS_LOWER_BOUND:
        status = "suspicious"
        verdict = "SUSPICIOUS"
        is_spam = False
        is_suspicious = True
    else:
        status = "safe"
        verdict = "HAM"
        is_spam = False
        is_suspicious = False

    return {
        "detection_type": "email",
        "source_value": source_value or "email-input",
        "status": status,
        "verdict": verdict,
        "predicted_class": predicted_label,
        "decision_threshold": round(float(result["threshold"]) * 100, 2),
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
            "model_spam_probability": round(model_spam_probability, 4),
            "phishing_signal_score": semantic_signals.get("phishing_score", 0.0),
            "legitimate_signal_score": semantic_signals.get("legitimate_score", 0.0),
            "used_semantic_predict_logic": True,
        },
        "spam_probability": round(spam_probability, 4),
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
