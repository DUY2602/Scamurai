import joblib
from email import policy
from email.parser import BytesParser
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[3]
MODEL_DIR = ROOT_DIR / "Email" / "models"
model = joblib.load(MODEL_DIR / "best_model.pkl")
vectorizer = joblib.load(MODEL_DIR / "vectorizer.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")


def classify_status(risk_score: float) -> str:
    if risk_score >= 70:
        return "threat"
    if risk_score >= 40:
        return "suspicious"
    return "safe"


def probability_confidence(probability: float) -> float:
    return round(max(probability, 1 - probability) * 100, 2)


def classify_signal_strength(risk_score: float) -> str:
    if risk_score >= 80 or risk_score <= 20:
        return "high"
    if risk_score >= 65 or risk_score <= 35:
        return "medium"
    return "moderate"


def clean_text(text: str) -> str:
    import re

    text = text.lower()
    text = re.sub(r"http\S+", " urltoken ", text)
    text = re.sub(r"\S+@\S+", " emailtoken ", text)
    text = re.sub(r"[^a-z0-9\s]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def build_features(subject: str, body: str, sender: str = ""):
    import scipy.sparse as sp

    combined = f"{subject}\n{body}"
    cleaned = clean_text(combined)

    tfidf_vec = vectorizer.transform([cleaned])

    num_urls = combined.lower().count("http")
    num_excl = combined.count("!")
    upper_r = sum(1 for char in combined if char.isupper()) / (len(combined) + 1)
    url_ratio = num_urls / (len(combined.split()) + 1)
    has_greet = int(any(word in combined.lower() for word in ["dear", "hello", "hi "]))
    free_email = int(any(domain in sender.lower() for domain in ["gmail", "yahoo", "hotmail"]))

    num_feat = scaler.transform(
        [[num_urls, len(combined), num_excl, upper_r, url_ratio, has_greet, free_email]]
    )
    return sp.hstack([tfidf_vec, num_feat])


def predict_from_text(subject: str, body: str, sender: str = "") -> dict:
    features = build_features(subject, body, sender)
    spam_probability = float(model.predict_proba(features)[0][1])
    risk_score = round(spam_probability * 100, 2)
    confidence = probability_confidence(spam_probability)
    status = classify_status(risk_score)
    verdict = "SPAM" if status == "threat" else ("SUSPICIOUS" if status == "suspicious" else "HAM")
    predicted_class = "spam" if spam_probability >= 0.5 else "ham"
    decision_threshold = 70
    signal_strength = classify_signal_strength(risk_score)
    combined = f"{subject}\n{body}"
    key_features = {
        "subject_length": len(subject),
        "body_length": len(body),
        "url_count": combined.lower().count("http"),
        "exclamation_count": combined.count("!"),
        "has_free_sender_domain": any(domain in sender.lower() for domain in ["gmail", "yahoo", "hotmail"]),
    }

    return {
        "detection_type": "email",
        "source_value": subject[:100] or sender[:100] or "email-input",
        "status": status,
        "verdict": verdict,
        "predicted_class": predicted_class,
        "decision_threshold": decision_threshold,
        "signal_strength": signal_strength,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_spam": status == "threat",
        "is_malicious": status == "threat",
        "is_suspicious": status == "suspicious",
        "subject_preview": subject[:100],
        "key_features": key_features,
    }


def predict_from_file(filename: str, raw: bytes) -> dict:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        subject = str(message.get("Subject", "") or "")
        sender = str(message.get("From", "") or "")
        parts = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    parts.append(part.get_content())
        else:
            parts.append(message.get_content())
        body = "\n".join(parts)
    except Exception:
        subject, body, sender = "", raw.decode("utf-8", errors="ignore"), ""

    result = predict_from_text(subject, body, sender)
    result["filename"] = filename
    if not result.get("source_value") or result["source_value"] == "email-input":
        result["source_value"] = filename
    return result
