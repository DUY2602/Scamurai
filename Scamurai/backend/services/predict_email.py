import argparse
import html
import math
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

import joblib

from backend.services.asset_paths import find_asset_dir

MODEL_DIR = find_asset_dir(Path(__file__), "Email", "models")
MODEL_ARTIFACT = joblib.load(MODEL_DIR / "spam_model.joblib")
VECTORIZER = MODEL_ARTIFACT["vectorizer"]
CLASSIFIER = MODEL_ARTIFACT["classifier"]
LABEL_MAP = MODEL_ARTIFACT.get("label_map", {0: "ham", 1: "spam"})
DEFAULT_THRESHOLD = float(MODEL_ARTIFACT.get("threshold", 0.5))

PHISHING_SIGNAL_WEIGHTS = {
    "credential": {
        "verify your account": 0.18,
        "verify account": 0.16,
        "confirm your account": 0.14,
        "password": 0.12,
        "reset password": 0.18,
        "login": 0.1,
        "sign in": 0.1,
        "security alert": 0.12,
        "unusual activity": 0.12,
        "account suspended": 0.16,
    },
    "urgency": {
        "urgent": 0.1,
        "immediately": 0.08,
        "within 24 hours": 0.14,
        "final notice": 0.12,
        "last warning": 0.14,
        "action required": 0.12,
        "limited time": 0.08,
    },
    "money": {
        "invoice": 0.12,
        "payment": 0.12,
        "refund": 0.12,
        "bank": 0.1,
        "wire transfer": 0.16,
        "gift card": 0.12,
        "crypto": 0.12,
    },
    "document_lure": {
        "shared document": 0.18,
        "view document": 0.16,
        "open document": 0.16,
        "document preview": 0.14,
        "access document": 0.14,
        "docusign": 0.14,
        "onedrive": 0.12,
        "dropbox": 0.1,
    },
}

LEGITIMATE_SIGNAL_WEIGHTS = {
    "academic": {
        "semester": 0.18,
        "unit enrolment": 0.24,
        "enrolment": 0.18,
        "course": 0.1,
        "lecturer": 0.12,
        "canvas": 0.16,
        "announcement": 0.14,
        "students": 0.08,
        "class": 0.08,
        "research-based learning festival": 0.22,
        "swinburne": 0.18,
    },
    "newsletter": {
        "unsubscribe": 0.16,
        "privacy policy": 0.12,
        "privacy statement": 0.12,
        "share your experience": 0.16,
        "survey": 0.12,
        "newsletter": 0.1,
        "thank you for your interest": 0.16,
    },
    "notification": {
        "budget notification": 0.22,
        "credits remaining": 0.16,
        "receipt": 0.1,
        "notification": 0.08,
        "reminder": 0.08,
    },
}

TRUSTED_SENDER_HINTS = (
    "swin.edu.au",
    "swinburne.edu.vn",
    "instructure.com",
    "canvaslms.com",
    "coursera.org",
    "netacad.com",
    "cisco.com",
    "vocareum.com",
)


def strip_html(html_text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html_text or "")
    return html.unescape(text)


def fallback_subject_body(text: str) -> tuple[str, str]:
    subject_match = re.search(r"(?im)^subject:\s*(.*)$", text or "")
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text or "", maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def extract_email_parts(raw_bytes: bytes) -> tuple[str, str, str]:
    fallback_text = raw_bytes.decode("utf-8", errors="ignore")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = str(msg.get("Subject", "") or "")
        sender = str(msg.get("From", "") or "")
        body_chunks: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_disposition() == "attachment":
                    continue

                content_type = part.get_content_type()
                try:
                    content = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    content = payload.decode(charset, errors="ignore")

                if not isinstance(content, str):
                    continue

                if content_type == "text/html":
                    content = strip_html(content)
                body_chunks.append(content)
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True) or b""
                charset = msg.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="ignore")

            if isinstance(content, str):
                if content_type == "text/html":
                    content = strip_html(content)
                body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if not body:
            _, body = fallback_subject_body(fallback_text)

        return subject, body, sender
    except Exception:
        subject, body = fallback_subject_body(fallback_text)
        return subject, body, ""


def clean_text(text: str) -> str:
    normalized = html.unescape(text or "").lower()
    normalized = re.sub(r"http[s]?://\S+|www\.\S+", " urltoken ", normalized)
    normalized = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", " emailtoken ", normalized)
    normalized = re.sub(r"[^a-z0-9\s]", " ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def extract_urls(text: str) -> list[str]:
    return re.findall(r"http[s]?://\S+|www\.\S+", text or "", flags=re.IGNORECASE)


def clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


def count_weighted_matches(text: str, weighted_terms: dict[str, float]) -> float:
    return sum(weight for term, weight in weighted_terms.items() if term in text)


def extract_sender_domain(sender: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender or "")
    return match.group(1).lower() if match else ""


def score_semantic_signals(subject: str, body: str, sender: str = "") -> dict:
    combined = f"{subject}\n{body}".strip().lower()
    urls = extract_urls(body)
    phishing_score = 0.0
    legitimate_score = 0.0

    for terms in PHISHING_SIGNAL_WEIGHTS.values():
        phishing_score += count_weighted_matches(combined, terms)
    for terms in LEGITIMATE_SIGNAL_WEIGHTS.values():
        legitimate_score += count_weighted_matches(combined, terms)

    cta_density = sum(
        1
        for phrase in ("click here", "view now", "open now", "review now", "sign in", "log in")
        if phrase in combined
    )
    phishing_score += min(0.18, cta_density * 0.06)

    sender_domain = extract_sender_domain(sender)
    sender_trust = 0.08 if any(sender_domain.endswith(domain) for domain in TRUSTED_SENDER_HINTS) else 0.0
    legitimate_score += sender_trust

    safe_url_bonus = 0.0
    for url in urls:
        hostname = urlparse(url if "://" in url else f"https://{url}").netloc.lower().replace("www.", "")
        if hostname.endswith(("google.com", "facebook.com", "coursera.org", "cisco.com", "netacad.com")):
            safe_url_bonus += 0.03
    legitimate_score += min(0.12, safe_url_bonus)

    return {
        "phishing_score": round(min(phishing_score, 1.0), 4),
        "legitimate_score": round(min(legitimate_score, 1.0), 4),
        "sender_domain": sender_domain,
        "url_count": len(urls),
    }


def blend_model_with_semantics(model_probability: float, semantic_signals: dict) -> float:
    semantic_delta = (
        semantic_signals["phishing_score"] * 0.55
        - semantic_signals["legitimate_score"] * 0.45
    )
    centered = (model_probability - 0.5) * 1.35 + semantic_delta
    blended_probability = 1.0 / (1.0 + math.exp(-centered * 2.4))
    return round(clamp(blended_probability), 4)


def predict_email_parts(subject: str, body: str, threshold: float | None = None, sender: str = "") -> dict:
    combined_text = f"{subject}\n{body}".strip()
    cleaned_text = clean_text(combined_text)
    if not cleaned_text:
        raise ValueError("Could not extract usable text from the email.")

    active_threshold = DEFAULT_THRESHOLD if threshold is None else float(threshold)
    features = VECTORIZER.transform([cleaned_text])

    if hasattr(CLASSIFIER, "predict_proba"):
        model_spam_probability = float(CLASSIFIER.predict_proba(features)[0][1])
    else:
        model_spam_probability = 1.0 if int(CLASSIFIER.predict(features)[0]) == 1 else 0.0

    semantic_signals = score_semantic_signals(subject, body, sender=sender)
    spam_probability = blend_model_with_semantics(model_spam_probability, semantic_signals)

    predicted_index = 1 if spam_probability >= active_threshold else 0
    predicted_label = str(LABEL_MAP.get(predicted_index, predicted_index)).lower()

    reasons = [
        "spam probability is above the decision threshold"
        if spam_probability >= active_threshold
        else "spam probability is below the decision threshold"
    ]

    urls = extract_urls(body)
    if urls:
        reasons.append(f"contains {len(urls)} URL(s)")

    if any(token in cleaned_text for token in ["verify", "account", "urgent"]):
        reasons.append("contains suspicious phishing-like language")

    return {
        "subject": subject,
        "body": body,
        "predicted_label": predicted_label,
        "spam_probability": spam_probability,
        "model_spam_probability": round(model_spam_probability, 4),
        "threshold": active_threshold,
        "urls": urls,
        "semantic_signals": semantic_signals,
        "reasons": reasons,
    }


def predict_email_bytes(raw_bytes: bytes, threshold: float | None = None) -> dict:
    subject, body, sender = extract_email_parts(raw_bytes)
    result = predict_email_parts(subject, body, threshold=threshold, sender=sender)
    result["sender"] = sender
    return result


def predict_email_file(file_path: str | Path, threshold: float | None = None) -> dict:
    path = Path(file_path)
    result = predict_email_bytes(path.read_bytes(), threshold=threshold)
    result["file_path"] = str(path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict whether an .eml email is spam or ham.")
    parser.add_argument("email_file", type=Path, help="Path to the .eml or raw email file")
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Optional decision threshold for spam probability",
    )
    args = parser.parse_args()

    if not args.email_file.is_file():
        raise FileNotFoundError(f"Email file not found: {args.email_file}")

    result = predict_email_file(args.email_file, threshold=args.threshold)

    print("=" * 60)
    print("EMAIL SPAM DETECTION RESULT")
    print("=" * 60)
    print(f"File:        {args.email_file}")
    print(f"Subject:     {result['subject'] if result['subject'] else '(no subject)'}")
    print(f"Threshold:   {result['threshold']:.2f}")
    print(f"Verdict:     {result['predicted_label'].upper()}")
    print(f"Confidence:  {result['spam_probability']:.4f}")

    print("\nReasons:")
    for reason in result["reasons"]:
        print(f"- {reason}")

    if result["urls"]:
        print("\nExtracted URLs:")
        for url in result["urls"][:10]:
            print(f"- {url}")

    print("\nPreview:")
    preview = f"{result['subject']}\n{result['body']}".strip()[:500].replace("\n", " ")
    print(preview if preview else "(empty)")
    print("=" * 60)


if __name__ == "__main__":
    main()
