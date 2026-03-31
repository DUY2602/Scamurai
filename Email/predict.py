from __future__ import annotations

import html
import re
import shutil
import warnings
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")


ROOT_DIR = Path(__file__).resolve().parent
MODELS_DIR = ROOT_DIR / "models"
ARCHIVE_MODELS_DIR = MODELS_DIR / "archive"

LGB_MODEL_PATH = MODELS_DIR / "lgb_model.pkl"
XGB_MODEL_PATH = MODELS_DIR / "xgb_model.pkl"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"

REQUIRED_ROOT_ARTIFACTS = {
    "lgb_model": LGB_MODEL_PATH,
    "xgb_model": XGB_MODEL_PATH,
    "vectorizer": VECTORIZER_PATH,
    "scaler": SCALER_PATH,
    "label_encoder": LABEL_ENCODER_PATH,
}
ARCHIVE_SOURCE_ARTIFACTS = {
    "lgb_model": ARCHIVE_MODELS_DIR / "lgb_model.pkl",
    "xgb_model": ARCHIVE_MODELS_DIR / "xgb_model.pkl",
    "vectorizer": ARCHIVE_MODELS_DIR / "vectorizer.pkl",
    "scaler": ARCHIVE_MODELS_DIR / "scaler.pkl",
}

NUMERIC_FEATURES = [
    "num_urls",
    "email_length",
    "num_exclamation",
    "upper_case_ratio",
    "url_to_text_ratio",
    "has_generic_greeting",
    "is_free_email",
]
FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com"}
URL_TOKEN_REGEX = re.compile(
    r"(\[link\]|\[url\]|https?://\S+|www\.\S+|\b\w+\.(?:com|net|org|info|biz|xyz|tk)\b)",
    flags=re.IGNORECASE,
)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
MULTISPACE_REGEX = re.compile(r"\s+")
SUBJECT_REGEX = re.compile(r"(?im)^subject:\s*(.*)$")
FROM_REGEX = re.compile(r"(?im)^from:\s*(.*)$")

SPAM_PROMO_PHRASES = (
    "free iphone",
    "reply with your address",
    "claim your prize",
    "you have won",
    "congratulations",
    "selected",
    "offer expires tonight",
)
SHIPPING_TRUST_HINTS = ("fedex.com", "ups.com", "usps.com", "dhl.com")
SHIPPING_TRANSACTIONAL_HINTS = ("package", "shipped", "dispatched", "track", "order #")
PHISHING_HINTS = ("verify", "suspended", "urgent", "lose access", "paypal-secure-login.xyz")


def _ensure_root_model_artifacts() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    for artifact_name, target_path in REQUIRED_ROOT_ARTIFACTS.items():
        if artifact_name == "label_encoder":
            continue

        if target_path.is_file():
            continue

        source_path = ARCHIVE_SOURCE_ARTIFACTS[artifact_name]
        if not source_path.is_file():
            raise FileNotFoundError(f"Missing required artifact: {source_path}")
        shutil.copy2(source_path, target_path)

    if not LABEL_ENCODER_PATH.is_file():
        label_encoder = LabelEncoder()
        label_encoder.fit(["ham", "spam"])
        joblib.dump(label_encoder, LABEL_ENCODER_PATH)


def load_email_artifacts(verbose: bool = False) -> dict[str, Any]:
    _ensure_root_model_artifacts()

    artifacts = {
        "paths": dict(REQUIRED_ROOT_ARTIFACTS),
        "lgb_model": joblib.load(LGB_MODEL_PATH),
        "xgb_model": joblib.load(XGB_MODEL_PATH),
        "vectorizer": joblib.load(VECTORIZER_PATH),
        "scaler": joblib.load(SCALER_PATH),
        "label_encoder": joblib.load(LABEL_ENCODER_PATH),
    }

    if verbose:
        print("Live Email inference artifacts:")
        for key in ("lgb_model", "xgb_model", "vectorizer", "scaler", "label_encoder"):
            print(f"  {key}: {artifacts['paths'][key]} -> {type(artifacts[key]).__name__}")

    return artifacts


ARTIFACTS = load_email_artifacts()


def describe_loaded_artifacts() -> dict[str, dict[str, str]]:
    return {
        key: {
            "path": str(ARTIFACTS["paths"][key]),
            "type": type(ARTIFACTS[key]).__name__,
        }
        for key in ("lgb_model", "xgb_model", "vectorizer", "scaler", "label_encoder")
    }


def strip_html(html_text: str) -> str:
    return html.unescape(HTML_TAG_REGEX.sub(" ", html_text or ""))


def _fallback_email_parts(text: str) -> tuple[str, str, str]:
    subject_match = SUBJECT_REGEX.search(text or "")
    sender_match = FROM_REGEX.search(text or "")
    subject = subject_match.group(1).strip() if subject_match else ""
    sender = sender_match.group(1).strip() if sender_match else ""
    parts = re.split(r"\r?\n\r?\n", text or "", maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body, sender


def _decode_part_content(part: Any) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode(part.get_content_charset() or "utf-8", errors="ignore")
    except Exception:
        pass

    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="ignore")


def extract_email_parts(file_path: Path) -> tuple[str, str, str]:
    raw_bytes = file_path.read_bytes()

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = str(message.get("Subject", "") or "")
        sender = str(message.get("From", "") or "")
        body_chunks: list[str] = []

        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_disposition() == "attachment":
                    continue

                content_type = part.get_content_type()
                content = _decode_part_content(part)
                if content_type == "text/html":
                    content = strip_html(content)
                if content:
                    body_chunks.append(content)
        else:
            content_type = message.get_content_type()
            content = _decode_part_content(message)
            if content_type == "text/html":
                content = strip_html(content)
            if content:
                body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if body:
            return subject, body, sender

        fallback_subject, fallback_body, fallback_sender = _fallback_email_parts(
            raw_bytes.decode("utf-8", errors="ignore")
        )
        return subject or fallback_subject, fallback_body, sender or fallback_sender
    except Exception:
        return _fallback_email_parts(raw_bytes.decode("utf-8", errors="ignore"))


def _build_feature_frame(subject: str, body: str, sender: str = "") -> pd.DataFrame:
    safe_subject = str(subject or "")
    safe_body = str(body or "")
    safe_sender = str(sender or "")

    raw_text = f"From: {safe_sender}\nSubject: {safe_subject}\n\n{safe_body}"
    urls = URL_TOKEN_REGEX.findall(raw_text.lower())
    full_text = f"{safe_subject} {safe_body}".strip()
    clean_text = URL_TOKEN_REGEX.sub(" url ", full_text).lower()
    clean_text = MULTISPACE_REGEX.sub(" ", clean_text).strip()

    email_length = len(full_text) if full_text else 1
    upper_case_count = sum(1 for character in full_text if character.isupper())
    sender_domain = safe_sender.split("@")[-1].lower() if "@" in safe_sender else ""

    feature_row = {
        "num_urls": len(urls),
        "email_length": email_length,
        "num_exclamation": full_text.count("!"),
        "upper_case_ratio": round(upper_case_count / email_length, 4),
        "url_to_text_ratio": round(len(urls) / email_length, 6),
        "has_generic_greeting": int(
            bool(re.search(r"(dear|hi|hello)\s+(customer|user|winner|friend|student)", full_text.lower()))
        ),
        "is_free_email": int(sender_domain in FREE_EMAIL_DOMAINS),
        "full_clean_text": clean_text,
    }

    return pd.DataFrame([feature_row])


def _build_model_matrix(feature_frame: pd.DataFrame):
    tfidf = ARTIFACTS["vectorizer"].transform(feature_frame["full_clean_text"])
    numeric = ARTIFACTS["scaler"].transform(feature_frame[NUMERIC_FEATURES])
    return hstack([tfidf, csr_matrix(numeric)]).tocsr()


def _probabilities_in_label_order(model, matrix) -> np.ndarray:
    raw_probabilities = np.asarray(model.predict_proba(matrix)[0], dtype=float)
    ordered = np.zeros(len(ARTIFACTS["label_encoder"].classes_), dtype=float)
    model_classes = list(getattr(model, "classes_", range(len(raw_probabilities))))

    for index, encoded_class in enumerate(model_classes):
        ordered[int(encoded_class)] = raw_probabilities[index]

    return ordered


def _blend_probabilities(
    base_probabilities: np.ndarray,
    target_probabilities: np.ndarray,
    weight: float,
) -> np.ndarray:
    clamped_weight = min(0.95, max(0.0, float(weight)))
    blended = ((1.0 - clamped_weight) * base_probabilities) + (clamped_weight * target_probabilities)
    total = float(blended.sum())
    if total <= 0:
        return target_probabilities
    return blended / total


def _apply_rule_adjustments(subject: str, body: str, final_probabilities: np.ndarray) -> tuple[np.ndarray, str | None]:
    lowered_text = f"{subject} {body}".lower()

    if any(phrase in lowered_text for phrase in SPAM_PROMO_PHRASES):
        boosted = _blend_probabilities(final_probabilities, np.array([0.02, 0.98], dtype=float), weight=0.65)
        return boosted, "Obvious giveaway-spam heuristic increased spam risk"

    has_shipping_host = any(host in lowered_text for host in SHIPPING_TRUST_HINTS)
    has_shipping_context = any(token in lowered_text for token in SHIPPING_TRANSACTIONAL_HINTS)
    has_phishing_context = any(token in lowered_text for token in PHISHING_HINTS)
    if has_shipping_host and has_shipping_context and not has_phishing_context:
        reduced = _blend_probabilities(final_probabilities, np.array([0.98, 0.02], dtype=float), weight=0.6)
        return reduced, "Transactional shipping heuristic reduced spam risk"

    return final_probabilities, None


def _predict_email(subject: str, body: str, sender: str = "") -> dict[str, Any]:
    feature_frame = _build_feature_frame(subject, body, sender=sender)
    model_matrix = _build_model_matrix(feature_frame)

    lgb_prob = _probabilities_in_label_order(ARTIFACTS["lgb_model"], model_matrix)
    xgb_prob = _probabilities_in_label_order(ARTIFACTS["xgb_model"], model_matrix)
    final_prob = (lgb_prob + xgb_prob) / 2.0
    final_prob, override_reason = _apply_rule_adjustments(subject, body, final_prob)

    label_encoder = ARTIFACTS["label_encoder"]
    pred_idx = int(np.argmax(final_prob))
    label = str(label_encoder.inverse_transform([pred_idx])[0]).lower()
    spam_idx = int(label_encoder.transform(["spam"])[0])

    indicators = [
        f"Loaded LGBM model: {type(ARTIFACTS['lgb_model']).__name__}",
        f"Loaded XGBoost model: {type(ARTIFACTS['xgb_model']).__name__}",
        f"LGBM spam probability: {lgb_prob[spam_idx]:.4f}",
        f"XGBoost spam probability: {xgb_prob[spam_idx]:.4f}",
    ]
    if override_reason is not None:
        indicators.insert(0, override_reason)

    return {
        "label": label,
        "confidence": float(final_prob[pred_idx]),
        "spam_probability": float(final_prob[spam_idx]),
        "risk_score": float(final_prob[spam_idx]),
        "indicators": indicators,
    }


def predict_from_parts(subject: str, body: str, sender: str = "") -> dict[str, Any]:
    return _predict_email(subject or "", body or "", sender=sender or "")


def predict_from_file(eml_path: str) -> dict[str, Any]:
    file_path = Path(str(eml_path or "")).expanduser().resolve()
    if not file_path.is_file():
        raise FileNotFoundError(f"Email file not found: {file_path}")

    subject, body, sender = extract_email_parts(file_path)
    return _predict_email(subject, body, sender=sender)


def predict_from_text(subject: str, body: str) -> dict[str, Any]:
    return predict_from_parts(subject or "", body or "", sender="")


if __name__ == "__main__":
    load_email_artifacts(verbose=True)
    result = predict_from_text(
        subject="Urgent: Verify your account now",
        body="Click here to claim your reward immediately",
    )
    print(result)
