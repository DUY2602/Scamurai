import joblib
from pathlib import Path
from email import policy
from email.parser import BytesParser

ROOT_DIR    = Path(__file__).resolve().parents[3]
MODEL_DIR   = ROOT_DIR / "Email" / "models"
model       = joblib.load(MODEL_DIR / "best_model.pkl")
vectorizer  = joblib.load(MODEL_DIR / "vectorizer.pkl")
scaler      = joblib.load(MODEL_DIR / "scaler.pkl")

def clean_text(text: str) -> str:
    import re
    text = text.lower()
    text = re.sub(r"http\S+", " urltoken ", text)
    text = re.sub(r"\S+@\S+", " emailtoken ", text)
    text = re.sub(r"[^a-z0-9\s]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def build_features(subject: str, body: str, sender: str = ""):
    import numpy as np, scipy.sparse as sp
    combined = f"{subject}\n{body}"
    cleaned  = clean_text(combined)

    tfidf_vec = vectorizer.transform([cleaned])

    num_urls  = combined.lower().count("http")
    num_excl  = combined.count("!")
    upper_r   = sum(1 for c in combined if c.isupper()) / (len(combined)+1)
    url_ratio = num_urls / (len(combined.split())+1)
    has_greet = int(any(w in combined.lower() for w in ["dear","hello","hi "]))
    free_em   = int(any(d in sender.lower() for d in ["gmail","yahoo","hotmail"]))

    num_feat  = scaler.transform([[num_urls, len(combined), num_excl,
                                   upper_r, url_ratio, has_greet, free_em]])
    return sp.hstack([tfidf_vec, num_feat])

def predict_from_text(subject: str, body: str, sender: str = "") -> dict:
    features = build_features(subject, body, sender)
    prob = float(model.predict_proba(features)[0][1])
    verdict = "SPAM" if prob >= 0.5 else "HAM"
    return {
        "verdict":          verdict,
        "spam_probability": round(prob, 4),
        "is_spam":          verdict == "SPAM",
        "subject_preview":  subject[:100],
    }

def predict_from_file(filename: str, raw: bytes) -> dict:
    try:
        msg     = BytesParser(policy=policy.default).parsebytes(raw)
        subject = str(msg.get("Subject", "") or "")
        sender  = str(msg.get("From", "") or "")
        parts   = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    parts.append(part.get_content())
        else:
            parts.append(msg.get_content())
        body = "\n".join(parts)
    except Exception:
        subject, body, sender = "", raw.decode("utf-8", errors="ignore"), ""

    result = predict_from_text(subject, body, sender)
    result["filename"] = filename
    return result
