import joblib
import pandas as pd
from pathlib import Path

from backend.services.asset_paths import find_asset_dir

MODEL_DIR = find_asset_dir(Path(__file__), "URL", "models")

lgbm = joblib.load(MODEL_DIR / "lgbm_model.pkl")
xgb = joblib.load(MODEL_DIR / "xgb_model.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
feature_names = joblib.load(MODEL_DIR / "feature_names.pkl")


def classify_status(risk_score: float) -> str:
    if risk_score >= 70:
        return "threat"
    if risk_score >= 40:
        return "suspicious"
    return "safe"


def probability_confidence(probability: float) -> float:
    return round(max(probability, 1 - probability) * 100, 2)


def extract_features(url: str) -> dict:
    from urllib.parse import urlparse
    import math
    import re

    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.netloc.replace("www.", "")
    path = parsed.path or ""
    query = parsed.query or ""
    full = f"{hostname}{path}"

    def entropy(value: str) -> float:
        if not value:
            return 0.0
        probs = [value.count(char) / len(value) for char in set(value)]
        return -sum(prob * math.log2(prob) for prob in probs)

    keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "banking",
        "signin",
        "confirm",
        "bank",
        "password",
        "reset",
    ]
    trash_tlds = (".tk", ".xyz", ".cc", ".top", ".pw", ".online", ".site", ".biz")
    popular_tlds = (".com", ".net", ".org", ".co", ".edu", ".gov")
    brands = ["google", "paypal", "apple", "microsoft", "amazon", "bank", "secure"]

    host_parts = [part for part in hostname.split(".") if part]
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""

    return {
        "url_len": len(full),
        "hostname_len": len(hostname),
        "dot_count": full.count("."),
        "dash_count": hostname.count("-"),
        "digit_ratio": len(re.findall(r"\d", full)) / (len(full) + 1),
        "entropy": round(entropy(full), 6),
        "is_trash_tld": int(hostname.endswith(trash_tlds)),
        "is_popular_tld": int(any(hostname.endswith(tld) for tld in popular_tlds)),
        "has_ip": int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname))),
        "is_exec": int(bool(re.search(r"\.(exe|apk|msi|zip)$", path))),
        "keyword_count": sum(1 for keyword in keywords if keyword in full),
        "subdomain_count": len(host_parts) - 2 if len(host_parts) > 2 else 0,
        "special_ratio": sum(full.count(char) for char in "-._@?&=") / (len(full) + 1),
        "has_number_in_host": int(any(char.isdigit() for char in hostname)),
        "has_at_symbol": int("@" in url),
        "path_depth": path.count("/"),
        "has_redirect": int("//" in url.split("://", 1)[-1]),
        "brand_in_subdomain": int(any(brand in subdomain for brand in brands)),
        "tld_in_path": int(any(marker in path for marker in (".com", ".net", ".org", ".io"))),
        "query_param_count": len([part for part in query.split("&") if part]),
        "has_hex_encoding": int("%" in url),
    }


def predict_url(url: str) -> dict:
    features = extract_features(url)
    frame = pd.DataFrame([features])[feature_names]
    scaled = scaler.transform(frame)

    lgbm_prob = float(lgbm.predict_proba(scaled)[0][1])
    xgb_prob = float(xgb.predict_proba(scaled)[0][1])
    avg_prob = (lgbm_prob + xgb_prob) / 2

    risk_score = round(avg_prob * 100, 2)
    confidence = probability_confidence(avg_prob)
    status = classify_status(risk_score)
    verdict = "MALICIOUS" if status == "threat" else ("SUSPICIOUS" if status == "suspicious" else "BENIGN")
    predicted_class = "malicious" if avg_prob >= 0.5 else "benign"
    decision_threshold = 70
    model_agreement = "high" if abs(lgbm_prob - xgb_prob) <= 0.15 else "mixed"
    key_features = {
        "keyword_count": features["keyword_count"],
        "entropy": features["entropy"],
        "has_ip": bool(features["has_ip"]),
        "is_trash_tld": bool(features["is_trash_tld"]),
        "subdomain_count": features["subdomain_count"],
        "path_depth": features["path_depth"],
    }

    return {
        "detection_type": "url",
        "source_value": url,
        "url": url,
        "status": status,
        "verdict": verdict,
        "predicted_class": predicted_class,
        "decision_threshold": decision_threshold,
        "model_agreement": model_agreement,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_malicious": status == "threat",
        "is_suspicious": status == "suspicious",
        "key_features": key_features,
    }
