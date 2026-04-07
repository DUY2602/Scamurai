import joblib
import math
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from backend.config.model_metadata_registry import get_model_metadata
from backend.config.threshold_registry import get_threshold_config
from backend.services.asset_paths import find_asset_dir

MODEL_DIR = find_asset_dir(Path(__file__), "URL", "models")


def load_xgboost_model(model_dir: Path):
    """Load XGBoost model, preferring .ubj format with .pkl fallback."""
    ubj_path = model_dir / "xgb_model.ubj"
    pkl_path = model_dir / "xgb_model.pkl"
    
    if ubj_path.exists():
        try:
            from xgboost import Booster
            return Booster(model_file=str(ubj_path))
        except Exception as e:
            print(f"Warning: Failed to load .ubj model, falling back to .pkl. Error: {e}")
    
    if pkl_path.exists():
        return joblib.load(pkl_path)
    
    raise FileNotFoundError(f"No XGBoost model found at {ubj_path} or {pkl_path}")


lgbm = joblib.load(MODEL_DIR / "lgbm_model.pkl")
xgb = load_xgboost_model(MODEL_DIR)
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
feature_names = joblib.load(MODEL_DIR / "feature_names.pkl")

# Load from centralized threshold registry
THRESHOLD_CONFIG = get_threshold_config("url")
MODEL_METADATA = get_model_metadata("url")


def probability_confidence(probability: float) -> float:
    return round(max(probability, 1 - probability) * 100, 2)


def normalize_risk_score(probability_percent: float) -> float:
    return int(max(0, min(100, math.ceil(probability_percent))))


def normalize_url_for_detection(url: str) -> str:
    normalized = str(url or "").strip().lower().replace("[", "").replace("]", "")
    address = normalized if "://" in normalized else f"http://{normalized}"

    try:
        parsed = urlparse(address)
    except Exception:
        parsed = urlparse("http://error-url.com")

    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = hostname
    if port and not (
        (parsed.scheme == "http" and port == 80)
        or (parsed.scheme == "https" and port == 443)
    ):
        netloc = f"{hostname}:{port}"

    path = parsed.path or ""
    if path == "/":
        path = ""

    return urlunparse((
        parsed.scheme or "http",
        netloc,
        path,
        "",
        parsed.query or "",
        "",
    ))


def extract_features(url: str) -> dict:
    import math
    import re

    canonical_url = normalize_url_for_detection(url)
    parsed = urlparse(canonical_url)
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
        "has_at_symbol": int("@" in canonical_url),
        "path_depth": path.count("/"),
        "has_redirect": int("//" in canonical_url.split("://", 1)[-1]),
        "brand_in_subdomain": int(any(brand in subdomain for brand in brands)),
        "tld_in_path": int(any(marker in path for marker in (".com", ".net", ".org", ".io"))),
        "query_param_count": len([part for part in query.split("&") if part]),
        "has_hex_encoding": int("%" in canonical_url),
    }


def _build_clean_homepage_result(url: str, normalized_url: str, features: dict) -> dict | None:
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    host_parts = [part for part in hostname.split(".") if part]
    is_clean_homepage = (
        len(host_parts) == 2
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
        and bool(hostname)
        and bool(host_parts[-1])
        and len(host_parts[-1]) >= 2
        and features["is_popular_tld"] == 1
        and features["is_trash_tld"] == 0
        and features["has_ip"] == 0
        and features["is_exec"] == 0
        and features["keyword_count"] == 0
        and features["subdomain_count"] == 0
        and features["has_number_in_host"] == 0
        and features["has_at_symbol"] == 0
        and features["path_depth"] == 0
        and features["has_redirect"] == 0
        and features["brand_in_subdomain"] == 0
        and features["tld_in_path"] == 0
        and features["query_param_count"] == 0
        and features["has_hex_encoding"] == 0
        and features["dash_count"] <= 1
        and features["entropy"] <= 3.9
    )

    if not is_clean_homepage:
        return None

    return {
        "detection_type": "url",
        "source_value": url,
        "url": url,
        "status": "safe",
        "verdict": "BENIGN",
        "predicted_class": "benign",
        "decision_threshold": THRESHOLD_CONFIG.threat_threshold,
        "decision_threshold_suspicious": THRESHOLD_CONFIG.suspicious_threshold,
        "model_agreement": "heuristic_override",
        "risk_score": 5,
        "confidence": 99.0,
        "is_malicious": False,
        "is_suspicious": False,
        "key_features": {
            "clean_homepage_override": True,
            "hostname": hostname,
            "normalized_url": normalized_url,
        },
        "model_info": {
            "model_version": MODEL_METADATA.model_version,
            "threshold_version": MODEL_METADATA.threshold_version,
            "lgbm_prob": None,
            "xgb_prob": None,
            "avg_prob": 0.0,
        },
    }


def predict_url(url: str) -> dict:
    normalized_url = normalize_url_for_detection(url)
    features = extract_features(url)
    clean_homepage_result = _build_clean_homepage_result(url, normalized_url, features)
    if clean_homepage_result is not None:
        return clean_homepage_result

    frame = pd.DataFrame([features])[feature_names]
    scaled = pd.DataFrame(
        scaler.transform(frame),
        columns=feature_names,
        index=frame.index,
    )

    lgbm_prob = float(lgbm.predict_proba(scaled)[0][1])
    xgb_prob = float(xgb.predict_proba(scaled)[0][1])
    avg_prob = (lgbm_prob + xgb_prob) / 2

    risk_score = normalize_risk_score(avg_prob * 100)
    confidence = probability_confidence(avg_prob)
    status = THRESHOLD_CONFIG.classify_status(risk_score)
    verdict = "MALICIOUS" if status == "threat" else ("SUSPICIOUS" if status == "suspicious" else "BENIGN")
    predicted_class = "malicious" if avg_prob >= 0.5 else "benign"
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
        "decision_threshold": THRESHOLD_CONFIG.threat_threshold,
        "decision_threshold_suspicious": THRESHOLD_CONFIG.suspicious_threshold,
        "model_agreement": model_agreement,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_malicious": status == "threat",
        "is_suspicious": status == "suspicious",
        "key_features": key_features,
        "model_info": {
            "model_version": MODEL_METADATA.model_version,
            "threshold_version": MODEL_METADATA.threshold_version,
            "lgbm_prob": round(lgbm_prob, 4),
            "xgb_prob": round(xgb_prob, 4),
            "avg_prob": round(avg_prob, 4),
        },
    }
