import os
import ipaddress
import sys
import warnings

import joblib
import pandas as pd

warnings.filterwarnings("ignore")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS_FOLDER = os.path.join(ROOT, "models")

sys.path.append(ROOT)
from utils.preprocess import apply_domain_stat_features, extract_features


URL_HARMFUL_LABELS = {"malicious", "harm", "phishing", "defacement", "malware", "dangerous"}
TRUSTED_HOST_SUFFIXES = {
    "google.com",
    "github.com",
    "youtube.com",
    "stackoverflow.com",
    "gmail.com",
    "microsoft.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
    "outlook.com",
}
REDIRECT_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "lnkd.in",
    "cutt.ly",
    "rb.gy",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "goo.gl",
    "tiny.cc",
}
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "work", "gq", "tk", "cf", "ml", "ga", "ru"}
GIVEAWAY_KEYWORDS = {"free", "winner", "iphone", "prize", "claim", "gift", "bonus", "promo", "selected", "won"}
TRUSTED_BRAND_KEYWORDS = {domain.split(".")[0] for domain in TRUSTED_HOST_SUFFIXES}


def _load_pickle(filename, default=None):
    path = os.path.join(MODELS_FOLDER, filename)
    if not os.path.exists(path):
        return default
    return joblib.load(path)


def load_inference_artifacts():
    if not os.path.exists(MODELS_FOLDER):
        raise FileNotFoundError(f"Folder not found: {MODELS_FOLDER}")

    model_files = sorted(f for f in os.listdir(MODELS_FOLDER) if f.endswith("_model.pkl"))
    if not model_files:
        raise FileNotFoundError(f"No model files found in: {MODELS_FOLDER}")

    domain_stats_artifact = _load_pickle("domain_stats.pkl", {})

    return {
        "models": {
            model_file.replace("_model.pkl", ""): joblib.load(os.path.join(MODELS_FOLDER, model_file))
            for model_file in model_files
        },
        "feature_names_lgbm": _load_pickle("feature_names.pkl"),
        "feature_names_xgb": _load_pickle("feature_names_xgb.pkl"),
        "scaler_xgb": _load_pickle("scaler_xgb.pkl"),
        "label_encoder": _load_pickle("label_encoder.pkl"),
        "registered_domain_stats": domain_stats_artifact.get("registered_domain_stats", {}),
        "global_benign_rate": float(domain_stats_artifact.get("global_benign_rate", 0.5)),
    }


ARTIFACTS = load_inference_artifacts()


def _prepare_feature_view(feature_row: pd.DataFrame, feature_names):
    if not feature_names:
        numeric_columns = feature_row.select_dtypes(include=["number", "bool"]).columns.tolist()
        return feature_row[numeric_columns].copy()

    missing_features = [feature for feature in feature_names if feature not in feature_row.columns]
    if missing_features:
        raise KeyError(f"Missing expected features: {missing_features}")

    return feature_row[feature_names].copy()


def _decode_prediction(prediction):
    label_encoder = ARTIFACTS["label_encoder"]
    if label_encoder is not None:
        return label_encoder.inverse_transform([int(prediction)])[0]
    return "harm" if int(prediction) == 1 else "benign"


def _normalize_prediction_label(label: str) -> str:
    return "harm" if str(label).strip().lower() in URL_HARMFUL_LABELS else "benign"


def _domain_matches_suffix(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def _domain_matches_any_suffix(domain: str, suffixes: set[str]) -> bool:
    return any(_domain_matches_suffix(domain, suffix) for suffix in suffixes)


def _get_probabilities(model, model_input):
    if not hasattr(model, "predict_proba"):
        return None
    return model.predict_proba(model_input)[0]


def _extract_harm_probability(model, model_input):
    probabilities = _get_probabilities(model, model_input)
    if probabilities is None:
        return None, None

    model_classes = list(getattr(model, "classes_", []))
    label_encoder = ARTIFACTS["label_encoder"]
    harm_index = None

    if label_encoder is not None and model_classes:
        for idx, encoded_class in enumerate(model_classes):
            try:
                decoded_label = label_encoder.inverse_transform([int(encoded_class)])[0]
            except Exception:
                decoded_label = None
            if decoded_label is not None and _normalize_prediction_label(decoded_label) == "harm":
                harm_index = idx
                break

    if harm_index is None and len(probabilities) >= 2:
        harm_index = 1

    if harm_index is None:
        return probabilities, None

    return probabilities, float(probabilities[harm_index])


def _apply_probability_adjustment(base_probability: float | None, delta: float) -> float | None:
    if base_probability is None:
        return None
    return float(min(0.99, max(0.01, base_probability + delta)))


def _url_risk_adjustment(url: str, feature_row: pd.DataFrame):
    row = feature_row.iloc[0]
    host = str(row.get("hostname", "") or "").strip().lower()
    registered_domain = str(row.get("registered_domain", "") or "").strip().lower()
    lowered_url = str(url or "").strip().lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    suspicious_tld = tld in SUSPICIOUS_TLDS or int(row.get("is_trash_tld", 0)) == 1
    has_ip = int(row.get("has_raw_ip", row.get("has_ip", 0))) == 1
    is_https = int(row.get("is_https", 0)) == 1
    keyword_count = int(row.get("keyword_count", 0))
    dash_count = int(row.get("dash_count", 0))
    subdomain_count = int(row.get("subdomain_count", 0))
    query_param_count = int(row.get("query_param_count", 0))
    has_suspicious_file_ext = int(row.get("has_suspicious_file_ext", 0)) == 1
    has_clean_resource_shape = (
        is_https
        and (
            int(row.get("has_single_resource_id_path", 0)) == 1
            or int(row.get("has_mixed_clean_path", 0)) == 1
        )
    )
    has_clean_academic_shape = (
        is_https
        and int(row.get("is_academic_domain", 0)) == 1
        and int(row.get("path_depth", 0)) == 0
        and int(row.get("query_len", 0)) == 0
    )

    is_trusted_host = bool(
        host
        and (
            _domain_matches_any_suffix(host, TRUSTED_HOST_SUFFIXES)
            or host.endswith((".gov", ".mil", ".gov.vn", ".edu", ".edu.vn"))
        )
    )
    brand_hit = any(keyword in lowered_url for keyword in TRUSTED_BRAND_KEYWORDS)
    brand_mismatch = brand_hit and not is_trusted_host
    giveaway_hit = any(keyword in lowered_url for keyword in GIVEAWAY_KEYWORDS)
    is_shortener = registered_domain in REDIRECT_SHORTENER_DOMAINS
    notes: list[str] = []
    risk_delta = 0.0
    has_clean_structure = (
        not suspicious_tld
        and not has_ip
        and keyword_count == 0
        and subdomain_count <= 2
        and query_param_count <= 2
        and not has_suspicious_file_ext
    )

    if has_ip:
        try:
            host_ip = ipaddress.ip_address(host)
            risk_delta += 0.14 if (host_ip.is_private or host_ip.is_loopback or host_ip.is_reserved) else 0.2
        except ValueError:
            risk_delta += 0.18
        notes.append("Raw-IP hostname increased risk")
    if is_shortener and not is_https:
        risk_delta += 0.18
        notes.append("Non-HTTPS shortener increased risk")
    if suspicious_tld and brand_mismatch:
        risk_delta += 0.28
        notes.append("Brand mismatch with suspicious TLD increased risk")
    elif brand_mismatch and (keyword_count >= 1 or dash_count >= 1 or subdomain_count >= 2):
        risk_delta += 0.2
        notes.append("Brand mismatch increased risk")
    if suspicious_tld and giveaway_hit:
        risk_delta += 0.16
        notes.append("Giveaway wording with suspicious TLD increased risk")
    if is_trusted_host and has_clean_structure:
        risk_delta -= 0.32
        notes.append("Trusted clean-host reduced risk")
    if has_clean_structure and has_clean_resource_shape:
        risk_delta -= 0.08
        notes.append("Clean HTTPS path structure reduced risk")
    if has_clean_structure and has_clean_academic_shape:
        risk_delta -= 0.08
        notes.append("Clean academic HTTPS structure reduced risk")

    risk_delta = max(-0.4, min(0.4, risk_delta))
    return risk_delta, "; ".join(notes) if notes else None


def _confidence_for_label(label: str, harm_probability: float | None, fallback_confidence: float | None):
    if harm_probability is None:
        return fallback_confidence

    normalized_label = _normalize_prediction_label(label)
    probability = harm_probability if normalized_label == "harm" else 1.0 - harm_probability
    return float(max(probability, 0.0))


def build_feature_row(url: str):
    features_dict = extract_features(url)
    feature_row = pd.DataFrame([features_dict])
    feature_row = apply_domain_stat_features(
        feature_row,
        registered_domain_stats=ARTIFACTS["registered_domain_stats"],
        global_benign_rate=ARTIFACTS["global_benign_rate"],
    )
    return features_dict, feature_row


def predict_url(url: str):
    candidate_url = str(url or "").strip()
    if not candidate_url:
        raise ValueError("URL is empty")

    _, feature_row = build_feature_row(candidate_url)
    risk_delta, override_reason = _url_risk_adjustment(candidate_url, feature_row)

    lgbm_features = _prepare_feature_view(feature_row, ARTIFACTS["feature_names_lgbm"])
    xgb_features = _prepare_feature_view(
        feature_row,
        ARTIFACTS["feature_names_xgb"] or ARTIFACTS["feature_names_lgbm"],
    )

    scaler_xgb = ARTIFACTS["scaler_xgb"]
    xgb_features_scaled = scaler_xgb.transform(xgb_features) if scaler_xgb is not None else xgb_features

    results = {}
    for model_name, model in ARTIFACTS["models"].items():
        if "xgb" in model_name.lower():
            model_input = xgb_features_scaled
        else:
            model_input = lgbm_features

        prediction = model.predict(model_input)[0]
        raw_label = _decode_prediction(prediction)
        probabilities, harm_probability = _extract_harm_probability(model, model_input)
        raw_confidence = float(max(probabilities)) if probabilities is not None else None
        adjusted_harm_probability = _apply_probability_adjustment(harm_probability, risk_delta)

        if adjusted_harm_probability is not None:
            final_label = "harm" if adjusted_harm_probability >= 0.5 else "benign"
            final_confidence = adjusted_harm_probability if final_label == "harm" else 1.0 - adjusted_harm_probability
        else:
            final_label = raw_label
            final_confidence = _confidence_for_label(final_label, harm_probability, raw_confidence)

        results[model_name] = {
            "prediction": final_label,
            "confidence": f"{final_confidence * 100:.2f}%" if final_confidence is not None else "N/A",
            "raw_prediction": raw_label,
            "raw_confidence": f"{raw_confidence * 100:.2f}%" if raw_confidence is not None else "N/A",
            "harm_probability": f"{harm_probability * 100:.2f}%" if harm_probability is not None else "N/A",
            "adjusted_harm_probability": (
                f"{adjusted_harm_probability * 100:.2f}%"
                if adjusted_harm_probability is not None
                else "N/A"
            ),
            "override_reason": override_reason,
        }

    return results


def print_prediction_table(url: str, prediction_results):
    print("=" * 60)
    print("URL MALWARE DETECTION - TEST ALL MODELS")
    print("=" * 60)
    print(f"URL: {url}")
    print("-" * 60)
    print(f"{'Model':<15} {'Prediction':<15} {'Confidence':<15}")
    print("-" * 60)

    for model_name, result in prediction_results.items():
        print(f"{model_name:<15} {result['prediction']:<15} {result['confidence']:<15}")

    print("-" * 60)


def run_cli():
    url = input("\nInput URL to test: ").strip()
    if not url:
        print("Error occurred: URL is empty")
        return

    try:
        prediction_results = predict_url(url)
        print_prediction_table(url, prediction_results)
    except Exception as exc:
        print(f"Error: {exc}")
        raise


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://paypal-secure-login.xyz/verify?token=abc123",
    ]
    for u in test_urls:
        result = predict_url(u)
        print(u, "→", result)
