import os
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


def _format_confidence(model, model_input):
    if not hasattr(model, "predict_proba"):
        return None

    probabilities = model.predict_proba(model_input)[0]
    return float(max(probabilities))


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
        confidence = _format_confidence(model, model_input)

        results[model_name] = {
            "prediction": _decode_prediction(prediction),
            "confidence": f"{confidence * 100:.2f}%" if confidence is not None else "N/A",
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
