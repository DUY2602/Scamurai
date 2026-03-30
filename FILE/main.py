import os
import sys
import warnings

import joblib
import numpy as np

warnings.filterwarnings("ignore")

ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS_FOLDER = os.path.join(ROOT, "models")

sys.path.append(ROOT)
from utils.preprocess import extract_features


MODEL_SPECS = [
    ("LGBM", "lightgbm_malware_model.pkl", False),
    ("XGB", "xgboost_malware_model.pkl", False),
    ("KMeans", "kmeans_malware_model.pkl", True),
]


def _load_pickle(filename):
    path = os.path.join(MODELS_FOLDER, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required artifact: {path}")
    return joblib.load(path)


def load_artifacts():
    if not os.path.exists(MODELS_FOLDER):
        raise FileNotFoundError(f"Folder not found: {MODELS_FOLDER}")

    return {
        "models": {
            display_name: _load_pickle(filename)
            for display_name, filename, _ in MODEL_SPECS
        },
        "feature_scaler": _load_pickle("feature_scaler.pkl"),
    }


ARTIFACTS = load_artifacts()


def _prediction_to_label(prediction):
    return "MALWARE" if int(prediction) == 1 else "BENIGN"


def _format_confidence(model, model_input):
    if not hasattr(model, "predict_proba"):
        return "N/A"

    probabilities = model.predict_proba(model_input)[0]
    return f"{max(probabilities) * 100:.2f}%"


def _extract_feature_array(file_path):
    features = extract_features(file_path, label=None)
    if not features:
        raise ValueError("Cannot extract features (ensure the file type is executable)")

    # Drop MD5 and label, matching the notebook feature slice.
    X_raw = np.array([features[1:-1]], dtype=float)
    return features, X_raw


def predict_file(file_path):
    candidate_path = str(file_path or "").strip().strip('"').strip("'")
    if not candidate_path:
        raise ValueError("File path is empty")
    if not os.path.exists(candidate_path):
        raise FileNotFoundError(f"File not found: {candidate_path}")

    features, X_raw = _extract_feature_array(candidate_path)
    X_scaled = ARTIFACTS["feature_scaler"].transform(X_raw)

    predictions = {}
    for display_name, _, use_scaled_features in MODEL_SPECS:
        model = ARTIFACTS["models"][display_name]
        model_input = X_scaled if use_scaled_features else X_raw
        pred = model.predict(model_input)[0]
        predictions[display_name] = {
            "prediction": _prediction_to_label(pred),
            "confidence": _format_confidence(model, model_input),
        }

    return {
        "file_path": candidate_path,
        "features": features,
        "predictions": predictions,
    }


def print_feature_summary(file_path, features):
    print("\n" + "=" * 60)
    print(f"FILE: {os.path.basename(file_path)}")
    print("-" * 60)
    print(f"Sections: {features[1]}")
    print(f"Avg Entropy: {features[2]}")
    print(f"Max Entropy: {features[3]}")
    print(f"Suspicious Sections: {features[4]}")
    print(f"DLLs: {features[5]}")
    print(f"Imports: {features[6]}")
    print(f"Sensitive API: {'Yes' if features[7] == 1 else 'None'}")
    print(f"Image Base: {features[8]}")
    print(f"Size Image: {features[9]}")
    print(f"Has Version Info: {'Yes' if features[10] == 1 else 'None'}")
    print("=" * 60)


def print_prediction_table(predictions):
    print("\nTEST RESULT:")
    print("-" * 60)
    print(f"{'Model':<15} {'Prediction':<10} {'Confidence':<15}")
    print("-" * 60)

    for model_name, result in predictions.items():
        print(f"{model_name:<15} {result['prediction']:<10} {result['confidence']:<15}")

    print("-" * 60)


def main():
    print("=" * 60)
    print("MALWARE DETECTION - TEST ALL MODELS")
    print("=" * 60)

    try:
        file_path = input("\nPath to test file: ").strip()
    except EOFError:
        print("\nNo interactive input available. Exiting CLI.")
        return

    try:
        result = predict_file(file_path)
        print_feature_summary(result["file_path"], result["features"])
        print_prediction_table(result["predictions"])
    except Exception as exc:
        print(f"Error: {exc}")


def run_smoke_test():
    test_files = [
        ("benign", r"C:\Windows\System32\notepad.exe"),
        ("malware", os.path.join(ROOT, "test", "malware_sample.exe")),
    ]

    print("\n" + "=" * 60)
    print("SMOKE TEST")
    print("=" * 60)

    for sample_kind, sample_path in test_files:
        if not os.path.exists(sample_path):
            print(f"{sample_kind.upper():<8} {sample_path} -> SKIPPED (file not found)")
            continue

        try:
            result = predict_file(sample_path)
            print(f"{sample_kind.upper():<8} {sample_path}")
            for model_name, prediction in result["predictions"].items():
                print(f"  {model_name}: {prediction['prediction']}")
        except Exception as exc:
            print(f"{sample_kind.upper():<8} {sample_path} -> ERROR ({exc})")


if __name__ == "__main__":
    run_smoke_test()
    if sys.stdin.isatty():
        main()
