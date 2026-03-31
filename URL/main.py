import os
import sys
import warnings

import joblib
import pandas as pd

warnings.filterwarnings("ignore")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.preprocess import extract_features


def load_feature_names(models_folder):
    feature_names_path = os.path.join(models_folder, "feature_names.pkl")
    feature_names_xgb_path = os.path.join(models_folder, "feature_names_xgb.pkl")

    if os.path.exists(feature_names_path):
        feature_names = joblib.load(feature_names_path)
    else:
        feature_names = None

    if os.path.exists(feature_names_xgb_path):
        feature_names_xgb = joblib.load(feature_names_xgb_path)
    else:
        feature_names_xgb = feature_names

    return feature_names, feature_names_xgb


def load_scalers(models_folder):
    scaler_path = os.path.join(models_folder, "scaler.pkl")
    scaler_xgb_path = os.path.join(models_folder, "scaler_xgb.pkl")

    scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
    scaler_xgb = joblib.load(scaler_xgb_path) if os.path.exists(scaler_xgb_path) else scaler
    return scaler, scaler_xgb


def main():
    print("=" * 60)
    print("URL MALWARE DETECTION - TEST ALL MODELS")
    print("=" * 60)

    url = input("\nInput URL to test: ").strip()
    if not url:
        print("Error: URL is empty")
        return

    models_folder = "URL/models"
    if not os.path.exists(models_folder):
        print("Folder 'URL/models' not found")
        return

    model_files = [file_name for file_name in os.listdir(models_folder) if file_name.endswith("_model.pkl")]
    if not model_files:
        print("Cannot find any model files in 'URL/models' folder")
        return

    print(f"\nFound {len(model_files)} models:")
    for model_file in model_files:
        print(f"  - {model_file}")

    try:
        print("\nExtracting features...")
        features_dict = extract_features(url)
        feature_names, feature_names_xgb = load_feature_names(models_folder)
        if not feature_names:
            feature_names = list(features_dict.keys())
        if not feature_names_xgb:
            feature_names_xgb = feature_names

        scaler, scaler_xgb = load_scalers(models_folder)

        encoder_path = os.path.join(models_folder, "label_encoder.pkl")
        label_encoder = joblib.load(encoder_path) if os.path.exists(encoder_path) else None

        print("\n" + "=" * 60)
        print(f"URL: {url}")
        print("-" * 60)
        for key, value in features_dict.items():
            if isinstance(value, float):
                print(f"{key}: {value:.3f}")
            else:
                print(f"{key}: {value}")
        print("=" * 60)

        print("\nPREDICTION RESULTS:")
        print("-" * 70)
        print(f"{'Model':<15} {'Prediction':<15} {'Confidence':<15}")
        print("-" * 70)

        for model_file in model_files:
            model_path = os.path.join(models_folder, model_file)
            model_name = model_file.replace("_model.pkl", "")
            model = joblib.load(model_path)

            model_feature_names = feature_names_xgb if model_name == "xgb" else feature_names
            model_scaler = scaler_xgb if model_name == "xgb" else scaler
            ordered_frame = pd.DataFrame([features_dict])[model_feature_names]
            if model_scaler is not None:
                model_input = pd.DataFrame(model_scaler.transform(ordered_frame), columns=model_feature_names)
            else:
                model_input = ordered_frame

            pred = model.predict(model_input)[0]
            if label_encoder is not None:
                result = label_encoder.inverse_transform([pred])[0]
            else:
                result = "MALICIOUS" if pred == 1 else "BENIGN"

            confidence = ""
            if hasattr(model, "predict_proba"):
                prob = model.predict_proba(model_input)[0]
                confidence = f"{max(prob) * 100:.2f}%"

            print(f"{model_name:<15} {result:<15} {confidence:<15}")

        print("-" * 70)

    except Exception as exc:
        print(f"Error: {exc}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
