import joblib
import pandas as pd
import pefile
import tempfile
from pathlib import Path

from backend.services.asset_paths import find_asset_dir

MODEL_DIR = find_asset_dir(Path(__file__), "FILE", "models")

lgbm = joblib.load(MODEL_DIR / "lightgbm_malware_model.pkl")
xgb = joblib.load(MODEL_DIR / "xgboost_malware_model.pkl")
scaler = joblib.load(MODEL_DIR / "feature_scaler.pkl")

FEATURES = [
    "Sections",
    "AvgEntropy",
    "MaxEntropy",
    "SuspiciousSections",
    "DLLs",
    "Imports",
    "HasSensitiveAPI",
    "ImageBase",
    "SizeOfImage",
    "HasVersionInfo",
]

SENSITIVE_APIS = {
    b"CreateRemoteThread",
    b"WriteProcessMemory",
    b"VirtualAllocEx",
    b"InternetOpen",
    b"HttpSendRequest",
    b"SetWindowsHookEx",
}


def classify_status(risk_score: float) -> str:
    if risk_score >= 70:
        return "threat"
    if risk_score >= 40:
        return "suspicious"
    return "safe"


def probability_confidence(probability: float) -> float:
    return round(max(probability, 1 - probability) * 100, 2)


def extract_features(raw: bytes, filename: str) -> dict:
    suffix = Path(filename).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
        handle.write(raw)
        temp_path = Path(handle.name)

    try:
        pe = pefile.PE(str(temp_path))
        sections = len(pe.sections)
        entropies = [section.get_entropy() for section in pe.sections]
        avg_entropy = sum(entropies) / sections if sections else 0.0
        max_entropy = max(entropies) if entropies else 0.0
        suspicious_sections = sum(
            1
            for section in pe.sections
            if (section.Characteristics & 0x80000000)
            and (section.Characteristics & 0x20000000)
        )
        dlls = 0
        imports = 0
        has_sensitive_api = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports += len(entry.imports)
                for imported in entry.imports:
                    if imported.name in SENSITIVE_APIS:
                        has_sensitive_api = 1
        has_version_info = 1 if hasattr(pe, "VS_FIXEDFILEINFO") else 0
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
        pe.close()
        return {
            "Sections": sections,
            "AvgEntropy": round(avg_entropy, 4),
            "MaxEntropy": round(max_entropy, 4),
            "SuspiciousSections": suspicious_sections,
            "DLLs": dlls,
            "Imports": imports,
            "HasSensitiveAPI": has_sensitive_api,
            "ImageBase": image_base,
            "SizeOfImage": size_of_image,
            "HasVersionInfo": has_version_info,
        }
    finally:
        temp_path.unlink(missing_ok=True)


def predict_file(filename: str, raw: bytes) -> dict:
    features = extract_features(raw, filename)
    frame = pd.DataFrame([features])[FEATURES]
    scaled = scaler.transform(frame)

    lgbm_prob = float(lgbm.predict_proba(scaled)[0][1]) if hasattr(lgbm, "predict_proba") else None
    xgb_prob = float(xgb.predict_proba(scaled)[0][1]) if hasattr(xgb, "predict_proba") else None

    if lgbm_prob is not None and xgb_prob is not None:
        avg_prob = (lgbm_prob + xgb_prob) / 2
        risk_score = round(avg_prob * 100, 2)
        confidence = probability_confidence(avg_prob)
        model_agreement = "high" if abs(lgbm_prob - xgb_prob) <= 0.15 else "mixed"
    else:
        lgbm_pred = int(lgbm.predict(scaled)[0])
        xgb_pred = int(xgb.predict(scaled)[0])
        avg_prob = None
        vote_ratio = (lgbm_pred + xgb_pred) / 2
        risk_score = round(vote_ratio * 100, 2)
        confidence = probability_confidence(vote_ratio)
        model_agreement = "high" if lgbm_pred == xgb_pred else "mixed"

    status = classify_status(risk_score)
    verdict = "MALWARE" if status == "threat" else ("SUSPICIOUS" if status == "suspicious" else "BENIGN")
    predicted_class = "malware" if (avg_prob is not None and avg_prob >= 0.5) or (avg_prob is None and risk_score >= 50) else "benign"
    decision_threshold = 70
    key_features = {
        "Sections": features["Sections"],
        "AvgEntropy": features["AvgEntropy"],
        "MaxEntropy": features["MaxEntropy"],
        "SuspiciousSections": features["SuspiciousSections"],
        "Imports": features["Imports"],
        "HasSensitiveAPI": bool(features["HasSensitiveAPI"]),
    }

    return {
        "detection_type": "file",
        "source_value": filename,
        "filename": filename,
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
