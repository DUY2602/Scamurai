import hashlib
import joblib
import math
import os
import pandas as pd
import pefile
from pathlib import Path
from typing import Any

from backend.config.model_metadata_registry import get_model_metadata
from backend.config.threshold_registry import get_threshold_config
from backend.services.asset_paths import find_asset_dir

MODEL_DIR = find_asset_dir(Path(__file__), "FILE", "models")


def load_xgboost_model(model_dir: Path):
    """Load XGBoost model, preferring .ubj format with .pkl fallback."""
    ubj_path = model_dir / "xgboost_malware_model.ubj"
    pkl_path = model_dir / "xgboost_malware_model.pkl"
    
    if ubj_path.exists():
        try:
            from xgboost import Booster
            return Booster(model_file=str(ubj_path))
        except Exception as e:
            print(f"Warning: Failed to load .ubj model, falling back to .pkl. Error: {e}")
    
    if pkl_path.exists():
        return joblib.load(pkl_path)
    
    raise FileNotFoundError(f"No XGBoost model found at {ubj_path} or {pkl_path}")


lgbm = joblib.load(MODEL_DIR / "lightgbm_malware_model.pkl")
xgb = load_xgboost_model(MODEL_DIR)
scaler = joblib.load(MODEL_DIR / "feature_scaler.pkl")

# Load thresholds from centralized registry
THRESHOLD_CONFIG = get_threshold_config("file")
MODEL_METADATA = get_model_metadata("file")

# Known clean system files whitelist
KNOWN_CLEAN_SYSTEM_FILES = ("notepad.exe", "calc.exe", "cmd.exe", "mspaint.exe", "taskmgr.exe")

FEATURES = [
    # v1 baseline features (10)
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
    # v2 new features (6)
    "is_packed",
    "import_category_score",
    "has_tls",
    "export_table_size",
    "resource_entropy",
    "api_category_score",
]

SENSITIVE_APIS = {
    b"CreateRemoteThread",
    b"WriteProcessMemory",
    b"VirtualAllocEx",
    b"LoadLibraryA",
    b"LoadLibraryW",
    b"GetProcAddress",
    b"CreateProcessA",
    b"CreateProcessW",
    b"WinExec",
    b"ShellExecuteA",
    b"ShellExecuteW",
    b"InternetOpen",
    b"HttpSendRequest",
    b"URLDownloadToFileA",
    b"URLDownloadToFileW",
    b"WSAStartup",
    b"connect",
    b"send",
    b"recv",
    b"RegOpenKeyExA",
    b"RegSetValueExA",
    b"RegCreateKeyExA",
    b"SetWindowsHookEx",
    b"CreateToolhelp32Snapshot",
    b"Process32First",
    b"Process32Next",
    b"IsDebuggerPresent",
}


class FileScanError(Exception):
    pass


def compute_sha256_from_bytes(raw_bytes: bytes) -> str:
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(raw_bytes).hexdigest()


def build_known_clean_whitelist() -> set[str]:
    """Build whitelist of known clean system files."""
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    whitelist: set[str] = set()
    for filename in KNOWN_CLEAN_SYSTEM_FILES:
        candidate = system_root / "System32" / filename
        if candidate.is_file():
            with open(candidate, "rb") as f:
                whitelist.add(hashlib.sha256(f.read()).hexdigest())
    return whitelist


def probability_confidence(probability: float) -> float:
    return round(max(probability, 1 - probability) * 100, 2)


def normalize_risk_score(probability_percent: float) -> float:
    return int(max(0, min(100, math.ceil(probability_percent))))


def extract_features(raw: bytes, filename: str) -> dict:
    try:
        pe = pefile.PE(data=raw)
    except pefile.PEFormatError as exc:
        raise FileScanError(f"'{filename}' is not a valid PE executable or is too malformed to inspect.") from exc
    except Exception as exc:
        raise FileScanError(f"Could not parse '{filename}' as a Windows PE file.") from exc

    try:
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
        
        # v1 features
        features = {
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
        
        # v2 features
        # is_packed: entropy > 7.5 + suspicious sections
        is_packed_v = 1 if (max_entropy > 7.5 or avg_entropy > 7.0) and suspicious_sections > 0 else 0
        features["is_packed"] = is_packed_v
        
        # import_category_score: suspicious dll count / total dlls (normalized)
        import_category_v = round(min(1.0, dlls / 100.0 if dlls else 0.0), 4)
        features["import_category_score"] = import_category_v
        
        # has_tls: check for .tls section
        has_tls_v = 1 if any(s.Name.startswith(b'.tls') for s in pe.sections) else 0
        features["has_tls"] = has_tls_v
        
        # export_table_size: count exports (DLL injection risk)
        export_size_v = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            export_size_v = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if pe.DIRECTORY_ENTRY_EXPORT.symbols else 0
        features["export_table_size"] = export_size_v
        
        # resource_entropy: entropy of .rsrc section
        rsrc_entropy_v = 0.0
        for section in pe.sections:
            if section.Name.startswith(b'.rsrc'):
                rsrc_entropy_v = round(section.get_entropy(), 4)
                break
        features["resource_entropy"] = rsrc_entropy_v
        
        # api_category_score: range based on import count / dll count
        api_score_v = round(min(1.0, (imports / 100.0) if imports else 0.0), 4)
        features["api_category_score"] = api_score_v
        
        return features
    finally:
        if "pe" in locals():
            pe.close()


def predict_file(filename: str, raw: bytes) -> dict:
    """
    Predict if a file is malware using ensemble of LGBM and XGB models.
    Includes SHA256 whitelist check and uses centralized thresholds.
    """
    features = extract_features(raw, filename)
    frame = pd.DataFrame([features])[FEATURES]
    scaled = pd.DataFrame(
        scaler.transform(frame),
        columns=FEATURES,
        index=frame.index,
    )

    # Get model probabilities
    try:
        lgbm_prob = float(lgbm.predict_proba(scaled)[0][1]) if hasattr(lgbm, "predict_proba") else None
    except Exception:
        lgbm_prob = None
    
    try:
        # For XGBoost: try predict_proba first
        if hasattr(xgb, "predict_proba"):
            xgb_prob = float(xgb.predict_proba(scaled.values)[0][1])
        elif hasattr(xgb, "predict"):
            # Fallback: use predict on numpy array, convert to probability
            pred_class = int(xgb.predict(scaled.values)[0])
            xgb_prob = 1.0 if pred_class == 1 else 0.0
        else:
            xgb_prob = None
    except Exception:
        xgb_prob = None

    if lgbm_prob is not None and xgb_prob is not None:
        avg_prob = (lgbm_prob + xgb_prob) / 2
        risk_score = normalize_risk_score(avg_prob * 100)
        confidence = probability_confidence(avg_prob)
        model_agreement = "high" if abs(lgbm_prob - xgb_prob) <= 0.15 else "mixed"
    elif lgbm_prob is not None or xgb_prob is not None:
        # Use whichever is available
        avg_prob = lgbm_prob if lgbm_prob is not None else xgb_prob
        risk_score = normalize_risk_score(avg_prob * 100)
        confidence = probability_confidence(avg_prob)
        model_agreement = "single_model"
    else:
        # Both models failed, default to 0 (benign)
        avg_prob = 0.0
        risk_score = 0
        confidence = "unknown"
        model_agreement = "unavailable"

    # Compute file hash
    file_sha256 = compute_sha256_from_bytes(raw)

    # Build whitelist
    try:
        whitelist = build_known_clean_whitelist()
    except Exception:
        whitelist = set()

    # Check whitelist first
    if file_sha256 in whitelist:
        return {
            "detection_type": "file",
            "source_value": filename,
            "filename": filename,
            "status": "safe",
            "verdict": "BENIGN",
            "predicted_class": "benign",
            "decision_threshold": THRESHOLD_CONFIG.threat_threshold,
            "decision_threshold_suspicious": THRESHOLD_CONFIG.suspicious_threshold,
            "model_agreement": "whitelist",
            "risk_score": 0,
            "confidence": 99.99,
            "is_malicious": False,
            "is_suspicious": False,
            "key_features": {k: v for k, v in features.items() if k in ["Sections", "AvgEntropy", "MaxEntropy", "SuspiciousSections", "Imports", "HasSensitiveAPI"]},
            "model_info": {
                "model_version": MODEL_METADATA.model_version,
                "threshold_version": MODEL_METADATA.threshold_version,
                "lgbm_prob": None,
                "xgb_prob": None,
                "avg_prob": 0.0,
            },
            "file_hash": file_sha256,
            "risk_flag": "Known-clean SHA256 whitelist hit",
        }

    # Use centralized threshold for status classification
    status = THRESHOLD_CONFIG.classify_status(risk_score)
    verdict = "MALICIOUS" if status == "threat" else ("SUSPICIOUS" if status == "suspicious" else "BENIGN")

    key_features_output = {
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
        "predicted_class": "malware" if status == "threat" else "benign",
        "decision_threshold": THRESHOLD_CONFIG.threat_threshold,
        "decision_threshold_suspicious": THRESHOLD_CONFIG.suspicious_threshold,
        "model_agreement": model_agreement,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_malicious": status == "threat",
        "is_suspicious": status == "suspicious",
        "key_features": key_features_output,
        # Model versioning and metadata
        "model_info": {
            "model_version": MODEL_METADATA.model_version,
            "threshold_version": MODEL_METADATA.threshold_version,
            "lgbm_prob": round(lgbm_prob, 4) if lgbm_prob else None,
            "xgb_prob": round(xgb_prob, 4) if xgb_prob else None,
            "avg_prob": round(avg_prob, 4),
        },
        "file_hash": file_sha256,
        "risk_flag": None,
    }
