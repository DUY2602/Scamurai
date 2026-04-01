import joblib
import pefile  # đọc đọc cấu trúc file PE của Window
import tempfile # tạo file tạm để pefile xử lý
import pandas as pd
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
MODEL_DIR = ROOT_DIR / "FILE" / "models"

lgbm   = joblib.load(MODEL_DIR / "lightgbm_malware_model.pkl")
xgb    = joblib.load(MODEL_DIR / "xgboost_malware_model.pkl")
scaler = joblib.load(MODEL_DIR / "feature_scaler.pkl")

FEATURES = ["Sections","AvgEntropy","MaxEntropy","SuspiciousSections",
            "DLLs","Imports","HasSensitiveAPI","ImageBase","SizeOfImage","HasVersionInfo"]

SENSITIVE_APIS = {b"CreateRemoteThread",b"WriteProcessMemory",b"VirtualAllocEx",
                  b"InternetOpen",b"HttpSendRequest",b"SetWindowsHookEx"}

def extract_features(raw: bytes, filename: str) -> dict:
    suffix = Path(filename).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
        f.write(raw)
        tmp = Path(f.name)
    try:
        pe = pefile.PE(str(tmp))
        sections = len(pe.sections)
        entropies = [s.get_entropy() for s in pe.sections]
        avg_e = sum(entropies)/sections if sections else 0.0
        max_e = max(entropies) if entropies else 0.0
        susp  = sum(1 for s in pe.sections
                    if (s.Characteristics & 0x80000000) and (s.Characteristics & 0x20000000))
        dlls, imports, has_api = 0, 0, 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                imports += len(e.imports)
                for imp in e.imports:
                    if imp.name in SENSITIVE_APIS:
                        has_api = 1
        has_ver = 1 if hasattr(pe, "VS_FIXEDFILEINFO") else 0
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        size_img   = int(pe.OPTIONAL_HEADER.SizeOfImage)
        pe.close()
        return {"Sections":sections,"AvgEntropy":round(avg_e,4),"MaxEntropy":round(max_e,4),
                "SuspiciousSections":susp,"DLLs":dlls,"Imports":imports,
                "HasSensitiveAPI":has_api,"ImageBase":image_base,
                "SizeOfImage":size_img,"HasVersionInfo":has_ver}
    finally:
        tmp.unlink(missing_ok=True)

def predict_file(filename: str, raw: bytes) -> dict:
    features = extract_features(raw, filename)
    df = pd.DataFrame([features])[FEATURES]

    lgbm_pred = int(lgbm.predict(df)[0])
    xgb_pred  = int(xgb.predict(df)[0])
    harmful_votes = lgbm_pred + xgb_pred

    # Lấy probability nếu có
    lgbm_prob = float(lgbm.predict_proba(df)[0][1]) if hasattr(lgbm, "predict_proba") else None
    xgb_prob  = float(xgb.predict_proba(df)[0][1])  if hasattr(xgb,  "predict_proba") else None
    avg_prob  = (lgbm_prob + xgb_prob) / 2 if lgbm_prob and xgb_prob else None

    is_malicious = harmful_votes >= 2  # cả 2 đều đồng ý
    verdict = "MALWARE" if is_malicious else "BENIGN"

    return {
        "filename":      filename,
        "verdict":       verdict,
        "is_malicious":  is_malicious,
        "harmful_votes": harmful_votes,
        "total_models":  2,
        "risk_score":    round((avg_prob or harmful_votes/2) * 100, 2),
        "features":      features,
    }
