import joblib
import pandas as pd
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[3]
MODEL_DIR = ROOT_DIR / "URL" / "models"

lgbm  = joblib.load(MODEL_DIR / "lgbm_model.pkl")
xgb   = joblib.load(MODEL_DIR / "xgb_model.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
feature_names = joblib.load(MODEL_DIR / "feature_names.pkl")

def extract_features(url: str) -> dict:
    """Trích xuất features từ URL string"""
    from urllib.parse import urlparse
    import math, re

    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.netloc.replace("www.", "")
    path = parsed.path or ""
    query = parsed.query or ""
    full = f"{hostname}{path}"

    def entropy(s):
        if not s: return 0.0
        probs = [s.count(c)/len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in probs)

    keywords = ["login","verify","update","secure","account","banking",
                "signin","confirm","bank","password","reset"]
    trash_tlds = (".tk",".xyz",".cc",".top",".pw",".online",".site",".biz")
    popular_tlds = (".com",".net",".org",".co",".edu",".gov")
    brands = ["google","paypal","apple","microsoft","amazon","bank","secure"]

    host_parts = [p for p in hostname.split(".") if p]
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""

    return {
        "url_len":           len(full),
        "hostname_len":      len(hostname),
        "dot_count":         full.count("."),
        "dash_count":        hostname.count("-"),
        "digit_ratio":       len(re.findall(r"\d", full)) / (len(full)+1),
        "entropy":           round(entropy(full), 6),
        "is_trash_tld":      int(hostname.endswith(trash_tlds)),
        "is_popular_tld":    int(any(hostname.endswith(t) for t in popular_tlds)),
        "has_ip":            int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname))),
        "is_exec":           int(bool(re.search(r"\.(exe|apk|msi|zip)$", path))),
        "keyword_count":     sum(1 for k in keywords if k in full),
        "subdomain_count":   len(host_parts) - 2 if len(host_parts) > 2 else 0,
        "special_ratio":     sum(full.count(c) for c in "-._@?&=") / (len(full)+1),
        "has_number_in_host":int(any(c.isdigit() for c in hostname)),
        "has_at_symbol":     int("@" in url),
        "path_depth":        path.count("/"),
        "has_redirect":      int("//" in url.split("://",1)[-1]),
        "brand_in_subdomain":int(any(b in subdomain for b in brands)),
        "tld_in_path":       int(any(m in path for m in (".com",".net",".org",".io"))),
        "query_param_count": len([p for p in query.split("&") if p]),
        "has_hex_encoding":  int("%" in url),
    }

def predict_url(url: str) -> dict:
    features = extract_features(url)
    df = pd.DataFrame([features])[feature_names]

    # Soft voting với threshold 0.45
    lgbm_prob = lgbm.predict_proba(scaler.transform(df))[0][1]
    xgb_prob  = xgb.predict_proba(scaler.transform(df))[0][1]
    avg_prob  = (lgbm_prob + xgb_prob) / 2

    is_malicious = avg_prob >= 0.45
    verdict = "MALICIOUS" if is_malicious else "BENIGN"

    return {
        "url":         url,
        "verdict":     verdict,
        "risk_score":  float(round(avg_prob * 100, 2)),
        "lgbm_prob":   float(round(lgbm_prob, 4)),
        "xgb_prob":    float(round(xgb_prob, 4)),
        "avg_prob":    float(round(avg_prob, 4)),
        "is_malicious": bool(is_malicious),
    }
