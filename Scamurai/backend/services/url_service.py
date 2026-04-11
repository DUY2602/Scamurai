import json
import joblib
import math
import pandas as pd
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlunparse

from backend.services.asset_paths import find_asset_dir
from backend.services.model_runtime import classify_status, load_url_thresholds

MODEL_DIR = find_asset_dir(Path(__file__), "URL", "models")
ADAPTIVE_SAFE_PATTERNS_PATH = MODEL_DIR / "adaptive_safe_patterns.json"
COMMON_MULTI_LEVEL_SUFFIXES = {
    "com.au",
    "edu.au",
    "gov.au",
    "com.vn",
    "edu.vn",
    "gov.vn",
    "org.vn",
    "ac.vn",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
}
BENIGN_TRACKING_QUERY_KEYS = {
    "aid",
    "aff_id",
    "affid",
    "affiliate_id",
    "campaign",
    "clickid",
    "fbclid",
    "gclid",
    "label",
    "mmp_pid",
    "msclkid",
    "ref",
    "referrer",
    "source",
    "subid",
    "term",
    "ttclid",
    "uls_trackid",
}
BENIGN_TRACKING_QUERY_PREFIXES = (
    "utm_",
    "aff_",
    "ref_",
)

lgbm = joblib.load(MODEL_DIR / "lgbm_model.pkl")
xgb = joblib.load(MODEL_DIR / "xgb_model.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
feature_names = joblib.load(MODEL_DIR / "feature_names.pkl")
THREAT_THRESHOLD, SUSPICIOUS_THRESHOLD = load_url_thresholds(Path(__file__))


def probability_confidence(probability: float) -> float:
    return round(max(probability, 1 - probability) * 100, 2)


def normalize_risk_score(probability_percent: float) -> float:
    return int(max(0, min(100, math.ceil(probability_percent))))


def _extract_registered_domain(hostname: str) -> str:
    host_parts = [part for part in str(hostname or "").lower().split(".") if part]
    if len(host_parts) <= 2:
        return ".".join(host_parts)

    last_two = ".".join(host_parts[-2:])
    if last_two in COMMON_MULTI_LEVEL_SUFFIXES and len(host_parts) >= 3:
        return ".".join(host_parts[-3:])
    return ".".join(host_parts[-2:])


def _extract_query_keys(normalized_url: str) -> list[str]:
    parsed = urlparse(normalized_url)
    return [key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]


def _extract_query_pairs(normalized_url: str) -> list[tuple[str, str]]:
    parsed = urlparse(normalized_url)
    return [(key.lower(), value.lower()) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]


def _load_adaptive_safe_patterns() -> dict:
    if not ADAPTIVE_SAFE_PATTERNS_PATH.exists():
        return {
            "safe_hostnames": [],
            "safe_registered_domains": [],
            "safe_path_signatures": [],
            "threat_hostnames": [],
            "threat_registered_domains": [],
            "threat_path_signatures": [],
            "safe_observations": {},
            "threat_observations": {},
        }

    try:
        data = json.loads(ADAPTIVE_SAFE_PATTERNS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {
            "safe_hostnames": [],
            "safe_registered_domains": [],
            "safe_path_signatures": [],
            "threat_hostnames": [],
            "threat_registered_domains": [],
            "threat_path_signatures": [],
            "safe_observations": {},
            "threat_observations": {},
        }

    if not isinstance(data, dict):
        return {
            "safe_hostnames": [],
            "safe_registered_domains": [],
            "safe_path_signatures": [],
            "threat_hostnames": [],
            "threat_registered_domains": [],
            "threat_path_signatures": [],
            "safe_observations": {},
            "threat_observations": {},
        }

    return {
        "safe_hostnames": sorted({str(item).lower() for item in data.get("safe_hostnames", []) if item}),
        "safe_registered_domains": sorted({str(item).lower() for item in data.get("safe_registered_domains", []) if item}),
        "safe_path_signatures": sorted({str(item).lower() for item in data.get("safe_path_signatures", []) if item}),
        "threat_hostnames": sorted({str(item).lower() for item in data.get("threat_hostnames", []) if item}),
        "threat_registered_domains": sorted({str(item).lower() for item in data.get("threat_registered_domains", []) if item}),
        "threat_path_signatures": sorted({str(item).lower() for item in data.get("threat_path_signatures", []) if item}),
        "safe_observations": {
            str(key).lower(): int(value)
            for key, value in data.get("safe_observations", {}).items()
            if key
        },
        "threat_observations": {
            str(key).lower(): int(value)
            for key, value in data.get("threat_observations", {}).items()
            if key
        },
    }


def _save_adaptive_safe_patterns(patterns: dict) -> None:
    payload = {
        "safe_hostnames": sorted({str(item).lower() for item in patterns.get("safe_hostnames", []) if item}),
        "safe_registered_domains": sorted({str(item).lower() for item in patterns.get("safe_registered_domains", []) if item}),
        "safe_path_signatures": sorted({str(item).lower() for item in patterns.get("safe_path_signatures", []) if item}),
        "threat_hostnames": sorted({str(item).lower() for item in patterns.get("threat_hostnames", []) if item}),
        "threat_registered_domains": sorted({str(item).lower() for item in patterns.get("threat_registered_domains", []) if item}),
        "threat_path_signatures": sorted({str(item).lower() for item in patterns.get("threat_path_signatures", []) if item}),
        "safe_observations": {
            str(key).lower(): int(value)
            for key, value in patterns.get("safe_observations", {}).items()
            if key
        },
        "threat_observations": {
            str(key).lower(): int(value)
            for key, value in patterns.get("threat_observations", {}).items()
            if key
        },
    }
    ADAPTIVE_SAFE_PATTERNS_PATH.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )


def _match_adaptive_safe_pattern(hostname: str, normalized_url: str, features: dict) -> dict:
    host = str(hostname or "").lower()
    registered_domain = _extract_registered_domain(host)
    path_archetype = _derive_path_archetype(normalized_url, features)
    patterns = _load_adaptive_safe_patterns()
    safe_hostnames = set(patterns["safe_hostnames"])
    safe_registered_domains = set(patterns["safe_registered_domains"])
    safe_path_signatures = set(patterns["safe_path_signatures"])
    path_signature = f"{registered_domain}|{path_archetype}" if path_archetype else None

    return {
        "hostname_match": host if host in safe_hostnames else None,
        "registered_domain_match": registered_domain if registered_domain in safe_registered_domains else None,
        "path_signature_match": path_signature if path_signature and path_signature in safe_path_signatures else None,
    }


def _match_adaptive_threat_pattern(hostname: str, normalized_url: str, features: dict) -> dict:
    host = str(hostname or "").lower()
    registered_domain = _extract_registered_domain(host)
    path_archetype = _derive_path_archetype(normalized_url, features)
    patterns = _load_adaptive_safe_patterns()
    threat_hostnames = set(patterns["threat_hostnames"])
    threat_registered_domains = set(patterns["threat_registered_domains"])
    threat_path_signatures = set(patterns["threat_path_signatures"])
    path_signature = f"{registered_domain}|{path_archetype}" if path_archetype else None

    return {
        "hostname_match": host if host in threat_hostnames else None,
        "registered_domain_match": registered_domain if registered_domain in threat_registered_domains else None,
        "path_signature_match": path_signature if path_signature and path_signature in threat_path_signatures else None,
    }


def _derive_path_archetype(normalized_url: str, features: dict) -> str | None:
    parsed = urlparse(normalized_url)
    path = (parsed.path or "").strip("/")
    if not path:
        return None

    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return None

    if not all(re.fullmatch(r"[a-z0-9._-]+", segment) for segment in segments):
        return None

    has_html_suffix = segments[-1].endswith(".html")
    has_query = bool(parsed.query)
    depth = len(segments)
    digit_segments = sum(1 for segment in segments if any(char.isdigit() for char in segment))

    if has_html_suffix and not has_query and 1 <= depth <= 4:
        return f"html_content_depth_{depth}_digits_{min(digit_segments, 2)}"
    if not has_query and 1 <= depth <= 4 and features.get("keyword_count", 0) == 0:
        return f"clean_content_depth_{depth}_digits_{min(digit_segments, 2)}"
    return None


def _is_benign_commerce_or_content_path(
    normalized_url: str,
    features: dict,
    benign_tracking_link: bool,
    tld_risk: float,
    homograph_risk: float,
    brand_impersonation: float,
    threat_signals: int,
) -> bool:
    parsed = urlparse(normalized_url)
    path = (parsed.path or "").strip("/")
    if not path:
        return False

    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return False

    safe_segment_pattern = re.compile(r"^[a-z0-9._-]+$")
    if not all(safe_segment_pattern.fullmatch(segment) for segment in segments):
        return False

    allowed_query = (not parsed.query) or benign_tracking_link
    return (
        threat_signals == 0
        and allowed_query
        and features["is_exec"] == 0
        and features["has_redirect"] == 0
        and features["has_hex_encoding"] == 0
        and features["has_at_symbol"] == 0
        and features["keyword_count"] == 0
        and features["subdomain_count"] <= 1
        and features["path_depth"] <= 4
        and features["has_number_in_host"] == 0
        and features["brand_in_subdomain"] == 0
        and features["tld_in_path"] == 0
        and features["is_trash_tld"] == 0
        and tld_risk <= 0.15
        and homograph_risk == 0.0
        and brand_impersonation == 0.0
        and features["entropy"] <= 4.25
        and features["hostname_len"] <= 35
    )


def _learn_adaptive_safe_pattern(hostname: str, normalized_url: str, features: dict) -> None:
    host = str(hostname or "").lower()
    if not host:
        return

    patterns = _load_adaptive_safe_patterns()
    safe_hostnames = set(patterns["safe_hostnames"])
    safe_registered_domains = set(patterns["safe_registered_domains"])
    safe_path_signatures = set(patterns["safe_path_signatures"])
    safe_hostnames.add(host)

    if int(features.get("subdomain_count", 0)) == 0:
        safe_registered_domains.add(_extract_registered_domain(host))

    path_archetype = _derive_path_archetype(normalized_url, features)
    if path_archetype:
        safe_path_signatures.add(f"{_extract_registered_domain(host)}|{path_archetype}")

    _save_adaptive_safe_patterns(
        {
            "safe_hostnames": sorted(safe_hostnames),
            "safe_registered_domains": sorted(safe_registered_domains),
            "safe_path_signatures": sorted(safe_path_signatures),
            "threat_hostnames": patterns["threat_hostnames"],
            "threat_registered_domains": patterns["threat_registered_domains"],
            "threat_path_signatures": patterns["threat_path_signatures"],
        }
    )


def submit_url_feedback(url: str, verdict: str) -> dict:
    normalized_url = normalize_url_for_detection(url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    features = extract_features(url)
    patterns = _load_adaptive_safe_patterns()

    safe_hostnames = set(patterns["safe_hostnames"])
    safe_registered_domains = set(patterns["safe_registered_domains"])
    safe_path_signatures = set(patterns["safe_path_signatures"])
    threat_hostnames = set(patterns["threat_hostnames"])
    threat_registered_domains = set(patterns["threat_registered_domains"])
    threat_path_signatures = set(patterns["threat_path_signatures"])

    registered_domain = _extract_registered_domain(hostname)
    path_archetype = _derive_path_archetype(normalized_url, features)
    path_signature = f"{registered_domain}|{path_archetype}" if path_archetype else None
    normalized_verdict = str(verdict or "").strip().lower()

    if normalized_verdict not in {"safe", "threat"}:
        raise ValueError("Feedback verdict must be either 'safe' or 'threat'.")

    if normalized_verdict == "safe":
        safe_hostnames.add(hostname)
        threat_hostnames.discard(hostname)
        if int(features.get("subdomain_count", 0)) == 0:
            safe_registered_domains.add(registered_domain)
            threat_registered_domains.discard(registered_domain)
        if path_signature:
            safe_path_signatures.add(path_signature)
            threat_path_signatures.discard(path_signature)
    else:
        threat_hostnames.add(hostname)
        safe_hostnames.discard(hostname)
        if int(features.get("subdomain_count", 0)) == 0:
            threat_registered_domains.add(registered_domain)
            safe_registered_domains.discard(registered_domain)
        if path_signature:
            threat_path_signatures.add(path_signature)
            safe_path_signatures.discard(path_signature)

    _save_adaptive_safe_patterns(
        {
            "safe_hostnames": sorted(safe_hostnames),
            "safe_registered_domains": sorted(safe_registered_domains),
            "safe_path_signatures": sorted(safe_path_signatures),
            "threat_hostnames": sorted(threat_hostnames),
            "threat_registered_domains": sorted(threat_registered_domains),
            "threat_path_signatures": sorted(threat_path_signatures),
            "safe_observations": patterns["safe_observations"],
            "threat_observations": patterns["threat_observations"],
        }
    )

    return {
        "url": url,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "path_signature": path_signature,
        "verdict": normalized_verdict,
    }


def _increment_counter(counters: dict, key: str | None) -> None:
    if not key:
        return
    counters[key] = int(counters.get(key, 0)) + 1


def _auto_promote_url_pattern(
    hostname: str,
    normalized_url: str,
    features: dict,
    risk_score: float,
    threat_signals: int,
    post_model_details: dict,
) -> None:
    host = str(hostname or "").lower()
    if not host:
        return

    registered_domain = _extract_registered_domain(host)
    path_archetype = _derive_path_archetype(normalized_url, features)
    path_signature = f"{registered_domain}|{path_archetype}" if path_archetype else None
    patterns = _load_adaptive_safe_patterns()

    safe_hostnames = set(patterns["safe_hostnames"])
    safe_registered_domains = set(patterns["safe_registered_domains"])
    safe_path_signatures = set(patterns["safe_path_signatures"])
    threat_hostnames = set(patterns["threat_hostnames"])
    threat_registered_domains = set(patterns["threat_registered_domains"])
    threat_path_signatures = set(patterns["threat_path_signatures"])
    safe_observations = dict(patterns["safe_observations"])
    threat_observations = dict(patterns["threat_observations"])

    auto_safe_candidate = (
        threat_signals == 0
        and risk_score <= 35
        and (
            post_model_details.get("low_risk_unknown_domain")
            or post_model_details.get("benign_tracking_link")
            or post_model_details.get("benign_content_path")
            or post_model_details.get("benign_commerce_or_content_path")
            or post_model_details.get("adaptive_safe_hostname_match")
            or post_model_details.get("adaptive_safe_registered_domain_match")
            or post_model_details.get("adaptive_safe_path_signature_match")
        )
    )
    auto_threat_candidate = (
        risk_score >= 85
        and (
            threat_signals >= 2
            or post_model_details.get("adaptive_threat_hostname_match")
            or post_model_details.get("adaptive_threat_registered_domain_match")
            or post_model_details.get("adaptive_threat_path_signature_match")
        )
    )

    if auto_safe_candidate:
        _increment_counter(safe_observations, f"host:{host}")
        if int(features.get("subdomain_count", 0)) == 0:
            _increment_counter(safe_observations, f"domain:{registered_domain}")
        if path_signature:
            _increment_counter(safe_observations, f"path:{path_signature}")

        if safe_observations.get(f"host:{host}", 0) >= 2:
            safe_hostnames.add(host)
            threat_hostnames.discard(host)
        if int(features.get("subdomain_count", 0)) == 0 and safe_observations.get(f"domain:{registered_domain}", 0) >= 2:
            safe_registered_domains.add(registered_domain)
            threat_registered_domains.discard(registered_domain)
        if path_signature and safe_observations.get(f"path:{path_signature}", 0) >= 2:
            safe_path_signatures.add(path_signature)
            threat_path_signatures.discard(path_signature)

    if auto_threat_candidate:
        _increment_counter(threat_observations, f"host:{host}")
        if int(features.get("subdomain_count", 0)) == 0:
            _increment_counter(threat_observations, f"domain:{registered_domain}")
        if path_signature:
            _increment_counter(threat_observations, f"path:{path_signature}")

        if threat_observations.get(f"host:{host}", 0) >= 2:
            threat_hostnames.add(host)
            safe_hostnames.discard(host)
        if int(features.get("subdomain_count", 0)) == 0 and threat_observations.get(f"domain:{registered_domain}", 0) >= 2:
            threat_registered_domains.add(registered_domain)
            safe_registered_domains.discard(registered_domain)
        if path_signature and threat_observations.get(f"path:{path_signature}", 0) >= 2:
            threat_path_signatures.add(path_signature)
            safe_path_signatures.discard(path_signature)

    if auto_safe_candidate or auto_threat_candidate:
        _save_adaptive_safe_patterns(
            {
                "safe_hostnames": sorted(safe_hostnames),
                "safe_registered_domains": sorted(safe_registered_domains),
                "safe_path_signatures": sorted(safe_path_signatures),
                "threat_hostnames": sorted(threat_hostnames),
                "threat_registered_domains": sorted(threat_registered_domains),
                "threat_path_signatures": sorted(threat_path_signatures),
                "safe_observations": safe_observations,
                "threat_observations": threat_observations,
            }
        )


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


# ============================================================
# GREEN FLAG / RED FLAG DETECTION (From url_feature_engineering)
# ============================================================

SAFE_BRAND_DOMAINS = {
    # Tech Giants
    "google.com", "github.com", "youtube.com", "microsoft.com", "paypal.com",
    "apple.com", "amazon.com", "facebook.com", "instagram.com", "linkedin.com",
    "dropbox.com", "docusign.com", "adobe.com", "office.com", "outlook.com",
    "live.com", "netflix.com",
    # Banks
    "bankofamerica.com", "wellsfargo.com", "chase.com",
    # Government & Education
    "gov.vn", "edu.vn", "ac.vn", "org.vn",
    # Universities
    "mit.edu", "stanford.edu", "berkeley.edu", "harvard.edu", "yale.edu",
    "princeton.edu", "columbia.edu", "upenn.edu", "caltech.edu",
    "vnu.edu.vn", "hust.edu.vn", "hcmut.edu.vn",
    # Swinburne & Australian Universities
    "swinburne.edu.au", "monash.edu.au", "unimelb.edu.au", "unsw.edu.au",
    "sydney.edu.au", "anu.edu.au",
    # Learning Management Systems (LMS)
    "instructure.com", "swinburne.instructure.com", "canvas.vn", 
    "moodle.org", "blackboard.com", "brightspace.com",
    # Government
    "usa.gov", "gov.uk", "australia.gov.au",
}

TLD_RISK_SCORES = {
    "gov": 0.01, "gov.vn": 0.01, "gov.au": 0.01,
    "edu": 0.02, "edu.vn": 0.02, "edu.au": 0.02, "ac.uk": 0.02, "ac.au": 0.02,
    "com": 0.0, "org": 0.05, "net": 0.08, "co": 0.05,
    "vn": 0.06, "au": 0.05, "uk": 0.05,
    "us": 0.15, "sg": 0.05, "jp": 0.05, "de": 0.05, "fr": 0.05,
    "info": 0.25, "biz": 0.35, "site": 0.45, "online": 0.45,
    "work": 0.65, "xyz": 0.70, "click": 0.80, "top": 0.85,
    "cc": 0.75, "pw": 0.80, "tk": 0.90, "cf": 0.90,
    "vip": 0.75, "ru": 0.70, "cn": 0.15,
}

CHEAP_TLDS = {".xyz", ".top", ".cc", ".vip", ".click", ".tk", ".cf", ".ga", ".ml", ".pw"}


def _detect_homograph_risk(hostname: str) -> float:
    """Detect homograph attacks using non-Latin lookalikes"""
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", str(hostname or "")):
        return 0.0
    homograph_indicators = [
        ('а', 'a'), ('е', 'e'), ('о', 'o'), ('р', 'p'),
        ('с', 'c'), ('у', 'y'), ('х', 'x'),  # Cyrillic
        ('0', 'o'), ('1', 'l'), ('1', 'i'),  # Numeric lookalikes
    ]
    
    risk = 0.0
    suspicious_count = 0
    for suspect_char, _ in homograph_indicators:
        if suspect_char in hostname:
            suspicious_count += hostname.count(suspect_char)
    
    if suspicious_count > 0:
        risk = min(1.0, 0.3 + (suspicious_count * 0.2))
    
    return risk


def _get_tld_risk_score(hostname: str) -> float:
    """Get risk score for TLD"""
    host_parts = [part for part in hostname.split(".") if part]
    tld = host_parts[-1] if host_parts else ""
    return TLD_RISK_SCORES.get(tld, 0.15)


def _get_brand_impersonation_score(hostname: str) -> float:
    """Detect brand impersonation & subdomain exploitation"""
    risk = 0.0
    host = hostname.lower()
    host_parts = [part for part in host.split(".") if part]
    main_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    
    # ✅ Nếu hostname là safe domain hoặc subdomain của safe domain → NO RISK
    for safe_domain in SAFE_BRAND_DOMAINS:
        if host == safe_domain or host.endswith("." + safe_domain):
            # Domain này là safe hoặc là subdomain của safe domain
            return 0.0
    
    # ❌ Nếu domain khác nhưng chứa tên brand → RISK (brand impersonation)
    for safe_domain in SAFE_BRAND_DOMAINS:
        brand_name = safe_domain.split(".")[0]
        # Kiểm tra typosquat hoặc brand spoofing
        if brand_name in host and safe_domain not in host:
            # Element contains brand name nhưng ko phải safe domain
            if len(brand_name) > 3:  # Chỉ tính nếu brand name đủ dài
                risk += 0.4
    
    # Multiple dashes = suspicious
    if hostname.count("-") >= 2:
        risk += 0.2
    
    return min(1.0, risk)


def _detect_security_test_artifact(normalized_url: str) -> str | None:
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    combined = f"{hostname}{path}"
    path_segments = [segment for segment in path.split("/") if segment]
    filename = path_segments[-1] if path_segments else ""

    eicar_tokens = (
        "eicar.com",
        "eicar_com",
        "eicarcom",
        "eicar.com.txt",
        "eicar_com.zip",
        "eicarcom2.zip",
    )
    if "eicar" in combined and any(token in combined for token in eicar_tokens):
        return "eicar_test_artifact"

    security_tokens = {"security", "antivirus", "anti-malware", "malware", "virus"}
    test_tokens = {"test", "testfile", "sample", "signature", "payload"}
    download_like_extensions = (".txt", ".com", ".bin", ".zip", ".dat")
    filename_has_download_extension = any(filename.endswith(ext) for ext in download_like_extensions)
    has_security_token = any(token in combined for token in security_tokens)
    has_test_token = any(token in combined for token in test_tokens)

    if filename_has_download_extension and has_security_token and has_test_token:
        return "security_test_payload"

    if "eicar" in combined and filename_has_download_extension:
        return "security_test_payload"

    return None


def _detect_local_dev_context(normalized_url: str) -> str | None:
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()

    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return "localhost_loopback"
    if hostname.startswith("127."):
        return "localhost_loopback"
    if hostname.startswith("192.168.") or hostname.startswith("10."):
        return "private_network_host"
    if hostname.startswith("172."):
        try:
            second_octet = int(hostname.split(".")[1])
            if 16 <= second_octet <= 31:
                return "private_network_host"
        except Exception:
            return None
    return None


def _detect_open_redirect(normalized_url: str) -> dict | None:
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    registered_domain = _extract_registered_domain(hostname)
    redirect_keys = {
        "redirect",
        "redirect_uri",
        "redirect_url",
        "return",
        "return_to",
        "next",
        "url",
        "target",
        "dest",
        "destination",
        "continue",
    }

    for key, value in _extract_query_pairs(normalized_url):
        if key not in redirect_keys:
            continue
        if "://" not in value:
            continue
        try:
            target = urlparse(value)
        except Exception:
            continue
        target_host = (target.hostname or "").lower()
        if not target_host:
            continue
        target_registered_domain = _extract_registered_domain(target_host)
        target_tld_risk = _get_tld_risk_score(target_host)
        if target_registered_domain != registered_domain:
            return {
                "type": "open_redirect_to_external_domain",
                "param": key,
                "target_host": target_host,
                "target_registered_domain": target_registered_domain,
                "target_tld_risk": target_tld_risk,
            }
    return None


def _detect_xss_payload(normalized_url: str) -> str | None:
    lowered = str(normalized_url or "").lower()
    xss_markers = (
        "<script",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "alert(",
        "%3cscript",
        "%3c/svg",
        "<img",
        "<svg",
    )
    if any(marker in lowered for marker in xss_markers):
        return "script_injection_payload"
    return None


def _detect_sqli_payload(normalized_url: str) -> str | None:
    lowered = str(normalized_url or "").lower()
    parsed = urlparse(lowered)
    query = parsed.query or ""
    path = parsed.path or ""
    combined = f"{path}?{query}" if query else path

    strong_patterns = [
        r"(?:^|[\W_])or\s*'?\d+'?\s*=\s*'?\d+'?",
        r"(?:^|[\W_])or\s*'[^']+'\s*=\s*'[^']+'",
        r"union\s+all\s+select",
        r"union\s+select",
        r"information_schema",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
        r"drop\s+table",
        r"insert\s+into",
        r"update\s+\w+\s+set",
        r"delete\s+from",
    ]
    medium_patterns = [
        r"(?:'|%27)\s*or\s+1=1",
        r"--",
        r"/\*",
        r"\bselect\b.+\bfrom\b",
        r"\bexec\b\s*\(",
        r"\bcast\s*\(",
        r"\bconvert\s*\(",
    ]

    for pattern in strong_patterns:
        if re.search(pattern, combined):
            return "sqli_payload"

    hit_count = 0
    for pattern in medium_patterns:
        if re.search(pattern, combined):
            hit_count += 1
    if hit_count >= 2:
        return "sqli_payload"

    return None


def _count_red_flags(hostname: str) -> int:
    """Count red flags: subdomain mismatches, cheap TLDs, weird patterns"""
    flags = 0
    host_parts = [part for part in hostname.split(".") if part]
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
    main_part = host_parts[-2] if len(host_parts) >= 2 else ""
    tld = host_parts[-1] if host_parts else ""
    
    # Flag: Subdomain with brand but unsafe domain
    if subdomain:
        for safe_domain in SAFE_BRAND_DOMAINS:
            if safe_domain.split(".")[0] in subdomain:
                flags += 1
                break
    
    # Flag: Too many dashes
    if hostname.count("-") >= 2:
        flags += 1
    
    # Flag: High digit ratio in main part
    if main_part:
        digit_ratio = sum(1 for c in main_part if c.isdigit()) / len(main_part)
        if digit_ratio > 0.4:
            flags += 1
    
    # Flag: Unusually long hostname
    if len(hostname) > 35:
        flags += 1
    
    # Flag: Cheap/dangerous TLD
    if f".{tld}" in CHEAP_TLDS or TLD_RISK_SCORES.get(tld, 0.15) > 0.6:
        flags += 1
    
    # Flag: IP-based
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname):
        flags += 2
    
    return min(flags, 5)


def _is_clean_homepage(normalized_url: str, features: dict) -> bool:
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    host_parts = [part for part in hostname.split(".") if part]
    return (
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


def _match_safe_domain(hostname: str) -> str | None:
    host = str(hostname or "").lower()
    for safe_domain in SAFE_BRAND_DOMAINS:
        if host == safe_domain or host.endswith("." + safe_domain):
            return safe_domain
    return None


def _count_threat_confirmation_signals(
    features: dict,
    tld_risk: float,
    homograph_risk: float,
    brand_impersonation: float,
    local_dev_context: str | None = None,
    open_redirect_signal: dict | None = None,
    xss_payload_signal: str | None = None,
    sqli_payload_signal: str | None = None,
) -> int:
    signals = 0

    if features["has_ip"] and not local_dev_context:
        signals += 2
    if features["is_exec"]:
        signals += 2
    if features["has_at_symbol"]:
        signals += 1
    if features["has_redirect"]:
        signals += 1
    if features["has_hex_encoding"]:
        signals += 1
    if features["is_trash_tld"] or tld_risk >= 0.7:
        signals += 1
    if homograph_risk >= 0.3:
        signals += 1
    if brand_impersonation >= 0.5:
        signals += 1
    if features["keyword_count"] >= 3:
        signals += 1
    if features["subdomain_count"] >= 3:
        signals += 1
    if features["path_depth"] >= 4:
        signals += 1
    if open_redirect_signal:
        signals += 2
    if xss_payload_signal:
        signals += 3
    if sqli_payload_signal:
        signals += 3

    return signals


def _compute_post_model_adjustment(
    normalized_url: str,
    hostname: str,
    features: dict,
    base_prob: float,
    tld_risk: float,
    homograph_risk: float,
    brand_impersonation: float,
) -> tuple[float, dict]:
    parsed = urlparse(normalized_url)
    path_archetype = _derive_path_archetype(normalized_url, features)
    security_test_artifact = _detect_security_test_artifact(normalized_url)
    local_dev_context = _detect_local_dev_context(normalized_url)
    open_redirect_signal = _detect_open_redirect(normalized_url)
    xss_payload_signal = _detect_xss_payload(normalized_url)
    sqli_payload_signal = _detect_sqli_payload(normalized_url)
    safe_domain = _match_safe_domain(hostname)
    adaptive_safe_match = _match_adaptive_safe_pattern(hostname, normalized_url, features)
    adaptive_threat_match = _match_adaptive_threat_pattern(hostname, normalized_url, features)
    query_keys = _extract_query_keys(normalized_url)
    threat_signals = _count_threat_confirmation_signals(
        features,
        tld_risk,
        homograph_risk,
        brand_impersonation,
        local_dev_context,
        open_redirect_signal,
        xss_payload_signal,
        sqli_payload_signal,
    )

    adjustment = 0.0
    reasons: list[str] = []
    benign_tracking_link = (
        bool(query_keys)
        and all(
            key in BENIGN_TRACKING_QUERY_KEYS
            or any(key.startswith(prefix) for prefix in BENIGN_TRACKING_QUERY_PREFIXES)
            for key in query_keys
        )
    )
    benign_commerce_or_content_path = _is_benign_commerce_or_content_path(
        normalized_url,
        features,
        benign_tracking_link,
        tld_risk,
        homograph_risk,
        brand_impersonation,
        threat_signals,
    )
    benign_content_path = (
        threat_signals == 0
        and bool(path_archetype)
        and not parsed.query
        and features["is_exec"] == 0
        and features["has_redirect"] == 0
        and features["has_hex_encoding"] == 0
        and features["keyword_count"] == 0
        and features["path_depth"] <= 4
        and features["subdomain_count"] <= 1
        and features["has_number_in_host"] == 0
        and features["brand_in_subdomain"] == 0
        and tld_risk <= 0.15
        and homograph_risk == 0.0
        and brand_impersonation == 0.0
    )
    low_risk_unknown_domain = (
        threat_signals == 0
        and not safe_domain
        and not adaptive_safe_match["hostname_match"]
        and not adaptive_safe_match["registered_domain_match"]
        and not adaptive_safe_match["path_signature_match"]
        and features["is_trash_tld"] == 0
        and features["has_ip"] == 0
        and features["is_exec"] == 0
        and features["has_at_symbol"] == 0
        and features["has_redirect"] == 0
        and features["has_hex_encoding"] == 0
        and features["keyword_count"] == 0
        and features["subdomain_count"] <= 1
        and (features["path_depth"] <= 1 or benign_content_path or benign_commerce_or_content_path)
        and features["has_number_in_host"] == 0
        and features["brand_in_subdomain"] == 0
        and features["tld_in_path"] == 0
        and (features["query_param_count"] == 0 or benign_tracking_link)
        and tld_risk <= 0.15
        and homograph_risk == 0.0
        and brand_impersonation == 0.0
        and features["entropy"] <= 4.0
        and features["hostname_len"] <= 35
    )

    if _is_clean_homepage(normalized_url, features):
        adjustment -= 0.10
        reasons.append("clean_homepage_discount")

    if low_risk_unknown_domain:
        adjustment -= 0.20
        reasons.append("low_risk_unknown_domain_discount")

    if benign_content_path:
        adjustment -= 0.18
        reasons.append("benign_content_path_discount")

    if benign_commerce_or_content_path:
        adjustment -= 0.12
        reasons.append("benign_commerce_or_content_path_discount")

    if (
        adaptive_safe_match["hostname_match"]
        or adaptive_safe_match["registered_domain_match"]
        or adaptive_safe_match["path_signature_match"]
    ):
        adjustment -= 0.15
        reasons.append("adaptive_safe_pattern_discount")

    if (
        adaptive_threat_match["hostname_match"]
        or adaptive_threat_match["registered_domain_match"]
        or adaptive_threat_match["path_signature_match"]
    ):
        adjustment += 0.25
        reasons.append("adaptive_threat_pattern_boost")

    if security_test_artifact in {"eicar_test_artifact", "security_test_payload"}:
        adjustment += 0.45
        reasons.append("security_test_artifact_boost")

    if features["has_ip"] and not local_dev_context:
        adjustment += 0.28
        reasons.append("public_ip_host_boost")

    if open_redirect_signal:
        adjustment += 0.35
        reasons.append("open_redirect_boost")

    if xss_payload_signal:
        adjustment += 0.45
        reasons.append("xss_payload_boost")

    if sqli_payload_signal:
        adjustment += 0.45
        reasons.append("sqli_payload_boost")

    if local_dev_context == "localhost_loopback":
        adjustment -= 0.35
        reasons.append("localhost_loopback_discount")
    elif local_dev_context == "private_network_host":
        adjustment -= 0.20
        reasons.append("private_network_discount")

    if safe_domain:
        if threat_signals == 0:
            adjustment -= 0.18
            reasons.append("trusted_domain_discount")
        elif threat_signals == 1:
            adjustment -= 0.10
            reasons.append("trusted_domain_soft_discount")
        else:
            reasons.append("trusted_domain_no_override_due_to_threat_signals")

    if threat_signals >= 4:
        adjustment += 0.12
        reasons.append("confirmed_threat_signal_boost")
    elif threat_signals >= 2 and base_prob >= 0.45:
        adjustment += 0.06
        reasons.append("moderate_threat_signal_boost")

    adjusted_prob = max(0.0, min(1.0, base_prob + adjustment))

    if safe_domain and threat_signals == 0:
        adjusted_prob = min(adjusted_prob, 0.20)
        reasons.append("trusted_domain_safe_cap")
    elif xss_payload_signal:
        adjusted_prob = max(adjusted_prob, 0.95)
        reasons.append("xss_payload_cap")
    elif sqli_payload_signal:
        adjusted_prob = max(adjusted_prob, 0.95)
        reasons.append("sqli_payload_cap")
    elif open_redirect_signal and open_redirect_signal.get("target_tld_risk", 0.0) >= 0.6:
        adjusted_prob = max(adjusted_prob, 0.90)
        reasons.append("open_redirect_high_risk_cap")
    elif open_redirect_signal:
        adjusted_prob = max(adjusted_prob, 0.80)
        reasons.append("open_redirect_cap")
    elif local_dev_context == "localhost_loopback" and threat_signals <= 1:
        adjusted_prob = min(adjusted_prob, 0.15)
        reasons.append("localhost_loopback_cap")
    elif local_dev_context == "private_network_host" and threat_signals <= 1:
        adjusted_prob = min(adjusted_prob, 0.25)
        reasons.append("private_network_cap")
    elif (
        adaptive_threat_match["hostname_match"]
        or adaptive_threat_match["registered_domain_match"]
        or adaptive_threat_match["path_signature_match"]
    ):
        adjusted_prob = max(adjusted_prob, 0.85)
        reasons.append("adaptive_threat_pattern_cap")
    elif security_test_artifact in {"eicar_test_artifact", "security_test_payload"}:
        adjusted_prob = max(adjusted_prob, 0.95)
        reasons.append("security_test_artifact_cap")
    elif features["has_ip"] and not local_dev_context:
        adjusted_prob = max(adjusted_prob, 0.88)
        reasons.append("public_ip_host_cap")
    elif safe_domain and threat_signals == 1:
        adjusted_prob = min(adjusted_prob, 0.35)
        reasons.append("trusted_domain_caution_cap")
    elif (
        adaptive_safe_match["hostname_match"]
        or adaptive_safe_match["registered_domain_match"]
        or adaptive_safe_match["path_signature_match"]
    ) and threat_signals == 0:
        adjusted_prob = min(adjusted_prob, 0.30)
        reasons.append("adaptive_safe_pattern_cap")
    elif benign_content_path and benign_commerce_or_content_path and threat_signals == 0:
        adjusted_prob = min(adjusted_prob, 0.35)
        reasons.append("benign_commerce_content_combo_cap")
    elif benign_content_path and threat_signals == 0:
        adjusted_prob = min(adjusted_prob, 0.40)
        reasons.append("benign_content_path_cap")
    elif benign_commerce_or_content_path and threat_signals == 0:
        adjusted_prob = min(adjusted_prob, 0.35)
        reasons.append("benign_commerce_or_content_path_cap")
    elif low_risk_unknown_domain:
        adjusted_prob = min(adjusted_prob, 0.35)
        reasons.append("low_risk_unknown_domain_cap")

    return adjusted_prob, {
        "post_model_adjustment": round(adjustment, 4),
        "threat_confirmation_signals": threat_signals,
        "trusted_domain_match": safe_domain,
        "adaptive_safe_hostname_match": adaptive_safe_match["hostname_match"],
        "adaptive_safe_registered_domain_match": adaptive_safe_match["registered_domain_match"],
        "adaptive_safe_path_signature_match": adaptive_safe_match["path_signature_match"],
        "adaptive_threat_hostname_match": adaptive_threat_match["hostname_match"],
        "adaptive_threat_registered_domain_match": adaptive_threat_match["registered_domain_match"],
        "adaptive_threat_path_signature_match": adaptive_threat_match["path_signature_match"],
        "security_test_artifact": security_test_artifact,
        "local_dev_context": local_dev_context,
        "open_redirect_signal": open_redirect_signal,
        "xss_payload_signal": xss_payload_signal,
        "sqli_payload_signal": sqli_payload_signal,
        "benign_tracking_link": benign_tracking_link,
        "benign_content_path": benign_content_path,
        "benign_commerce_or_content_path": benign_commerce_or_content_path,
        "low_risk_unknown_domain": low_risk_unknown_domain,
        "adjustment_reasons": reasons,
    }


def predict_url(url: str) -> dict:
    normalized_url = normalize_url_for_detection(url)
    features = extract_features(url)

    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    
    # ============================================================
    # 🟢 HARD WHITELIST OVERRIDE: Safe Brand Domains = INSTANT SAFE
    # ============================================================

    
    # ============================================================
    # Machine Learning Prediction (for non-whitelisted domains)
    # ============================================================
    
    # Check TLD risk and apply adjustments
    tld_risk = _get_tld_risk_score(hostname)
    red_flag_penalty = 0.0
    
    if tld_risk > 0.7:  # Dangerous TLDs
        red_flag_penalty = 0.15
    
    # Homograph attack detection
    homograph_risk = _detect_homograph_risk(hostname)
    if homograph_risk > 0.3:
        red_flag_penalty = max(red_flag_penalty, 0.20)
    
    # Brand impersonation check
    brand_impersonation = _get_brand_impersonation_score(hostname)
    if brand_impersonation > 0.5:
        red_flag_penalty = max(red_flag_penalty, 0.15)

    frame = pd.DataFrame([features])[feature_names]
    scaled = pd.DataFrame(
        scaler.transform(frame),
        columns=feature_names,
        index=frame.index,
    )

    lgbm_prob = float(lgbm.predict_proba(scaled)[0][1])
    xgb_prob = float(xgb.predict_proba(scaled)[0][1])
    avg_prob = (lgbm_prob + xgb_prob) / 2
    
    # Layer 1: model score plus direct red-flag penalty.
    model_prob = max(0.0, min(1.0, avg_prob + red_flag_penalty))

    # Layer 2: confirm threat or trusted-domain signals before final verdict.
    adjusted_prob, post_model_details = _compute_post_model_adjustment(
        normalized_url,
        hostname,
        features,
        model_prob,
        tld_risk,
        homograph_risk,
        brand_impersonation,
    )

    risk_score = normalize_risk_score(adjusted_prob * 100)
    confidence = probability_confidence(adjusted_prob)
    status = classify_status(risk_score, THREAT_THRESHOLD, SUSPICIOUS_THRESHOLD)
    verdict = "MALICIOUS" if status == "threat" else ("SUSPICIOUS" if status == "suspicious" else "BENIGN")
    predicted_class = "malicious" if adjusted_prob >= 0.5 else "benign"
    decision_threshold = round(THREAT_THRESHOLD, 2)
    model_agreement = "high" if abs(lgbm_prob - xgb_prob) <= 0.15 else "mixed"
    
    key_features = {
        "keyword_count": features["keyword_count"],
        "entropy": features["entropy"],
        "has_ip": bool(features["has_ip"]),
        "is_trash_tld": bool(features["is_trash_tld"]),
        "subdomain_count": features["subdomain_count"],
        "path_depth": features["path_depth"],
        "tld_risk_score": round(tld_risk, 3),
        "homograph_risk": round(homograph_risk, 3),
        "brand_impersonation_risk": round(brand_impersonation, 3),
        "original_prob": round(avg_prob, 4),
        "model_prob": round(model_prob, 4),
        "adjusted_prob": round(adjusted_prob, 4),
        "post_model_adjustment": post_model_details["post_model_adjustment"],
        "threat_confirmation_signals": post_model_details["threat_confirmation_signals"],
        "trusted_domain_match": post_model_details["trusted_domain_match"],
        "adaptive_safe_hostname_match": post_model_details["adaptive_safe_hostname_match"],
        "adaptive_safe_registered_domain_match": post_model_details["adaptive_safe_registered_domain_match"],
        "adaptive_safe_path_signature_match": post_model_details["adaptive_safe_path_signature_match"],
        "adaptive_threat_hostname_match": post_model_details["adaptive_threat_hostname_match"],
        "adaptive_threat_registered_domain_match": post_model_details["adaptive_threat_registered_domain_match"],
        "adaptive_threat_path_signature_match": post_model_details["adaptive_threat_path_signature_match"],
        "security_test_artifact": post_model_details["security_test_artifact"],
        "local_dev_context": post_model_details["local_dev_context"],
        "open_redirect_signal": post_model_details["open_redirect_signal"],
        "xss_payload_signal": post_model_details["xss_payload_signal"],
        "sqli_payload_signal": post_model_details["sqli_payload_signal"],
        "benign_tracking_link": post_model_details["benign_tracking_link"],
        "benign_content_path": post_model_details["benign_content_path"],
        "benign_commerce_or_content_path": post_model_details["benign_commerce_or_content_path"],
        "low_risk_unknown_domain": post_model_details["low_risk_unknown_domain"],
        "adjustment_reasons": post_model_details["adjustment_reasons"],
    }

    _auto_promote_url_pattern(
        hostname,
        normalized_url,
        features,
        risk_score,
        post_model_details["threat_confirmation_signals"],
        post_model_details,
    )

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
