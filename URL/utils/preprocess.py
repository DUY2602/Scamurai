from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, urlparse

import pandas as pd
from tqdm import tqdm


SUSPICIOUS_KEYWORDS = (
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
    "wallet",
    "invoice",
    "payment",
    "auth",
)
TRASH_TLDS = (".tk", ".xyz", ".cc", ".top", ".pw", ".online", ".site", ".biz")
POPULAR_TLDS = (".com", ".net", ".org", ".co", ".edu", ".gov", ".info", ".edu.vn")
EXECUTABLE_EXTENSIONS = (".exe", ".apk", ".msi", ".bin", ".js", ".vbs", ".scr", ".zip")
COMMON_SECOND_LEVEL_TLDS = {"co.uk", "org.uk", "gov.uk", "com.au", "com.vn", "co.jp", "com.sg"}


def get_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(char) / len(text) for char in set(text)]
    return -sum(probability * math.log2(probability) for probability in probs)


def normalize_url(url: str) -> tuple[str, object]:
    raw = str(url or "").strip().lower().replace("[", "").replace("]", "")
    address = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlparse(address)
    except Exception:
        parsed = urlparse("http://error-url.com")
    return address, parsed


def extract_registered_domain(hostname: str) -> str:
    host = (hostname or "").strip().lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host:
        return host

    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return host

    tail = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:]) if len(parts) >= 3 else tail
    if tail in {"uk", "au", "jp", "sg", "vn"} and tail3.endswith(tuple(COMMON_SECOND_LEVEL_TLDS)):
        return tail3
    return tail


def is_academic_domain(hostname: str) -> int:
    host = (hostname or "").lower()
    return int(host.endswith(".edu") or host.endswith(".edu.vn") or ".ac." in host)


def analyze_path_segments(path: str) -> dict[str, int]:
    segments = [segment for segment in str(path or "").split("/") if segment]
    numeric_segments = [segment for segment in segments if segment.isdigit()]
    long_numeric_segments = [segment for segment in numeric_segments if len(segment) >= 8]
    clean_alpha_segments = [
        segment for segment in segments if re.fullmatch(r"[a-z]{1,12}", segment or "") and segment not in SUSPICIOUS_KEYWORDS
    ]

    return {
        "numeric_path_segment_count": len(numeric_segments),
        "long_numeric_path_segment_count": len(long_numeric_segments),
        "alpha_path_segment_count": len(clean_alpha_segments),
        "has_single_resource_id_path": int(
            len(segments) in {1, 2}
            and len(long_numeric_segments) == 1
            and len(clean_alpha_segments) >= 1
            and len(numeric_segments) == 1
        ),
        "has_mixed_clean_path": int(
            len(segments) <= 3
            and len(long_numeric_segments) <= 1
            and not any(re.search(r"(login|verify|secure|update|confirm|password)", segment) for segment in segments)
        ),
    }


def extract_features(url: str) -> dict[str, object]:
    normalized_url, parsed = normalize_url(url)
    hostname = parsed.netloc.split("@")[-1].split(":")[0].replace("www.", "")
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = f"{hostname}{path}"
    if query:
        full_url = f"{full_url}?{query}"
    registered_domain = extract_registered_domain(hostname)
    query_pairs = parse_qsl(query, keep_blank_values=True)
    path_analysis = analyze_path_segments(path)

    return {
        "normalized_url": normalized_url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "url_len": len(full_url),
        "hostname_len": len(hostname),
        "path_len": len(path),
        "query_len": len(query),
        "dot_count": full_url.count("."),
        "dash_count": hostname.count("-"),
        "underscore_count": full_url.count("_"),
        "digit_ratio": len(re.findall(r"\d", full_url)) / (len(full_url) + 1),
        "entropy": get_entropy(full_url),
        "is_trash_tld": int(hostname.endswith(TRASH_TLDS)),
        "is_popular_tld": int(any(hostname.endswith(tld) for tld in POPULAR_TLDS)),
        "has_ip": int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname))),
        "is_exec": int(bool(re.search(r"\.(exe|apk|msi|bin|js|vbs|scr|zip)$", path))),
        "keyword_count": sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in full_url),
        "subdomain_count": max(0, len([part for part in hostname.split(".") if part]) - 2),
        "special_ratio": sum(full_url.count(char) for char in ["-", ".", "_", "@", "?", "&", "="]) / (len(full_url) + 1),
        "has_number_in_host": int(any(char.isdigit() for char in hostname)),
        "is_https": int(parsed.scheme == "https"),
        "path_depth": len([segment for segment in path.split("/") if segment]),
        "query_param_count": len(query_pairs),
        "percent_encoding_count": query.count("%"),
        "hostname_token_count": len([token for token in re.split(r"[^a-z0-9]+", hostname) if token]),
        "path_token_count": len([token for token in re.split(r"[^a-z0-9]+", path) if token]),
        "registered_domain_len": len(registered_domain),
        "tld_len": len(hostname.rsplit(".", 1)[-1]) if "." in hostname else 0,
        "is_academic_domain": is_academic_domain(hostname),
        "has_suspicious_file_ext": int(path.endswith(EXECUTABLE_EXTENSIONS)),
        **path_analysis,
    }


def process_and_save_csv(input_path: str, output_path: str) -> None:
    print(f"Loading data from: {input_path}")
    try:
        df = pd.read_csv(input_path)
    except Exception as exc:
        print(f"Error reading file: {exc}")
        return

    label_col = next((column for column in df.columns if column.lower() in ["type", "label", "target"]), None)
    if "url" not in df.columns or not label_col:
        print("Error: Need 'url' and a label column.")
        return

    print(f"Extracting URL features for {len(df)} rows...")
    all_features: list[dict[str, object]] = []

    for _, row in tqdm(df.iterrows(), total=len(df)):
        features = extract_features(row["url"])
        original_label = str(row[label_col]).lower()
        features["target"] = "benign" if original_label == "benign" else "harm"
        features["url"] = row["url"]
        all_features.append(features)

    processed = pd.DataFrame(all_features)
    ordered_columns = ["url", "target", "hostname", "registered_domain", "normalized_url"] + [
        column for column in processed.columns if column not in {"url", "target", "hostname", "registered_domain", "normalized_url"}
    ]
    processed = processed[ordered_columns]
    processed.to_csv(output_path, index=False, encoding="utf-8")
    print(f"Saved processed file at: {output_path}")


if __name__ == "__main__":
    process_and_save_csv("URL/data/malicious_url.csv", "URL/data/processed_malicious_url.csv")
