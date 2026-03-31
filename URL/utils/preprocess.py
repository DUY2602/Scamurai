import math
import re
from urllib.parse import urlparse

import pandas as pd

FEATURE_COLUMNS = [
    "url_len",
    "hostname_len",
    "dot_count",
    "dash_count",
    "digit_ratio",
    "entropy",
    "is_trash_tld",
    "is_popular_tld",
    "has_ip",
    "is_exec",
    "keyword_count",
    "subdomain_count",
    "special_ratio",
    "has_number_in_host",
    "has_at_symbol",
    "path_depth",
    "has_redirect",
    "brand_in_subdomain",
    "tld_in_path",
    "query_param_count",
    "has_hex_encoding",
]

KEYWORDS = ["login", "verify", "update", "secure", "account", "banking", "signin", "confirm", "bank"]
TRASH_TLDS = (".tk", ".xyz", ".cc", ".top", ".pw", ".online", ".site", ".biz")
POPULAR_TLDS = (".com", ".net", ".org", ".co", ".edu", ".gov", ".info")
BRAND_KEYWORDS = ["google", "paypal", "apple", "microsoft", "amazon", "bank", "secure", "login", "verify"]
PATH_TLD_MARKERS = (".com", ".net", ".org", ".io")


def get_entropy(text):
    if not text:
        return 0.0
    probs = [text.count(char) / len(text) for char in set(text)]
    return float(-sum(probability * math.log2(probability) for probability in probs))


def extract_features(url):
    normalized = str(url).strip().lower().replace("[", "").replace("]", "")
    address = normalized if "://" in normalized else f"http://{normalized}"

    try:
        parsed = urlparse(address)
    except Exception:
        parsed = urlparse("http://error-url.com")

    hostname = parsed.netloc.replace("www.", "")
    host_without_auth = hostname.split("@")[-1]
    host_without_port = host_without_auth.split(":")[0]
    host_parts = [part for part in host_without_port.split(".") if part]
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
    path_only = parsed.path or ""
    query_only = parsed.query or ""
    path = f"{path_only}{query_only}"
    full_url = f"{hostname}{path}"
    remainder = address.split("://", 1)[1] if "://" in address else address

    query_param_count = 0
    if query_only:
        query_param_count = len([part for part in query_only.split("&") if part])

    return {
        "url_len": len(full_url),
        "hostname_len": len(hostname),
        "dot_count": full_url.count("."),
        "dash_count": hostname.count("-"),
        "digit_ratio": len(re.findall(r"\d", full_url)) / (len(full_url) + 1),
        "entropy": round(get_entropy(full_url), 6),
        "is_trash_tld": int(host_without_port.endswith(TRASH_TLDS)),
        "is_popular_tld": int(any(host_without_port.endswith(tld) for tld in POPULAR_TLDS)),
        "has_ip": int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", host_without_port))),
        "is_exec": int(bool(re.search(r"\.(exe|apk|msi|bin|js|vbs|scr|zip)$", path_only))),
        "keyword_count": sum(1 for keyword in KEYWORDS if keyword in full_url),
        "subdomain_count": len(host_parts) - 2 if len(host_parts) > 2 else 0,
        "special_ratio": sum(full_url.count(char) for char in ["-", ".", "_", "@", "?", "&", "="]) / (len(full_url) + 1),
        "has_number_in_host": int(any(char.isdigit() for char in hostname)),
        "has_at_symbol": int("@" in normalized),
        "path_depth": path_only.count("/"),
        "has_redirect": int("//" in remainder),
        "brand_in_subdomain": int(any(brand in subdomain for brand in BRAND_KEYWORDS)),
        "tld_in_path": int(any(marker in path_only for marker in PATH_TLD_MARKERS)),
        "query_param_count": query_param_count,
        "has_hex_encoding": int("%" in address),
    }


def process_and_save_csv(input_path, output_path):
    print(f"Loading data from: {input_path}")
    try:
        df = pd.read_csv(input_path)
    except Exception as exc:
        print(f"Error reading file: {exc}")
        return

    label_col = next((column for column in df.columns if column.lower() in ["type", "label", "target"]), None)
    if "url" not in df.columns or not label_col:
        print("Error: input must include 'url' and a label column.")
        return

    print(f"Extracting {len(FEATURE_COLUMNS)} features for {len(df)} rows...")
    rows = []
    for url_value, label_value in zip(df["url"], df[label_col]):
        feature_row = extract_features(url_value)
        feature_row["target"] = "benign" if str(label_value).lower() == "benign" else "harm"
        feature_row["url"] = url_value
        rows.append(feature_row)

    new_df = pd.DataFrame(rows)
    new_df = new_df[["url", "target", *FEATURE_COLUMNS]]
    new_df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"Saved processed file at: {output_path}")


if __name__ == "__main__":
    process_and_save_csv("URL/data/malicious_url.csv", "URL/data/processed_malicious_url.csv")
