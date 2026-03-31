from __future__ import annotations

from dataclasses import dataclass


TOP_BRAND_DOMAINS = {
    "google.com": "google",
    "github.com": "github",
    "youtube.com": "youtube",
    "microsoft.com": "microsoft",
    "paypal.com": "paypal",
    "apple.com": "apple",
    "amazon.com": "amazon",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "linkedin.com": "linkedin",
    "dropbox.com": "dropbox",
    "docusign.com": "docusign",
    "adobe.com": "adobe",
    "office.com": "microsoft",
    "outlook.com": "microsoft",
    "live.com": "microsoft",
    "netflix.com": "netflix",
    "bankofamerica.com": "bankofamerica",
    "wellsfargo.com": "wellsfargo",
    "chase.com": "chase",
}
TLD_RISK_TABLE = {
    "com": 0.0,
    "org": 0.05,
    "net": 0.08,
    "edu": 0.05,
    "gov": 0.02,
    "vn": 0.08,
    "info": 0.25,
    "biz": 0.35,
    "site": 0.45,
    "online": 0.45,
    "work": 0.65,
    "xyz": 0.7,
    "click": 0.8,
    "top": 0.85,
    "tk": 0.9,
    "cf": 0.9,
    "ga": 0.9,
    "ml": 0.9,
    "ru": 0.65,
}


@dataclass(frozen=True)
class UrlRiskFeatures:
    brand_impersonation_score: float
    typosquat_distance: float
    tld_risk_score: float
    subdomain_brand_mismatch: int

    def as_dict(self) -> dict[str, float | int]:
        return {
            "brand_impersonation_score": round(float(self.brand_impersonation_score), 4),
            "typosquat_distance": round(float(self.typosquat_distance), 4),
            "tld_risk_score": round(float(self.tld_risk_score), 4),
            "subdomain_brand_mismatch": int(self.subdomain_brand_mismatch),
        }


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            insert_cost = current[right_index - 1] + 1
            delete_cost = previous[right_index] + 1
            replace_cost = previous[right_index - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _extract_brand_hits(hostname: str, registered_domain: str) -> list[tuple[str, str]]:
    lowered_host = str(hostname or "").lower()
    lowered_registered = str(registered_domain or "").lower()
    hits: list[tuple[str, str]] = []
    for official_domain, brand_name in TOP_BRAND_DOMAINS.items():
        brand_token = brand_name.lower()
        if brand_token in lowered_host and official_domain != lowered_registered:
            hits.append((official_domain, brand_name))
    return hits


def _compute_typosquat_distance(hostname: str) -> float:
    host = str(hostname or "").lower()
    if not host:
        return 1.0

    min_distance = 1.0
    for official_domain, brand_name in TOP_BRAND_DOMAINS.items():
        host_token = host.split(".")[0]
        candidate_token = brand_name.lower()
        if not host_token or not candidate_token:
            continue
        distance = levenshtein_distance(host_token, candidate_token)
        normalized = distance / max(len(host_token), len(candidate_token), 1)
        min_distance = min(min_distance, normalized)
    return min_distance


def build_url_risk_features(hostname: str, registered_domain: str) -> dict[str, float | int]:
    host = str(hostname or "").strip().lower()
    registered = str(registered_domain or "").strip().lower()
    host_parts = [part for part in host.split(".") if part]
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
    tld = host_parts[-1] if host_parts else ""

    brand_hits = _extract_brand_hits(host, registered)
    subdomain_brand_mismatch = int(bool(subdomain and brand_hits))

    brand_impersonation_score = 0.0
    if brand_hits:
        brand_impersonation_score += 0.6
    if subdomain_brand_mismatch:
        brand_impersonation_score += 0.25
    if "-" in host and brand_hits:
        brand_impersonation_score += 0.15

    typosquat_distance = _compute_typosquat_distance(host)
    tld_risk_score = TLD_RISK_TABLE.get(tld, 0.15)

    features = UrlRiskFeatures(
        brand_impersonation_score=min(1.0, brand_impersonation_score),
        typosquat_distance=typosquat_distance,
        tld_risk_score=tld_risk_score,
        subdomain_brand_mismatch=subdomain_brand_mismatch,
    )
    return features.as_dict()
