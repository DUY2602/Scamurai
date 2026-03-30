"""Signal analyzers for headers, URLs, language, HTML, and attachments."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from config import (
    ASSET_URL_HOST_BLOCKLIST,
    LEADING_URL_PUNCTUATION,
    MARKETING_KEYWORDS,
    MARKETING_SIGNALS,
    PHISHING_KEYWORDS,
    RISKY_COMPRESSED_EXTENSIONS,
    RISKY_EXECUTABLE_EXTENSIONS,
    RISKY_MACRO_EXTENSIONS,
    SUSPICIOUS_TLDS,
    TRACKING_HINTS,
    TRAILING_URL_PUNCTUATION,
    TRANSACTIONAL_SYSTEM_KEYWORDS,
    TRANSACTIONAL_SYSTEM_PHRASES,
    TRUSTED_OFFICIAL_DOMAINS,
    URL_REGEX,
)
from services.email_parser import extract_domain_from_header
from services.text_processing import unique_preserve_order


def is_academic_domain(domain: str) -> bool:
    """Heuristic for academic domains."""
    return domain.endswith(".edu") or domain.endswith(".edu.vn") or ".ac." in domain


def domain_matches_suffix(domain: str, suffix: str) -> bool:
    """Check if domain matches suffix exactly or as subdomain."""
    return domain == suffix or domain.endswith(f".{suffix}")


def domains_related(domain_a: str, domain_b: str) -> bool:
    """Check if two domains are equivalent or subdomains of each other."""
    if not domain_a or not domain_b:
        return False
    return domain_matches_suffix(domain_a, domain_b) or domain_matches_suffix(domain_b, domain_a)


def is_official_looking_domain(domain: str) -> bool:
    """Heuristic for trusted/official looking domains."""
    if domain.endswith(".gov") or domain.endswith(".mil") or domain.endswith(".gov.vn"):
        return True
    if any(domain_matches_suffix(domain, suffix) for suffix in TRUSTED_OFFICIAL_DOMAINS):
        return True
    return False


def analyze_headers(sender: str, reply_to: str, return_path: str) -> dict[str, Any]:
    """Analyze sender/reply headers and return flags + normalized domains."""
    from_domain = extract_domain_from_header(sender)
    reply_domain = extract_domain_from_header(reply_to)
    return_domain = extract_domain_from_header(return_path)
    header_context_present = bool((sender or "").strip() or (reply_to or "").strip() or (return_path or "").strip())

    flags: list[str] = []
    if header_context_present and not from_domain:
        flags.append("Missing sender domain.")

    reply_mismatch = bool(from_domain and reply_domain and not domains_related(reply_domain, from_domain))
    return_path_mismatch = bool(from_domain and return_domain and not domains_related(return_domain, from_domain))

    if reply_mismatch:
        flags.append("Reply-To domain differs from sender domain.")
    if return_path_mismatch:
        flags.append("Return-Path domain differs from sender domain.")

    academic = bool(from_domain and is_academic_domain(from_domain))
    official = bool(from_domain and is_official_looking_domain(from_domain))
    if official:
        flags.append("Trusted sender domain pattern detected.")
    if academic:
        flags.append("Academic domain detected.")

    return {
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "header_flags": unique_preserve_order(flags),
        "is_academic": academic,
        "is_official": official,
        "reply_mismatch": reply_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "missing_sender_domain": not bool(from_domain),
        "header_context_present": header_context_present,
    }


def normalize_url_candidate(url: str) -> str:
    """Trim common surrounding punctuation from URL candidates."""
    return url.strip().lstrip(LEADING_URL_PUNCTUATION).rstrip(TRAILING_URL_PUNCTUATION)


def parse_url_like(url: str):
    """Parse URL while tolerating bare www links."""
    target = url if re.match(r"^https?://", url, flags=re.IGNORECASE) else f"http://{url}"
    return urlparse(target)


def is_meaningful_url(url: str) -> bool:
    """Filter out malformed or obvious asset URLs."""
    if not url:
        return False
    parsed = parse_url_like(url)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        return False
    if host in ASSET_URL_HOST_BLOCKLIST:
        return False
    return True


def is_tracking_url(url: str) -> bool:
    """Detect common redirect/tracking URL patterns."""
    lowered = url.lower()
    if any(hint in lowered for hint in TRACKING_HINTS):
        return True
    parsed = parse_url_like(url)
    return any(segment in parsed.path.lower() for segment in ("/redirect", "/out", "/click"))


def is_ip_hostname(hostname: str) -> bool:
    """Check whether hostname is a raw IP address."""
    if not hostname:
        return False
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_suspicious_url(url: str) -> bool:
    """Heuristic URL risk checks."""
    parsed = parse_url_like(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False

    tld = host.split(".")[-1] if "." in host else ""
    structural_oddity = host.count(".") >= 5 and not any(
        domain_matches_suffix(host, suffix) for suffix in TRUSTED_OFFICIAL_DOMAINS
    )
    checks = [
        is_ip_hostname(host),
        host.count("-") >= 4,
        len(host) >= 45,
        tld in SUSPICIOUS_TLDS,
        bool(re.search(r"[a-z]{3,}\d{4,}", host)),
        structural_oddity,
    ]
    return any(checks)


def extract_urls(text: str) -> list[str]:
    """Extract normalized, meaningful URLs from original text."""
    raw_urls = URL_REGEX.findall(text)
    output: list[str] = []
    seen: set[str] = set()

    for raw in raw_urls:
        url = normalize_url_candidate(raw)
        if not is_meaningful_url(url):
            continue
        key = url.lower().rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        output.append(url)

    return output


def analyze_urls(original_text: str) -> dict[str, Any]:
    """Run URL extraction + URL-level risk checks."""
    urls = extract_urls(original_text)
    suspicious_urls = [url for url in urls if is_suspicious_url(url)]
    tracking_detected = any(is_tracking_url(url) for url in urls)

    url_flags: list[str] = []
    if urls:
        url_flags.append("Contains URLs.")
    if len(urls) >= 4:
        url_flags.append("Multiple external links detected.")
    if tracking_detected:
        url_flags.append("Tracked redirect links detected.")
        if not suspicious_urls:
            url_flags.append("Tracking links detected, but no strongly suspicious URL structure found.")
    if suspicious_urls:
        url_flags.append("Potentially suspicious URL patterns detected.")

    return {
        "extracted_urls": urls,
        "suspicious_urls": unique_preserve_order(suspicious_urls),
        "url_count": len(urls),
        "tracking_detected": tracking_detected,
        "url_flags": unique_preserve_order(url_flags),
    }


def analyze_attachments(attachment_names: list[str], attachment_extensions: list[str]) -> dict[str, Any]:
    """Analyze attachment metadata only (no execution)."""
    normalized_extensions = unique_preserve_order([ext.lower() for ext in attachment_extensions if ext])
    flags: list[str] = []

    ext_set = set(normalized_extensions)
    has_exec = bool(ext_set & RISKY_EXECUTABLE_EXTENSIONS)
    has_compressed = bool(ext_set & RISKY_COMPRESSED_EXTENSIONS)
    has_macro = bool(ext_set & RISKY_MACRO_EXTENSIONS)

    if has_exec:
        flags.append("Executable attachment type detected.")
    if has_compressed:
        flags.append("Compressed attachment detected.")
    if has_macro:
        flags.append("Macro-enabled Office attachment detected.")

    return {
        "attachment_count": len(attachment_names),
        "attachment_names": attachment_names,
        "attachment_extensions": normalized_extensions,
        "attachment_flags": unique_preserve_order(flags),
        "has_risky_exec": has_exec,
        "has_compressed": has_compressed,
        "has_macro": has_macro,
    }


def analyze_language(cleaned_text: str) -> dict[str, Any]:
    """Run lightweight phishing/marketing keyword analysis."""
    tokens = set(cleaned_text.split())
    phishing_hits = sorted([keyword for keyword in PHISHING_KEYWORDS if keyword in tokens])
    marketing_hits = sorted([keyword for keyword in MARKETING_KEYWORDS if keyword in tokens])
    transactional_keyword_hits = sorted([keyword for keyword in TRANSACTIONAL_SYSTEM_KEYWORDS if keyword in tokens])
    transactional_phrase_hits = sorted([phrase for phrase in TRANSACTIONAL_SYSTEM_PHRASES if phrase in cleaned_text])
    transactional_hits = unique_preserve_order(transactional_phrase_hits + transactional_keyword_hits)
    has_transactional = bool(transactional_phrase_hits) or len(transactional_keyword_hits) >= 2

    # Avoid over-penalizing common words like "account" in legitimate transactional emails.
    has_phishing = len(phishing_hits) >= 2

    flags: list[str] = []
    if has_phishing:
        flags.append("Phishing-like language detected.")
    elif phishing_hits:
        flags.append("Low-confidence phishing terms detected.")
    else:
        flags.append("No strong phishing keywords detected.")
    if marketing_hits:
        flags.append("Marketing/promotional language detected.")
    if has_transactional:
        flags.append("Transactional/system notification pattern detected.")

    return {
        "phishing_hits": phishing_hits,
        "marketing_hits": marketing_hits,
        "transactional_hits": transactional_hits,
        "has_phishing": has_phishing,
        "has_marketing": bool(marketing_hits),
        "has_transactional": has_transactional,
        "language_flags": unique_preserve_order(flags),
    }


def analyze_html_signals(
    has_html: bool,
    url_count: int,
    has_phishing: bool,
    has_marketing: bool,
    cleaned_text: str,
) -> dict[str, Any]:
    """Analyze HTML-specific content patterns."""
    html_flags: list[str] = []
    newsletter_like = False

    if has_html:
        html_flags.append("HTML email detected.")

    if has_html and url_count >= 2 and has_marketing and not has_phishing:
        newsletter_like = True
        html_flags.append("Marketing/newsletter-style email detected.")
    elif has_html and not has_phishing and any(signal in cleaned_text for signal in MARKETING_SIGNALS):
        newsletter_like = True
        html_flags.append("Marketing/newsletter-style email detected.")

    return {
        "html_flags": unique_preserve_order(html_flags),
        "newsletter_like": newsletter_like,
    }
