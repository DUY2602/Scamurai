"""FastAPI backend for hybrid multi-signal email threat analysis."""

from __future__ import annotations

from collections import Counter
from contextlib import asynccontextmanager
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from functools import lru_cache
from html import unescape
import os
import ipaddress
import math
from pathlib import Path
import re
import sys
import tempfile
from typing import Any
from urllib.parse import parse_qsl, urlparse

import joblib
import pandas as pd
import pefile
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


BACKEND_DIR = Path(__file__).resolve().parent
MODEL_PATH = BACKEND_DIR / "spam_model.joblib"
DEFAULT_THRESHOLD = 0.5
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_UPLOAD_LABEL = f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB"
REPO_ROOT = BACKEND_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
FILE_MODELS_DIR = REPO_ROOT / "FILE" / "models"
URL_MODELS_DIR = REPO_ROOT / "URL" / "models"
try:
    from Email import predict as email_predict_module
except Exception as exc:  # pragma: no cover - runtime fallback only
    email_predict_module = None
    EMAIL_PREDICT_IMPORT_ERROR = str(exc)
else:
    EMAIL_PREDICT_IMPORT_ERROR = None
try:
    from FILE.utils import preprocess as file_preprocess
except Exception:  # pragma: no cover - runtime fallback only
    file_preprocess = None
FILE_SENSITIVE_APIS = {
    b"CreateRemoteThread",
    b"WriteProcessMemory",
    b"VirtualAllocEx",
    b"InternetOpen",
    b"HttpSendRequest",
    b"GetKeyboardState",
    b"SetWindowsHookEx",
    b"ShellExecuteA",
    b"IsDebuggerPresent",
}
FILE_FEATURE_COLUMNS = [
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
URL_HARMFUL_LABELS = {"malicious", "harm", "phishing", "defacement", "malware", "dangerous"}

HAM_MAX_THRESHOLD = 30.0
SUSPICIOUS_MAX_THRESHOLD = 60.0
THREAT_BASE_THRESHOLD = 82.0
THREAT_SPAM_PROB_THRESHOLD = 0.85
THREAT_HARD_THRESHOLD = 90.0

URL_REGEX = re.compile(r"http[s]?://\S+|www\.\S+", flags=re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", flags=re.IGNORECASE)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
HTML_COMMENT_REGEX = re.compile(r"<!--.*?-->", flags=re.IGNORECASE | re.DOTALL)
HTML_STYLE_REGEX = re.compile(r"<style\b[^>]*>.*?</style>", flags=re.IGNORECASE | re.DOTALL)
HTML_SCRIPT_REGEX = re.compile(r"<script\b[^>]*>.*?</script>", flags=re.IGNORECASE | re.DOTALL)
HTML_BREAK_TAG_REGEX = re.compile(
    r"<\s*(?:br|p|/p|div|/div|li|/li|tr|/tr|h[1-6]|/h[1-6]|table|/table|ul|/ul|ol|/ol|hr)\b[^>]*>",
    flags=re.IGNORECASE,
)
HTML_ATTR_URL_REGEX = re.compile(
    r"""(?is)\b(?:href|src)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'<>`]+))"""
)
HTML_MARKUP_REGEX = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")
NON_ALNUM_REGEX = re.compile(r"[^a-z0-9\s]+")
MULTISPACE_REGEX = re.compile(r"\s+")
SUBJECT_REGEX = re.compile(r"(?im)^subject:\s*(.*)$")
INVISIBLE_CHAR_REGEX = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]")
CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x1F\x7F]")

TRAILING_URL_PUNCTUATION = ")]}.,;:'\"!?`"
LEADING_URL_PUNCTUATION = "([{<'\""
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "work", "gq", "tk", "cf", "ml", "ga", "ru"}

TRACKING_HINTS = ("utm_", "redirect", "trk", "track", "click", "ref=", "fbclid", "gclid", "mc_eid")
IGNORED_EMBEDDED_URL_PREFIXES = ("javascript:", "mailto:", "tel:", "cid:", "data:", "#")
ASSET_FILE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".bmp",
    ".ico",
    ".avif",
    ".tif",
    ".tiff",
    ".apng",
    ".heic",
    ".heif",
}
LOW_PRIORITY_ASSET_HOST_SUFFIXES = {
    "braze-images.com",
    "cdn.braze.eu",
    "fonts.gstatic.com",
    "fonts.googleapis.com",
    "gravatar.com",
}
LOW_PRIORITY_SOCIAL_HOST_SUFFIXES = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "youtube.com",
    "tiktok.com",
    "pinterest.com",
}
LOW_PRIORITY_APP_BADGE_HOST_SUFFIXES = {"apps.apple.com", "play.google.com"}
ASSET_PATH_HINTS = (
    "/image",
    "/images/",
    "/img/",
    "/assets/",
    "/static/",
    "/media/",
    "/logo",
    "/icon",
    "/banner",
    "/badge",
    "/pixel",
    "/tracking",
    "/thumbnail",
    "/thumb",
)

PHISHING_KEYWORDS = {
    "urgent",
    "verify",
    "account",
    "password",
    "bank",
    "suspended",
    "login",
    "confirm",
    "security",
    "recovery",
}
MARKETING_KEYWORDS = {
    "register",
    "event",
    "ticket",
    "sale",
    "offer",
    "subscribe",
    "newsletter",
    "limited",
    "shop",
    "discount",
}
MARKETING_SIGNALS = (
    "unsubscribe",
    "newsletter",
    "promotion",
    "special offer",
    "limited time",
    "view in browser",
    "opt out",
    "manage preferences",
    "coupon",
    "sale",
    "deal",
)

RISKY_EXECUTABLE_EXTENSIONS = {".exe", ".js", ".scr", ".bat", ".cmd", ".ps1", ".vbs"}
RISKY_COMPRESSED_EXTENSIONS = {".zip", ".rar", ".7z"}
RISKY_MACRO_EXTENSIONS = {".docm", ".xlsm"}

TRUSTED_OFFICIAL_DOMAINS = {
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "outlook.com",
    "gmail.com",
    "railway.com",
    "upwork.com",
    "github.com",
    "roblox.com",
}
TRUSTED_BRAND_KEYWORDS = {domain.split(".")[0] for domain in TRUSTED_OFFICIAL_DOMAINS}
GIVEAWAY_KEYWORDS = {"free", "winner", "iphone", "prize", "claim", "gift", "bonus", "promo", "selected", "won"}
FILE_INSTALLER_NAME_HINTS = ("setup", "install", "installer", "update")
FILE_REFERENCE_BENIGN_BINARIES = ("notepad.exe", "calc.exe", "cmd.exe")

TRANSACTIONAL_SYSTEM_KEYWORDS = {
    "build",
    "failed",
    "deployment",
    "notification",
    "alert",
    "receipt",
    "invoice",
    "statement",
    "policy",
    "privacy",
    "agreement",
    "password",
    "reset",
    "verification",
    "code",
    "login",
    "recovery",
    "account",
    "activity",
    "billing",
    "support",
    "project",
    "environment",
}
TRANSACTIONAL_SYSTEM_PHRASES = (
    "password reset",
    "verification code",
    "login alert",
    "account activity",
    "security update",
    "policy update",
    "build failed",
    "deployment failed",
)

URGENCY_CUE_KEYWORDS = {"urgent", "immediately", "immediate", "asap", "now", "today", "suspended"}
CREDENTIAL_HARVESTING_KEYWORDS = {
    "verify",
    "verification",
    "login",
    "password",
    "credential",
    "account",
    "confirm",
    "security",
    "reset",
}
CREDENTIAL_STRONG_KEYWORDS = {"verify", "verification", "password", "credential", "confirm", "reset", "unlock", "restore"}

REDIRECT_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "lnkd.in",
    "cutt.ly",
    "rebrand.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "goo.gl",
    "tiny.cc",
}
TRUSTED_REDIRECT_DOMAINS = {"c.gle", "aka.ms", "mailchi.mp"}

SUSPICIOUS_DOMAIN_KEYWORDS = {
    "verify",
    "secure",
    "support",
    "login",
    "account",
    "docs",
    "document",
    "billing",
    "invoice",
    "update",
    "portal",
    "workspace",
    "share",
    "shared",
    "password",
    "auth",
    "access",
    "notification",
    "records",
    "staff",
    "payment",
}

BRAND_DOMAIN_MAP: dict[str, set[str]] = {
    "google": {"google.com", "googlemail.com", "withgoogle.com", "youtube.com", "g.co", "c.gle"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "msn.com", "aka.ms"},
    "paypal": {"paypal.com", "paypalobjects.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com", "adobesign.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "amazon": {"amazon.com", "amazonaws.com", "amzn.com"},
}
BRAND_ALIAS_TERMS: dict[str, set[str]] = {
    "google": {"google", "gmail", "google workspace", "google docs", "google drive"},
    "microsoft": {"microsoft", "office 365", "microsoft 365", "onedrive", "sharepoint", "outlook"},
    "paypal": {"paypal"},
    "docusign": {"docusign", "docu sign"},
    "dropbox": {"dropbox"},
    "adobe": {"adobe sign", "acrobat sign"},
    "apple": {"apple", "icloud"},
    "amazon": {"amazon", "aws"},
}

GENERIC_SENDER_TERMS = {
    "notifications",
    "notification",
    "billing",
    "document center",
    "shared workspace",
    "workspace",
    "admin team",
    "support",
    "helpdesk",
    "hr department",
    "finance team",
    "finance",
    "accounts",
    "records",
    "security team",
}

CREDENTIAL_CUE_PHRASES = (
    "sign in",
    "verify your account",
    "confirm your password",
    "session expired",
    "restore access",
    "unlock account",
    "re authenticate",
    "re-authenticate",
    "confirm your identity",
)
PAYMENT_CUE_KEYWORDS = {"invoice", "payment", "wire", "remittance", "balance", "billing", "bank", "overdue"}
PAYMENT_CUE_PHRASES = (
    "invoice attached",
    "payment failed",
    "wire transfer",
    "overdue balance",
    "billing statement",
    "bank details",
    "payment pending",
)
DOCUMENT_LURE_KEYWORDS = {"document", "file", "shared", "permission", "collaboration", "drive", "workspace"}
DOCUMENT_LURE_STRONG_KEYWORDS = {"document", "file", "permission", "collaboration", "shared"}
DOCUMENT_LURE_PHRASES = (
    "updated shared document",
    "view secure file",
    "access the document",
    "file preview",
    "permission changed",
    "collaboration request",
)
HR_LURE_KEYWORDS = {"payroll", "benefits", "tax", "onboarding", "policy", "deposit", "employee"}
HR_LURE_STRONG_KEYWORDS = {"payroll", "benefits", "tax", "deposit"}
HR_LURE_PHRASES = (
    "payroll update",
    "employee benefits",
    "tax form",
    "onboarding document",
    "policy acknowledgment",
    "direct deposit confirmation",
)
BEC_CUE_KEYWORDS = {"confidential", "kindly", "approval", "transfer", "urgent", "gift", "cards"}
BEC_CUE_PHRASES = (
    "are you available",
    "need your assistance",
    "keep this confidential",
    "purchase gift cards",
    "approve payment",
    "urgent transfer",
    "reply once you receive this",
)
URGENCY_CUE_PHRASES = (
    "within 24 hours",
    "action required",
    "avoid interruption",
    "final notice",
    "pending review",
    "immediate action",
)

RISKY_DISK_IMAGE_EXTENSIONS = {".iso", ".img"}
ATTACHMENT_LURE_KEYWORDS = {
    "invoice",
    "payment",
    "remittance",
    "payroll",
    "statement",
    "document",
    "secure",
    "shared",
    "hr",
    "tax",
}
ATTACHMENT_PASSWORD_HINTS = {
    "password",
    "passcode",
    "encrypted",
    "unlock",
    "protected",
}


class AnalyzeTextRequest(BaseModel):
    """Request body for manual subject/body analysis."""

    subject: str = ""
    body: str = ""


class AnalyzeUrlRequest(BaseModel):
    """Request body for URL threat analysis."""

    url: str


def clamp(value: float, low: float, high: float) -> float:
    """Clamp value to [low, high]."""
    return max(low, min(high, value))


def unique_preserve_order(items: list[str]) -> list[str]:
    """Deduplicate a list while preserving order."""
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


def remove_html_boilerplate(html_text: str) -> str:
    """Remove non-visible HTML blocks that pollute previews."""
    cleaned = HTML_COMMENT_REGEX.sub(" ", html_text)
    cleaned = HTML_STYLE_REGEX.sub(" ", cleaned)
    cleaned = HTML_SCRIPT_REGEX.sub(" ", cleaned)
    return cleaned


def normalize_visible_text(text: str) -> str:
    """Normalize decoded visible text to a readable single-space flow."""
    cleaned = INVISIBLE_CHAR_REGEX.sub("", text)
    cleaned = CONTROL_CHAR_REGEX.sub(" ", cleaned)
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    cleaned = MULTISPACE_REGEX.sub(" ", cleaned).strip()
    return cleaned


def strip_html(html_text: str) -> str:
    """Remove HTML boilerplate/tags and keep visible readable text."""
    cleaned_html = remove_html_boilerplate(html_text)
    cleaned_html = HTML_BREAK_TAG_REGEX.sub(" ", cleaned_html)
    text = unescape(HTML_TAG_REGEX.sub(" ", cleaned_html))
    return normalize_visible_text(text)


def fallback_subject_body(text: str) -> tuple[str, str]:
    """Fallback extraction for malformed emails."""
    subject_match = SUBJECT_REGEX.search(text)
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def parse_raw_headers_block(text: str) -> dict[str, list[str]]:
    """Parse raw RFC822 headers from text (including folded multiline headers)."""
    block = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
    header_map: dict[str, list[str]] = {}
    current_key = ""

    for line in block.splitlines():
        if not line.strip():
            break

        if line[:1] in {" ", "\t"} and current_key:
            header_map[current_key][-1] = f"{header_map[current_key][-1]} {line.strip()}"
            continue

        if ":" not in line:
            current_key = ""
            continue

        name, value = line.split(":", 1)
        current_key = name.strip().lower()
        header_map.setdefault(current_key, []).append(value.strip())

    return header_map


def first_header_value(header_map: dict[str, list[str]], key: str) -> str:
    """Safely read first header value from a parsed header map."""
    values = header_map.get(key.lower(), [])
    return str(values[0]).strip() if values else ""


def fallback_headers(text: str) -> tuple[str, str, str, list[str], list[str], list[str]]:
    """Fallback header extraction for malformed emails."""
    header_map = parse_raw_headers_block(text)

    return (
        first_header_value(header_map, "from"),
        first_header_value(header_map, "reply-to"),
        first_header_value(header_map, "return-path"),
        [value for value in header_map.get("authentication-results", []) if value],
        [value for value in header_map.get("received-spf", []) if value],
        [value for value in header_map.get("dkim-signature", []) if value],
    )


def decode_part_content(part: Any) -> str:
    """Safely decode email part content to text."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode(part.get_content_charset() or "utf-8", errors="ignore")
    except Exception:
        pass

    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="ignore")
    except Exception:
        return payload.decode("utf-8", errors="ignore")


def parse_email_payload(raw_bytes: bytes) -> dict[str, Any]:
    """Parse raw email and extract text + metadata for multi-signal analysis."""
    decoded_text = raw_bytes.decode("utf-8", errors="ignore")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        subject = str(msg.get("Subject", "") or "")
        sender = str(msg.get("From", "") or "")
        reply_to = str(msg.get("Reply-To", "") or "")
        return_path = str(msg.get("Return-Path", "") or "")
        authentication_results = [
            str(value).strip()
            for value in msg.get_all("Authentication-Results", [])
            if str(value).strip()
        ]
        received_spf = [str(value).strip() for value in msg.get_all("Received-SPF", []) if str(value).strip()]
        dkim_signatures = [str(value).strip() for value in msg.get_all("DKIM-Signature", []) if str(value).strip()]

        has_html = False
        body_chunks: list[str] = []
        html_urls: list[str] = []
        attachment_names: list[str] = []
        attachment_extensions: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue

                filename = part.get_filename()
                disposition = part.get_content_disposition()
                content_type = part.get_content_type()

                is_inline_resource = disposition == "inline"
                is_attachment = disposition == "attachment" or (filename and not is_inline_resource)
                if is_attachment:
                    name = filename or "unnamed_attachment"
                    attachment_names.append(name)
                    ext = Path(name).suffix.lower()
                    if ext:
                        attachment_extensions.append(ext)
                    continue

                if content_type == "text/html":
                    has_html = True
                if not content_type.startswith("text/"):
                    continue

                content = decode_part_content(part)
                if content_type == "text/html":
                    html_urls.extend(extract_urls_from_html(content))
                    content = strip_html(content)
                if content:
                    body_chunks.append(content)
        else:
            content_type = msg.get_content_type()
            if content_type == "text/html":
                has_html = True

            if content_type.startswith("text/") or content_type == "message/rfc822":
                content = decode_part_content(msg)
                if content_type == "text/html":
                    html_urls.extend(extract_urls_from_html(content))
                    content = strip_html(content)
                if content:
                    body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if not body:
            _, body = fallback_subject_body(decoded_text)
            if has_html:
                body = strip_html(body)

        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "authentication_results": authentication_results,
            "received_spf": received_spf,
            "dkim_signatures": dkim_signatures,
            "has_html": has_html,
            "html_urls": unique_preserve_order(html_urls),
            "attachment_names": attachment_names,
            "attachment_extensions": unique_preserve_order(attachment_extensions),
        }
    except Exception:
        subject, body = fallback_subject_body(decoded_text)
        sender, reply_to, return_path, authentication_results, received_spf, dkim_signatures = fallback_headers(
            decoded_text
        )
        has_html = bool(re.search(r"<html|<body|<table|<div|<a\s+href|<p\b", decoded_text, flags=re.IGNORECASE))
        html_urls = extract_urls_from_html(decoded_text) if has_html else []
        if has_html:
            body = strip_html(body)
        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "authentication_results": authentication_results,
            "received_spf": received_spf,
            "dkim_signatures": dkim_signatures,
            "has_html": has_html,
            "html_urls": unique_preserve_order(html_urls),
            "attachment_names": [],
            "attachment_extensions": [],
        }


def clean_text(text: str) -> str:
    """Normalize text exactly as in training preprocessing."""
    text = unescape(text).lower()
    text = URL_REGEX.sub(" urltoken ", text)
    text = EMAIL_REGEX.sub(" emailtoken ", text)
    text = NON_ALNUM_REGEX.sub(" ", text)
    text = MULTISPACE_REGEX.sub(" ", text).strip()
    return text


def clean_preview_text(text: str, max_length: int = 400) -> str:
    """Generate readable preview text for the frontend."""
    if HTML_MARKUP_REGEX.search(text):
        cleaned = strip_html(text)
    else:
        cleaned = normalize_visible_text(unescape(text))
    return cleaned[:max_length]


def extract_domain_from_header(header_value: str) -> str:
    """Extract sender domain from a header value."""
    if not header_value:
        return ""

    _, addr = parseaddr(header_value)
    candidate = (addr or header_value).strip()
    candidate = candidate.strip("<>\"' ")

    if "@" not in candidate:
        match = re.search(r"[\w\.-]+@([\w\.-]+\.\w+)", candidate)
        return match.group(1).lower() if match else ""

    domain = candidate.split("@")[-1].lower().strip(" >,;\"'")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain if "." in domain else ""


def is_academic_domain(domain: str) -> bool:
    """Heuristic for academic domains."""
    return domain.endswith(".edu") or domain.endswith(".edu.vn") or ".ac." in domain


def domain_matches_suffix(domain: str, suffix: str) -> bool:
    """Check if domain matches suffix exactly or as subdomain."""
    return domain == suffix or domain.endswith(f".{suffix}")


def domain_matches_any_suffix(domain: str, suffixes: set[str]) -> bool:
    """Check domain against any suffix in a set."""
    return any(domain_matches_suffix(domain, suffix) for suffix in suffixes)


def domains_related(domain_a: str, domain_b: str) -> bool:
    """Check if two domains are equivalent or subdomains of each other."""
    if not domain_a or not domain_b:
        return False
    return domain_matches_suffix(domain_a, domain_b) or domain_matches_suffix(domain_b, domain_a)


def is_official_looking_domain(domain: str) -> bool:
    """Heuristic for trusted/official looking domains."""
    if domain.endswith(".gov") or domain.endswith(".mil") or domain.endswith(".gov.vn"):
        return True
    if domain_matches_any_suffix(domain, TRUSTED_OFFICIAL_DOMAINS):
        return True
    return False


def extract_registered_domain(domain: str) -> str:
    """Naive registrable-domain extraction (offline heuristic)."""
    host = (domain or "").strip().lower().strip(".")
    if not host or "." not in host:
        return host
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host

    common_second_level_tlds = {"co.uk", "org.uk", "gov.uk", "com.au", "com.vn", "co.jp", "com.sg"}
    tail = ".".join(parts[-2:])
    if len(parts) >= 3:
        tail3 = ".".join(parts[-3:])
        if ".".join(parts[-2:]) in {"uk", "au", "jp", "sg", "vn"} and tail3.endswith(tuple(common_second_level_tlds)):
            return tail3
    return tail


def normalize_lookalike_token(text: str) -> str:
    """Normalize token by replacing common lookalike digits and removing separators."""
    mapping = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "2": "z",
            "3": "e",
            "4": "a",
            "5": "s",
            "6": "g",
            "7": "t",
            "8": "b",
            "9": "g",
            "-": "",
            "_": "",
            ".": "",
        }
    )
    return (text or "").lower().translate(mapping)


def bounded_levenshtein_distance(a: str, b: str, max_distance: int = 2) -> int:
    """Compute Levenshtein distance with early-stop bound for short typo checks."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        row_min = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            value = min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + cost,
            )
            current.append(value)
            row_min = min(row_min, value)
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def detect_suspicious_domain_keywords(domain: str) -> list[str]:
    """Extract suspicious semantic keywords found in domain labels."""
    host = (domain or "").lower()
    labels = [segment for segment in re.split(r"[.\-_]+", host) if segment]
    hits = [label for label in labels if label in SUSPICIOUS_DOMAIN_KEYWORDS]
    return unique_preserve_order(hits)


def is_typosquat_like(domain: str) -> dict[str, Any]:
    """Detect typosquat / impersonation-like patterns for popular brands."""
    host = (domain or "").lower().strip(".")
    if not host or "." not in host:
        return {"is_typosquat": False, "brands": [], "reasons": []}

    registered = extract_registered_domain(host)
    sld = registered.split(".")[0] if "." in registered else registered
    normalized = normalize_lookalike_token(sld)
    host_normalized = normalize_lookalike_token(host)

    brand_hits: list[str] = []
    reasons: list[str] = []

    for brand, trusted_domains in BRAND_DOMAIN_MAP.items():
        if any(domain_matches_suffix(host, trusted_domain) for trusted_domain in trusted_domains):
            continue

        brand_token = normalize_lookalike_token(brand)
        contains_brand = brand_token in host_normalized
        close_edit = bounded_levenshtein_distance(normalized, brand_token, max_distance=1) <= 1

        if contains_brand or close_edit:
            brand_hits.append(brand)
            reasons.append(f"Domain appears lookalike for {brand}.")

    hyphen_density = host.count("-")
    suspicious_keyword_hits = detect_suspicious_domain_keywords(host)
    if hyphen_density >= 3 and suspicious_keyword_hits:
        reasons.append("Domain uses excessive hyphenated service/login terms.")

    return {
        "is_typosquat": bool(brand_hits),
        "brands": unique_preserve_order(brand_hits),
        "reasons": unique_preserve_order(reasons),
    }


def classify_domain(domain: str, *, context: str = "sender") -> dict[str, Any]:
    """Classify a domain into trusted/unknown/suspicious/typosquat buckets."""
    host = (domain or "").lower().strip(".")
    if not host:
        return {"category": "unknown", "signals": ["Domain unavailable."], "keyword_hits": [], "typosquat": False}

    signals: list[str] = []
    keyword_hits = detect_suspicious_domain_keywords(host)
    typosquat_info = is_typosquat_like(host)
    label_count = len([part for part in host.split(".") if part])
    hyphen_count = host.count("-")

    if domain_matches_any_suffix(host, TRUSTED_OFFICIAL_DOMAINS) or host.endswith((".gov", ".mil", ".gov.vn")):
        return {
            "category": "trusted",
            "signals": ["Domain matches trusted/official suffix list."],
            "keyword_hits": keyword_hits,
            "typosquat": False,
        }

    if context == "url" and domain_matches_any_suffix(host, REDIRECT_SHORTENER_DOMAINS | TRUSTED_REDIRECT_DOMAINS):
        category = "trusted_redirect" if domain_matches_any_suffix(host, TRUSTED_REDIRECT_DOMAINS) else "redirect"
        signals.append("Domain is a known redirect/shortener service.")
        return {
            "category": category,
            "signals": signals,
            "keyword_hits": keyword_hits,
            "typosquat": False,
        }

    if typosquat_info["is_typosquat"]:
        signals.extend(typosquat_info["reasons"])
        return {
            "category": "typosquat",
            "signals": unique_preserve_order(signals),
            "keyword_hits": keyword_hits,
            "typosquat": True,
        }

    suspicious = False
    if keyword_hits and len(keyword_hits) >= 2:
        suspicious = True
        signals.append("Domain contains multiple phishing/service bait keywords.")
    if hyphen_count >= 2 and keyword_hits:
        suspicious = True
        signals.append("Domain uses multiple hyphens with suspicious semantic terms.")
    if label_count >= 5:
        suspicious = True
        signals.append("Domain has excessive subdomain depth.")
    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        suspicious = True
        signals.append(f"Domain uses suspicious TLD '.{tld}'.")

    return {
        "category": "suspicious" if suspicious else "unknown",
        "signals": unique_preserve_order(signals),
        "keyword_hits": keyword_hits,
        "typosquat": False,
    }


def detect_brand_impersonation(
    *,
    display_name: str,
    from_domain: str,
    subject: str = "",
    body_preview: str = "",
) -> list[str]:
    """Detect likely trusted-brand impersonation signals from sender context."""
    text_context = " ".join([display_name or "", subject or "", body_preview or ""]).lower()
    findings: list[str] = []

    for brand, aliases in BRAND_ALIAS_TERMS.items():
        if not any(alias in text_context for alias in aliases):
            continue
        trusted_domains = BRAND_DOMAIN_MAP.get(brand, set())
        if from_domain and any(domain_matches_suffix(from_domain, trusted) for trusted in trusted_domains):
            continue
        findings.append(f"Brand impersonation risk: mentions {brand} but sender domain is unofficial.")

    return unique_preserve_order(findings)


def detect_generic_sender_risk(
    *,
    display_name: str,
    local_part: str,
    from_domain: str,
    sender_domain_profile: dict[str, Any],
    spf_status: str,
    dkim_status: str,
    dmarc_status: str,
) -> list[str]:
    """Detect suspicious sender naming patterns beyond famous-brand spoofing."""
    findings: list[str] = []
    display = (display_name or "").lower().strip()
    local = (local_part or "").lower().strip()

    has_generic_display = any(term in display for term in GENERIC_SENDER_TERMS)
    weak_auth = any(status in {"n/a", "none", "neutral", "softfail", "fail"} for status in (spf_status, dkim_status, dmarc_status))
    low_trust_domain = sender_domain_profile.get("category") in {"unknown", "suspicious", "typosquat"}

    if has_generic_display and (weak_auth or low_trust_domain):
        findings.append("Generic service-style display name combined with low-trust or weakly authenticated sender.")

    odd_local_pattern = bool(
        re.search(r"[a-z]{1,3}\d{5,}", local)
        or re.search(r"[a-z0-9][._-][a-z0-9][._-][a-z0-9]", local)
        or (len(local) >= 16 and sum(ch.isdigit() for ch in local) >= 4)
    )
    if odd_local_pattern:
        findings.append("Sender local-part appears machine-generated or unusually random.")

    if has_generic_display and from_domain:
        domain_terms = set(detect_suspicious_domain_keywords(from_domain))
        if domain_terms:
            findings.append("Generic business/service sender name from domain with login/billing-style terms.")

    if display and from_domain:
        display_semantic = {"finance", "billing", "hr", "support", "admin", "workspace", "documents"}
        if any(token in display for token in display_semantic):
            trusted_semantic = {"payroll", "billing", "docs", "workspace", "support"}
            if not any(term in from_domain for term in trusted_semantic) and low_trust_domain:
                findings.append("Display-name business context does not align with sender domain semantics.")

    return unique_preserve_order(findings)


def normalize_auth_status(raw_status: str, protocol: str) -> str:
    """Normalize auth header status values into stable API enums."""
    token = (raw_status or "").strip().lower()
    if not token:
        return "n/a"

    if protocol == "spf":
        if token == "pass":
            return "pass"
        if token == "softfail":
            return "softfail"
        if token == "neutral":
            return "neutral"
        if token in {"none", "no"}:
            return "none"
        if token in {"fail", "hardfail", "permerror", "temperror", "error"}:
            return "fail"
        return "n/a"

    # DKIM / DMARC.
    if token == "pass":
        return "pass"
    if token == "none":
        return "none"
    if token in {"fail", "permerror", "temperror", "policy", "reject", "quarantine"}:
        return "fail"
    return "n/a"


def parse_authentication_results(authentication_results: list[str]) -> dict[str, Any]:
    """Parse Authentication-Results headers for SPF/DKIM/DMARC and related domains."""
    spf_status = "n/a"
    dkim_status = "n/a"
    dmarc_status = "n/a"
    auth_domains: list[str] = []

    for value in authentication_results:
        if spf_status == "n/a":
            spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z]+)\b", value, flags=re.IGNORECASE)
            if spf_match:
                spf_status = normalize_auth_status(spf_match.group(1), "spf")

        if dkim_status == "n/a":
            dkim_match = re.search(r"\bdkim\s*=\s*([a-zA-Z]+)\b", value, flags=re.IGNORECASE)
            if dkim_match:
                dkim_status = normalize_auth_status(dkim_match.group(1), "dkim")

        if dmarc_status == "n/a":
            dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z]+)\b", value, flags=re.IGNORECASE)
            if dmarc_match:
                dmarc_status = normalize_auth_status(dmarc_match.group(1), "dmarc")

        for pattern in (
            r"\bheader\.from\s*=\s*([^\s;]+)",
            r"\bsmtp\.mailfrom\s*=\s*([^\s;]+)",
            r"\bheader\.i\s*=\s*([^\s;]+)",
        ):
            for match in re.finditer(pattern, value, flags=re.IGNORECASE):
                domain = extract_domain_from_header(match.group(1))
                if domain:
                    auth_domains.append(domain)

    return {
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "auth_domains": unique_preserve_order(auth_domains),
    }


def extract_spf_status_from_received_spf(received_spf_headers: list[str]) -> str:
    """Parse SPF status from Received-SPF headers."""
    for value in received_spf_headers:
        spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z]+)\b", value, flags=re.IGNORECASE)
        if spf_match:
            normalized = normalize_auth_status(spf_match.group(1), "spf")
            if normalized != "n/a":
                return normalized

        prefix_match = re.match(r"^\s*([a-zA-Z]+)\b", value.strip())
        if prefix_match:
            normalized = normalize_auth_status(prefix_match.group(1), "spf")
            if normalized != "n/a":
                return normalized

    return "n/a"


def extract_domains_from_received_spf(received_spf_headers: list[str]) -> list[str]:
    """Extract candidate SPF identity domains from Received-SPF header text."""
    domains: list[str] = []
    patterns = (
        r"\bdomain of\s+[^@\s]+@([^\s>;]+)",
        r"\benvelope-from=([^\s;]+)",
        r"\bsender(?:\s+identity)?=([^\s;]+)",
    )

    for value in received_spf_headers:
        for pattern in patterns:
            for match in re.finditer(pattern, value, flags=re.IGNORECASE):
                domain = extract_domain_from_header(match.group(1))
                if domain:
                    domains.append(domain)

    return unique_preserve_order(domains)


def extract_dkim_signature_domains(dkim_signatures: list[str]) -> list[str]:
    """Extract DKIM d= domains from DKIM-Signature headers."""
    domains: list[str] = []
    for value in dkim_signatures:
        match = re.search(r"\bd\s*=\s*([^;\s]+)", value, flags=re.IGNORECASE)
        if not match:
            continue
        domain = extract_domain_from_header(match.group(1))
        if domain:
            domains.append(domain)
    return unique_preserve_order(domains)


def compute_domain_alignment(from_domain: str, candidate_domains: list[str]) -> str:
    """Compute domain alignment between From domain and authenticated domains."""
    if not from_domain or not candidate_domains:
        return "unknown"
    if any(domains_related(from_domain, candidate) for candidate in candidate_domains):
        return "aligned"
    return "mismatched"


def extract_header_auth_status(
    *,
    authentication_results: list[str],
    received_spf_headers: list[str],
    dkim_signatures: list[str],
) -> dict[str, Any]:
    """Resolve SPF/DKIM/DMARC status using header sources with precedence."""
    parsed = parse_authentication_results(authentication_results)

    spf_status = parsed["spf_status"]
    if spf_status == "n/a":
        spf_status = extract_spf_status_from_received_spf(received_spf_headers)

    dkim_status = parsed["dkim_status"]
    if dkim_status == "n/a" and not dkim_signatures:
        dkim_status = "none"

    dmarc_status = parsed["dmarc_status"]

    auth_domains = unique_preserve_order(
        parsed["auth_domains"]
        + extract_domains_from_received_spf(received_spf_headers)
        + extract_dkim_signature_domains(dkim_signatures)
    )

    return {
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "auth_domains": auth_domains,
    }


def analyze_headers(
    sender: str,
    reply_to: str,
    return_path: str,
    *,
    subject: str = "",
    body_preview: str = "",
    authentication_results: list[str] | None = None,
    received_spf_headers: list[str] | None = None,
    dkim_signatures: list[str] | None = None,
) -> dict[str, Any]:
    """Analyze sender/reply headers, authentication, and sender-domain trust signals."""
    authentication_results = authentication_results or []
    received_spf_headers = received_spf_headers or []
    dkim_signatures = dkim_signatures or []

    display_name, sender_addr = parseaddr(sender or "")
    sender_local_part = sender_addr.split("@")[0].lower() if "@" in sender_addr else ""
    from_domain = extract_domain_from_header(sender)
    reply_domain = extract_domain_from_header(reply_to)
    return_domain = extract_domain_from_header(return_path)
    header_context_present = bool((sender or "").strip() or (reply_to or "").strip() or (return_path or "").strip())

    header_warnings: list[str] = []
    if header_context_present and not from_domain:
        header_warnings.append("Missing sender domain.")

    reply_mismatch = bool(from_domain and reply_domain and not domains_related(reply_domain, from_domain))
    return_path_mismatch = bool(from_domain and return_domain and not domains_related(return_domain, from_domain))

    if reply_mismatch:
        header_warnings.append("Reply-To domain differs from sender domain.")

    if return_path_mismatch:
        header_warnings.append("Return-Path domain differs from sender domain.")

    auth_status = extract_header_auth_status(
        authentication_results=authentication_results,
        received_spf_headers=received_spf_headers,
        dkim_signatures=dkim_signatures,
    )
    auth_domains = auth_status["auth_domains"]
    if auth_status["spf_status"] != "n/a" and return_domain:
        auth_domains = unique_preserve_order(auth_domains + [return_domain])

    domain_alignment = compute_domain_alignment(from_domain, auth_domains)
    if domain_alignment == "mismatched":
        header_warnings.append("Authenticated domain is mismatched with From domain.")
    elif domain_alignment == "unknown":
        header_warnings.append("Domain alignment could not be confirmed.")

    auth_findings: list[str] = []
    if auth_status["spf_status"] == "fail":
        header_warnings.append("SPF authentication failed.")
        auth_findings.append("SPF failed.")
    elif auth_status["spf_status"] == "softfail":
        header_warnings.append("SPF authentication returned softfail.")
        auth_findings.append("SPF softfail.")
    elif auth_status["spf_status"] in {"none", "n/a", "neutral"}:
        header_warnings.append("SPF authentication is missing or inconclusive.")
        auth_findings.append("SPF missing/inconclusive.")
    elif auth_status["spf_status"] == "pass":
        auth_findings.append("SPF passed.")

    if auth_status["dkim_status"] == "fail":
        header_warnings.append("DKIM authentication failed.")
        auth_findings.append("DKIM failed.")
    elif auth_status["dkim_status"] in {"none", "n/a"}:
        header_warnings.append("DKIM signature is missing or unavailable.")
        auth_findings.append("DKIM missing.")
    elif auth_status["dkim_status"] == "pass":
        auth_findings.append("DKIM passed.")

    if auth_status["dmarc_status"] == "fail":
        header_warnings.append("DMARC authentication failed.")
        auth_findings.append("DMARC failed.")
    elif auth_status["dmarc_status"] in {"none", "n/a"}:
        header_warnings.append("DMARC policy result is missing or unavailable.")
        auth_findings.append("DMARC missing.")
    elif auth_status["dmarc_status"] == "pass":
        auth_findings.append("DMARC passed.")

    academic = bool(from_domain and is_academic_domain(from_domain))
    official = bool(from_domain and is_official_looking_domain(from_domain))
    strong_authentication = (
        auth_status["spf_status"] == "pass"
        and auth_status["dkim_status"] == "pass"
        and auth_status["dmarc_status"] == "pass"
        and domain_alignment == "aligned"
    )

    sender_domain_profile = classify_domain(from_domain, context="sender")
    brand_impersonation_findings = detect_brand_impersonation(
        display_name=display_name,
        from_domain=from_domain,
        subject=subject,
        body_preview=body_preview,
    )
    generic_sender_findings = detect_generic_sender_risk(
        display_name=display_name,
        local_part=sender_local_part,
        from_domain=from_domain,
        sender_domain_profile=sender_domain_profile,
        spf_status=auth_status["spf_status"],
        dkim_status=auth_status["dkim_status"],
        dmarc_status=auth_status["dmarc_status"],
    )
    domain_findings = unique_preserve_order(
        sender_domain_profile["signals"] + brand_impersonation_findings + generic_sender_findings
    )

    header_risk = 0.0
    if reply_mismatch:
        header_risk += 7.0
    if return_path_mismatch:
        header_risk += 4.0
    if header_context_present and not from_domain:
        header_risk += 8.0

    header_risk += {
        "pass": -2.5,
        "softfail": 6.0,
        "neutral": 2.0,
        "none": 2.0,
        "n/a": 2.0,
        "fail": 10.0,
    }.get(auth_status["spf_status"], 2.0)
    header_risk += {
        "pass": -2.0,
        "none": 2.0,
        "n/a": 2.0,
        "fail": 8.0,
    }.get(auth_status["dkim_status"], 2.0)
    header_risk += {
        "pass": -3.0,
        "none": 5.0,
        "n/a": 5.0,
        "fail": 12.0,
    }.get(auth_status["dmarc_status"], 5.0)
    header_risk += {
        "aligned": -2.0,
        "unknown": 2.0,
        "mismatched": 6.0,
    }.get(domain_alignment, 2.0)

    domain_risk = 0.0
    if sender_domain_profile["category"] == "typosquat":
        domain_risk += 16.0
    elif sender_domain_profile["category"] == "suspicious":
        domain_risk += 10.0
    elif sender_domain_profile["category"] == "unknown":
        domain_risk += 3.0

    if brand_impersonation_findings:
        domain_risk += min(18.0, len(brand_impersonation_findings) * 8.0)
    if generic_sender_findings:
        domain_risk += min(10.0, len(generic_sender_findings) * 3.0)
    if official:
        domain_risk -= 4.0
    if academic:
        domain_risk -= 2.0
    if strong_authentication:
        domain_risk -= 4.0

    informational_flags: list[str] = []
    if official:
        informational_flags.append("Trusted sender domain pattern detected.")
    if academic:
        informational_flags.append("Academic domain detected.")
    if strong_authentication:
        informational_flags.append("Strong sender authentication alignment detected.")

    combined_header_warnings = unique_preserve_order(header_warnings + domain_findings)

    return {
        "display_name": display_name.strip(),
        "sender_local_part": sender_local_part,
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "spf_status": auth_status["spf_status"],
        "dkim_status": auth_status["dkim_status"],
        "dmarc_status": auth_status["dmarc_status"],
        "domain_alignment": domain_alignment,
        "auth_domains": auth_domains,
        "auth_findings": unique_preserve_order(auth_findings),
        "header_warnings": combined_header_warnings,
        "header_flags": unique_preserve_order(combined_header_warnings + informational_flags),
        "sender_domain_category": sender_domain_profile["category"],
        "sender_domain_signals": sender_domain_profile["signals"],
        "brand_impersonation_findings": brand_impersonation_findings,
        "generic_sender_findings": generic_sender_findings,
        "domain_findings": domain_findings,
        "header_risk_score": int(round(clamp(header_risk, 0.0, 35.0))),
        "domain_risk_score": int(round(clamp(domain_risk, 0.0, 35.0))),
        "strong_authentication": strong_authentication,
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
    """Filter out malformed URL values."""
    if not url:
        return False
    parsed = parse_url_like(url)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        return False
    return True


def url_path_extension(path: str) -> str:
    """Extract lowercase file extension from URL path."""
    return Path(path).suffix.lower() if path else ""


def is_asset_url(url: str) -> bool:
    """Heuristic low-priority URL detector for email template/image links."""
    parsed = parse_url_like(url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    if not host:
        return False

    if domain_matches_any_suffix(host, LOW_PRIORITY_ASSET_HOST_SUFFIXES):
        return True
    if domain_matches_any_suffix(host, LOW_PRIORITY_SOCIAL_HOST_SUFFIXES):
        return True
    if domain_matches_any_suffix(host, LOW_PRIORITY_APP_BADGE_HOST_SUFFIXES):
        return True

    ext = url_path_extension(path)
    if ext in ASSET_FILE_EXTENSIONS:
        return True

    if host.startswith(("img.", "image.", "images.", "static.", "cdn.")) and (
        ext in ASSET_FILE_EXTENSIONS or any(hint in path for hint in ASSET_PATH_HINTS)
    ):
        return True

    if any(hint in path for hint in ASSET_PATH_HINTS):
        return True

    if "pixel" in query or ("open" in query and ("width=" in query or "height=" in query)):
        return True

    return False


def normalize_and_filter_url(url: str) -> str:
    """Normalize URL candidate, handle protocol-relative links, and filter non-actionable targets."""
    candidate = normalize_url_candidate(unescape((url or "").strip()))
    if not candidate:
        return ""

    if candidate.startswith("//"):
        candidate = f"https:{candidate}"

    lowered = candidate.lower()
    if lowered.startswith(IGNORED_EMBEDDED_URL_PREFIXES):
        return ""

    return candidate if is_meaningful_url(candidate) else ""


def merge_url_candidates(*candidate_groups: list[str]) -> list[str]:
    """Merge URL candidates, keeping meaningful unique values in stable order."""
    output: list[str] = []
    seen: set[str] = set()

    for group in candidate_groups:
        for raw in group:
            normalized = normalize_and_filter_url(raw)
            if not normalized:
                continue
            key = normalized.lower().rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            output.append(normalized)

    return output


def extract_urls_from_html(html_text: str) -> list[str]:
    """Extract meaningful links from href/src attributes in HTML."""
    if not html_text:
        return []

    cleaned_html = remove_html_boilerplate(html_text)
    candidates: list[str] = []
    for match in HTML_ATTR_URL_REGEX.finditer(cleaned_html):
        value = next((group for group in match.groups() if group), "")
        if value:
            candidates.append(value)

    return merge_url_candidates(candidates)


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
    structural_oddity = host.count(".") >= 5 and not domain_matches_any_suffix(host, TRUSTED_OFFICIAL_DOMAINS)
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
    return merge_url_candidates(URL_REGEX.findall(text))


def classify_urls(urls: list[str]) -> dict[str, list[str]]:
    """Split URL list into primary/tracking/asset/redirect buckets."""
    primary_urls: list[str] = []
    tracking_urls: list[str] = []
    asset_urls: list[str] = []
    redirect_urls: list[str] = []

    for url in urls:
        parsed = parse_url_like(url)
        host = (parsed.hostname or "").lower()
        tracking = is_tracking_url(url)
        asset = is_asset_url(url)
        is_redirect_domain = bool(
            host and domain_matches_any_suffix(host, REDIRECT_SHORTENER_DOMAINS | TRUSTED_REDIRECT_DOMAINS)
        )

        if asset:
            asset_urls.append(url)
        elif is_redirect_domain:
            redirect_urls.append(url)
            if tracking:
                tracking_urls.append(url)
        elif tracking:
            tracking_urls.append(url)
        else:
            primary_urls.append(url)

    return {
        "primary_urls": unique_preserve_order(primary_urls),
        "tracking_urls": unique_preserve_order(tracking_urls),
        "asset_urls": unique_preserve_order(asset_urls),
        "redirect_urls": unique_preserve_order(redirect_urls),
    }


def analyze_urls(
    original_text: str,
    extra_urls: list[str] | None = None,
    *,
    sender_domain: str = "",
) -> dict[str, Any]:
    """Run URL extraction + local domain intelligence/risk scoring."""
    all_urls = merge_url_candidates(extract_urls(original_text), extra_urls or [])
    categorized = classify_urls(all_urls)
    tracking_urls = categorized["tracking_urls"]
    asset_urls = categorized["asset_urls"]
    redirect_urls = categorized["redirect_urls"]
    primary_urls = categorized["primary_urls"]
    tracking_detected = bool(tracking_urls or redirect_urls)

    url_details: list[dict[str, Any]] = []
    suspicious_urls: list[str] = []
    domain_findings: list[str] = []
    unique_domains: set[str] = set()
    mismatched_domain_count = 0
    url_risk = 0.0

    for url in all_urls:
        parsed = parse_url_like(url)
        domain = (parsed.hostname or "").lower()
        if not domain:
            continue

        registered_domain = extract_registered_domain(domain)
        if registered_domain:
            unique_domains.add(registered_domain)

        tracking = is_tracking_url(url)
        asset = is_asset_url(url)
        structural_suspicious = is_suspicious_url(url)
        domain_profile = classify_domain(domain, context="url")

        classification = domain_profile["category"]
        if classification == "redirect":
            classification = "trusted_redirect" if domain_matches_any_suffix(domain, TRUSTED_REDIRECT_DOMAINS) else "redirect"

        signals = list(domain_profile["signals"])
        risk = 0.0

        if classification == "typosquat":
            risk += 12.0
        elif classification == "suspicious":
            risk += 8.0
        elif classification == "unknown":
            risk += 3.0
        elif classification == "redirect":
            risk += 1.5
        elif classification == "trusted_redirect":
            risk += 1.0

        if structural_suspicious:
            risk += 4.0
            signals.append("URL structure appears suspicious.")
        if tracking:
            risk += 1.0
            signals.append("Tracking/redirect pattern detected.")

        subdomain_depth = max(0, len([part for part in domain.split(".") if part]) - 2)
        if subdomain_depth >= 3:
            risk += 2.0
            signals.append("Domain has excessive subdomain depth.")

        if len(url) >= 180:
            risk += 1.5
            signals.append("URL is unusually long.")

        sender_mismatch = bool(sender_domain and not domains_related(domain, sender_domain))
        if sender_mismatch and classification not in {"trusted", "trusted_redirect", "redirect"}:
            mismatched_domain_count += 1
            risk += 2.0
            signals.append("Linked domain does not match sender domain context.")

        if asset:
            risk = max(0.0, risk - 2.0)

        risk = clamp(risk, 0.0, 20.0)
        url_risk += risk

        if risk >= 7.0 or classification in {"suspicious", "typosquat"}:
            suspicious_urls.append(url)

        if signals:
            domain_findings.append(f"{domain}: {signals[0]}")

        url_details.append(
            {
                "url": url,
                "domain": domain,
                "classification": classification,
                "tracking": tracking,
                "asset": asset,
                "risk_score": int(round(risk)),
                "signals": unique_preserve_order(signals),
            }
        )

    unique_domain_count = len(unique_domains)
    if unique_domain_count >= 3:
        url_risk += 3.0
    if unique_domain_count >= 5:
        url_risk += 4.0
    if len(tracking_urls) + len(redirect_urls) >= 3:
        url_risk += 2.0
    if mismatched_domain_count >= 2:
        url_risk += 2.0

    extracted_urls = merge_url_candidates(primary_urls, redirect_urls, tracking_urls, suspicious_urls)
    suspicious_urls = unique_preserve_order(suspicious_urls)
    domain_findings = unique_preserve_order(domain_findings)
    url_risk_score = int(round(clamp(url_risk, 0.0, 35.0)))

    url_flags: list[str] = []
    if extracted_urls:
        url_flags.append("Contains URLs.")
    if len(extracted_urls) >= 4:
        url_flags.append("Multiple external links detected.")
    if tracking_detected and redirect_urls:
        url_flags.append("Redirect/shortener links detected.")
    if tracking_detected and tracking_urls:
        url_flags.append("Tracked redirect links detected.")
        if not suspicious_urls:
            url_flags.append("Tracking links detected, but no strongly suspicious URL structure found.")
    if suspicious_urls:
        url_flags.append("Potentially suspicious URL patterns detected.")
    if any(detail["classification"] == "typosquat" for detail in url_details):
        url_flags.append("Typosquat or impersonation-like URL domain detected.")
    if mismatched_domain_count:
        url_flags.append("Sender domain context differs from one or more linked domains.")
    if asset_urls:
        url_flags.append("Low-priority asset links detected (hidden from extracted URLs).")

    return {
        "extracted_urls": extracted_urls,
        "primary_urls": primary_urls,
        "tracking_urls": tracking_urls,
        "redirect_urls": redirect_urls,
        "asset_urls": asset_urls,
        "suspicious_urls": suspicious_urls,
        "url_count": len(extracted_urls),
        "raw_url_count": len(all_urls),
        "tracking_detected": tracking_detected,
        "unique_domain_count": unique_domain_count,
        "mismatched_domain_count": mismatched_domain_count,
        "url_risk_score": url_risk_score,
        "domain_findings": domain_findings,
        "urls": url_details,
        "url_flags": unique_preserve_order(url_flags),
    }


def analyze_attachments(attachment_names: list[str], attachment_extensions: list[str]) -> dict[str, Any]:
    """Analyze attachment metadata heuristically (no execution/sandboxing)."""
    normalized_extensions = unique_preserve_order([ext.lower() for ext in attachment_extensions if ext])
    flags: list[str] = []
    findings: list[str] = []
    suspicious_filenames: list[str] = []
    risk = 0.0

    ext_set = set(normalized_extensions)
    has_exec = bool(ext_set & RISKY_EXECUTABLE_EXTENSIONS)
    has_compressed = bool(ext_set & RISKY_COMPRESSED_EXTENSIONS)
    has_macro = bool(ext_set & RISKY_MACRO_EXTENSIONS)
    has_disk_image = bool(ext_set & RISKY_DISK_IMAGE_EXTENSIONS)
    has_double_extension = False
    has_password_hint = False

    if has_exec:
        flags.append("Executable attachment type detected.")
        findings.append("Executable attachment extension detected.")
        risk += 14.0
    if has_compressed:
        flags.append("Compressed attachment detected.")
        findings.append("Archive attachment detected.")
        risk += 5.0
    if has_macro:
        flags.append("Macro-enabled Office attachment detected.")
        findings.append("Macro-enabled document extension detected.")
        risk += 10.0
    if has_disk_image:
        flags.append("Disk image attachment detected.")
        findings.append("Disk image attachment type detected.")
        risk += 8.0

    for name in attachment_names:
        lowered = (name or "").lower()
        if not lowered:
            continue

        if re.search(r"\.[a-z0-9]{1,8}\.(exe|js|scr|bat|cmd|ps1|vbs)$", lowered):
            has_double_extension = True
            suspicious_filenames.append(name)
            findings.append(f"Double-extension attachment filename: {name}")
            risk += 10.0

        if any(keyword in lowered for keyword in ATTACHMENT_LURE_KEYWORDS):
            suspicious_filenames.append(name)
            findings.append(f"Lure-themed attachment name detected: {name}")
            risk += 3.0

        if any(keyword in lowered for keyword in ATTACHMENT_PASSWORD_HINTS):
            has_password_hint = True
            findings.append(f"Password-protected/encrypted naming hint in attachment: {name}")
            risk += 4.0

    attachment_count = len(attachment_names)
    if attachment_count >= 3:
        risk += 2.0

    return {
        "attachment_count": attachment_count,
        "attachment_names": attachment_names,
        "attachment_extensions": normalized_extensions,
        "attachment_flags": unique_preserve_order(flags),
        "attachment_findings": unique_preserve_order(findings),
        "attachment_risk_score": int(round(clamp(risk, 0.0, 30.0))),
        "suspicious_filenames": unique_preserve_order(suspicious_filenames),
        "has_risky_exec": has_exec,
        "has_compressed": has_compressed,
        "has_macro": has_macro,
        "has_disk_image": has_disk_image,
        "has_double_extension": has_double_extension,
        "has_password_hint": has_password_hint,
    }


def compute_language_risk(
    *,
    phishing_hits: list[str],
    urgency_hits: list[str],
    credential_hits: list[str],
    payment_hits: list[str],
    document_hits: list[str],
    hr_hits: list[str],
    bec_hits: list[str],
    marketing_hits: list[str],
    has_transactional: bool,
) -> dict[str, int]:
    """Compute transparent heuristic language-risk metrics from multiple lure categories."""
    phishing_score = 0.0
    phishing_score += min(24.0, len(phishing_hits) * 8.0)
    phishing_score += min(30.0, len(credential_hits) * 10.0)
    phishing_score += min(18.0, len(urgency_hits) * 6.0)
    phishing_score += min(21.0, len(payment_hits) * 7.0)
    phishing_score += min(18.0, len(document_hits) * 6.0)
    phishing_score += min(18.0, len(hr_hits) * 6.0)
    phishing_score += min(24.0, len(bec_hits) * 8.0)

    language_risk = phishing_score
    high_risk_buckets = bool(credential_hits or payment_hits or document_hits or hr_hits or bec_hits)

    if has_transactional and not high_risk_buckets and len(phishing_hits) <= 1 and len(urgency_hits) <= 1:
        language_risk -= 10.0
    elif has_transactional and not high_risk_buckets:
        language_risk -= 5.0
    elif has_transactional:
        language_risk -= 2.0

    if marketing_hits and not high_risk_buckets and len(urgency_hits) <= 1 and len(phishing_hits) <= 1:
        language_risk -= 8.0
    elif marketing_hits and not high_risk_buckets:
        language_risk -= 4.0

    # Calm/professional phishing can avoid urgency words; preserve some risk.
    if credential_hits and (payment_hits or document_hits or hr_hits or bec_hits) and not urgency_hits:
        language_risk += 4.0

    return {
        "language_risk_score": int(round(clamp(language_risk, 0.0, 100.0))),
        "phishing_language_score": int(round(clamp(phishing_score, 0.0, 100.0))),
    }


def analyze_language(cleaned_text: str) -> dict[str, Any]:
    """Run rule-based language signal analysis and return transparent heuristic scores."""
    tokens = set(cleaned_text.split())

    def phrase_hits(phrases: tuple[str, ...]) -> list[str]:
        return sorted([phrase for phrase in phrases if phrase in cleaned_text])

    phishing_hits = sorted([keyword for keyword in PHISHING_KEYWORDS if keyword in tokens])
    marketing_hits = sorted([keyword for keyword in MARKETING_KEYWORDS if keyword in tokens])
    transactional_keyword_hits = sorted([keyword for keyword in TRANSACTIONAL_SYSTEM_KEYWORDS if keyword in tokens])
    transactional_phrase_hits = sorted([phrase for phrase in TRANSACTIONAL_SYSTEM_PHRASES if phrase in cleaned_text])
    transactional_hits = unique_preserve_order(transactional_phrase_hits + transactional_keyword_hits)
    has_transactional = bool(transactional_phrase_hits) or len(transactional_keyword_hits) >= 2

    urgency_hits = unique_preserve_order(
        sorted([keyword for keyword in URGENCY_CUE_KEYWORDS if keyword in tokens]) + phrase_hits(URGENCY_CUE_PHRASES)
    )
    credential_hits = unique_preserve_order(
        sorted([keyword for keyword in CREDENTIAL_STRONG_KEYWORDS if keyword in tokens])
        + phrase_hits(CREDENTIAL_CUE_PHRASES)
    )
    payment_hits = unique_preserve_order(
        sorted([keyword for keyword in PAYMENT_CUE_KEYWORDS if keyword in tokens])
        + phrase_hits(PAYMENT_CUE_PHRASES)
    )
    document_hits = unique_preserve_order(
        sorted([keyword for keyword in DOCUMENT_LURE_STRONG_KEYWORDS if keyword in tokens])
        + phrase_hits(DOCUMENT_LURE_PHRASES)
    )
    hr_hits = unique_preserve_order(
        sorted([keyword for keyword in HR_LURE_STRONG_KEYWORDS if keyword in tokens])
        + phrase_hits(HR_LURE_PHRASES)
    )
    bec_hits = unique_preserve_order(
        sorted([keyword for keyword in BEC_CUE_KEYWORDS if keyword in tokens])
        + phrase_hits(BEC_CUE_PHRASES)
    )

    suspicious_bucket_count = sum(
        bool(bucket) for bucket in [credential_hits, payment_hits, document_hits, hr_hits, bec_hits]
    )
    has_phishing = bool(
        len(phishing_hits) >= 2
        or (credential_hits and (urgency_hits or suspicious_bucket_count >= 2))
        or (bec_hits and (payment_hits or credential_hits))
        or (document_hits and credential_hits)
    )

    indicators: list[str] = []
    if has_phishing:
        indicators.append("Phishing/social-engineering language detected.")
    elif phishing_hits or credential_hits or payment_hits or document_hits or hr_hits or bec_hits:
        indicators.append("Low-confidence social-engineering cues detected.")
    else:
        indicators.append("No strong phishing keywords detected.")

    if urgency_hits:
        indicators.append("Urgency cues detected.")
    if credential_hits:
        indicators.append("Credential harvesting cues detected.")
    if payment_hits:
        indicators.append("Payment/invoice lure language detected.")
    if document_hits:
        indicators.append("Document/file-sharing lure language detected.")
    if hr_hits:
        indicators.append("HR/payroll/admin lure language detected.")
    if bec_hits:
        indicators.append("Business-email-compromise style cues detected.")
    if marketing_hits:
        indicators.append("Promotional language detected.")
    if has_transactional:
        indicators.append("Transactional/system notification pattern detected.")

    scores = compute_language_risk(
        phishing_hits=phishing_hits,
        urgency_hits=urgency_hits,
        credential_hits=credential_hits,
        payment_hits=payment_hits,
        document_hits=document_hits,
        hr_hits=hr_hits,
        bec_hits=bec_hits,
        marketing_hits=marketing_hits,
        has_transactional=has_transactional,
    )
    suspicious_indicators = [item for item in indicators if not item.startswith("No strong phishing")]

    return {
        "phishing_hits": phishing_hits,
        "marketing_hits": marketing_hits,
        "transactional_hits": transactional_hits,
        "urgency_hits": urgency_hits,
        "credential_hits": credential_hits,
        "payment_hits": payment_hits,
        "document_hits": document_hits,
        "hr_hits": hr_hits,
        "bec_hits": bec_hits,
        "has_phishing": has_phishing,
        "has_marketing": bool(marketing_hits),
        "has_transactional": has_transactional,
        "language_risk_score": scores["language_risk_score"],
        "phishing_language_score": scores["phishing_language_score"],
        "suspicious_indicators": suspicious_indicators,
        "signals": suspicious_indicators,
        "language_flags": unique_preserve_order(indicators),
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


def compute_risk_breakdown(
    *,
    spam_probability: float,
    threshold: float,
    header_analysis: dict[str, Any],
    url_analysis: dict[str, Any],
    html_analysis: dict[str, Any],
    attachment_analysis: dict[str, Any],
    language_analysis: dict[str, Any],
    header_context_available: bool = True,
) -> dict[str, float]:
    """Compute weighted hybrid risk breakdown in range [0, 100]."""
    ml_score = spam_probability * 35.0
    if spam_probability >= max(threshold, 0.7):
        ml_score += 3.0
    ml_score = clamp(ml_score, 0.0, 35.0)

    header_risk = clamp(float(header_analysis.get("header_risk_score", 0.0)), 0.0, 20.0)
    domain_risk = clamp(float(header_analysis.get("domain_risk_score", 0.0)), 0.0, 20.0)
    url_risk = clamp(float(url_analysis.get("url_risk_score", 0.0)) * 0.58, 0.0, 20.0)
    language_risk = clamp(
        float(language_analysis.get("language_risk_score", 0.0)) * 0.14
        + float(language_analysis.get("phishing_language_score", 0.0)) * 0.08,
        0.0,
        20.0,
    )
    attachment_risk = clamp(float(attachment_analysis.get("attachment_risk_score", 0.0)) * 0.8, 0.0, 20.0)

    trust_offset = 0.0
    phishing_combo_bonus = 0.0
    has_suspicious_urls = bool(url_analysis.get("suspicious_urls"))
    has_risky_attachments = bool(
        attachment_analysis.get("has_risky_exec")
        or attachment_analysis.get("has_macro")
        or attachment_analysis.get("has_compressed")
        or attachment_analysis.get("has_double_extension")
        or attachment_analysis.get("has_disk_image")
    )
    low_social_risk = not language_analysis.get("has_phishing", False)
    credential_hits = bool(language_analysis.get("credential_hits"))
    brand_impersonation = bool(header_analysis.get("brand_impersonation_findings"))

    if (
        header_analysis.get("strong_authentication")
        and header_analysis.get("sender_domain_category") == "trusted"
        and not has_suspicious_urls
        and not has_risky_attachments
        and low_social_risk
    ):
        trust_offset += 8.0
    if html_analysis.get("newsletter_like") and not has_suspicious_urls and low_social_risk:
        trust_offset += 3.0
    if language_analysis.get("has_transactional") and low_social_risk:
        trust_offset += 2.0
    if language_analysis.get("has_marketing") and low_social_risk and not has_suspicious_urls:
        trust_offset += 2.0
    if (
        header_analysis.get("sender_domain_category") == "trusted"
        and header_analysis.get("dmarc_status") == "pass"
        and header_analysis.get("domain_alignment") == "aligned"
    ):
        trust_offset += 2.0
    if not header_context_available:
        missing_header_discount = min(9.0, header_risk * 0.55 + domain_risk * 0.45)
        if has_suspicious_urls or language_analysis.get("has_phishing") or has_risky_attachments:
            trust_offset += min(2.0, missing_header_discount * 0.2)
        else:
            trust_offset += missing_header_discount

    if language_analysis.get("has_phishing") and has_suspicious_urls:
        phishing_combo_bonus += 8.0
    if float(url_analysis.get("url_risk_score", 0.0)) >= 12.0 and credential_hits:
        phishing_combo_bonus += 4.0
    if brand_impersonation and has_suspicious_urls:
        phishing_combo_bonus += 3.0
    if has_risky_attachments and language_analysis.get("has_phishing"):
        phishing_combo_bonus += 4.0

    final_risk_score = clamp(
        ml_score + header_risk + domain_risk + url_risk + language_risk + attachment_risk - trust_offset + phishing_combo_bonus,
        0.0,
        100.0,
    )

    return {
        "ml_score": round(ml_score, 2),
        "header_risk": round(header_risk, 2),
        "domain_risk": round(domain_risk, 2),
        "url_risk": round(url_risk, 2),
        "language_risk": round(language_risk, 2),
        "attachment_risk": round(attachment_risk, 2),
        "trust_offset": round(trust_offset, 2),
        "phishing_combo_bonus": round(phishing_combo_bonus, 2),
        "final_risk_score": round(final_risk_score, 2),
    }


def compute_risk_score(
    *,
    spam_probability: float,
    threshold: float,
    header_analysis: dict[str, Any],
    url_analysis: dict[str, Any],
    html_analysis: dict[str, Any],
    attachment_analysis: dict[str, Any],
    language_analysis: dict[str, Any],
    header_context_available: bool = True,
) -> float:
    """Backward-compatible wrapper returning final hybrid risk score."""
    breakdown = compute_risk_breakdown(
        spam_probability=spam_probability,
        threshold=threshold,
        header_analysis=header_analysis,
        url_analysis=url_analysis,
        html_analysis=html_analysis,
        attachment_analysis=attachment_analysis,
        language_analysis=language_analysis,
        header_context_available=header_context_available,
    )
    return float(breakdown["final_risk_score"])


def determine_verdict(
    risk_score: float,
    spam_probability: float,
    *,
    risk_breakdown: dict[str, Any] | None = None,
) -> str:
    """Final verdict from weighted hybrid risk score."""
    rb = risk_breakdown or {}
    strong_combined_evidence = bool(
        rb.get("attachment_risk", 0.0) >= 8.0
        or rb.get("url_risk", 0.0) >= 10.0
        or (rb.get("domain_risk", 0.0) >= 8.0 and rb.get("language_risk", 0.0) >= 8.0)
        or rb.get("header_risk", 0.0) >= 14.0
    )

    if risk_score >= THREAT_HARD_THRESHOLD and strong_combined_evidence:
        return "THREAT"
    if risk_score >= THREAT_BASE_THRESHOLD and spam_probability >= THREAT_SPAM_PROB_THRESHOLD and strong_combined_evidence:
        return "THREAT"
    if risk_score >= 56.0 or spam_probability >= 0.86:
        return "SPAM"
    if risk_score >= 26.0 or spam_probability >= 0.62:
        return "SUSPICIOUS"
    return "HAM"


def compute_confidence(verdict: str, spam_probability: float, risk_score: float) -> float:
    """Confidence heuristic for UI display."""
    if verdict == "THREAT":
        confidence = 0.72 * (risk_score / 100.0) + 0.28 * spam_probability
    elif verdict == "SPAM":
        confidence = 0.65 * spam_probability + 0.35 * (risk_score / 100.0)
    elif verdict == "HAM":
        confidence = 0.65 * ((100.0 - risk_score) / 100.0) + 0.35 * (1.0 - spam_probability)
    else:
        distance = min(abs(risk_score - 45.0) / 15.0, 1.0)
        confidence = 0.55 + 0.2 * distance
    return clamp(confidence, 0.0, 1.0)


def resolve_spam_class_index(classifier: Any, label_map: dict[Any, Any] | None = None) -> int:
    """Resolve spam class index from classifier classes + optional label map."""
    classes = list(getattr(classifier, "classes_", []))
    if not classes:
        return 1

    normalized_map = label_map or {}
    for idx, class_value in enumerate(classes):
        mapped = normalized_map.get(class_value)
        if mapped is None:
            try:
                mapped = normalized_map.get(int(class_value))
            except (TypeError, ValueError):
                mapped = None
        if isinstance(mapped, str) and mapped.strip().lower() == "spam":
            return idx

    for idx, class_value in enumerate(classes):
        if str(class_value).strip().lower() in {"1", "spam", "true"}:
            return idx

    return max(0, len(classes) - 1)


def build_indicators(
    *,
    spam_probability: float,
    threshold: float,
    risk_score: float,
    verdict: str,
    header_flags: list[str],
    url_flags: list[str],
    html_flags: list[str],
    attachment_flags: list[str],
    language_flags: list[str],
    newsletter_like: bool,
    has_phishing: bool,
    has_suspicious_urls: bool,
    has_risky_attachments: bool,
    trusted_or_academic_sender: bool,
    header_context_available: bool = True,
) -> list[str]:
    """Merge all signal flags into one readable indicator list."""
    indicators: list[str] = []
    indicators.extend(header_flags)
    indicators.extend(url_flags)
    indicators.extend(html_flags)
    indicators.extend(attachment_flags)
    indicators.extend(language_flags)

    if newsletter_like and not has_phishing and not has_suspicious_urls and not has_risky_attachments:
        indicators.append("Newsletter/promotional pattern detected with low phishing risk.")
    if trusted_or_academic_sender and not has_phishing:
        indicators.append("Trusted sender domain pattern detected.")
    if not header_context_available:
        indicators.append("Header authentication was unavailable for this manual text analysis.")

    if spam_probability >= threshold:
        indicators.append(
            f"Model spam probability ({spam_probability:.2f}) is above model threshold ({threshold:.2f})."
        )
    else:
        indicators.append(
            f"Model spam probability ({spam_probability:.2f}) is below model threshold ({threshold:.2f})."
        )

    indicators.append(f"Hybrid risk score: {risk_score:.1f}/100.")
    if verdict == "THREAT":
        indicators.append("Final verdict: THREAT (high confidence malicious signals).")
    elif verdict == "SPAM":
        indicators.append("Final verdict: SPAM (high combined spam risk).")
    elif verdict == "SUSPICIOUS":
        indicators.append("Final verdict: SUSPICIOUS (manual review recommended).")
    else:
        indicators.append("Final verdict: HAM (low combined risk).")

    return unique_preserve_order(indicators)


def build_threat_reasoning(
    *,
    header_analysis: dict[str, Any],
    url_analysis: dict[str, Any],
    attachment_analysis: dict[str, Any],
    language_analysis: dict[str, Any],
    risk_breakdown: dict[str, Any],
    verdict: str,
    header_context_available: bool = True,
) -> list[str]:
    """Build concise explainable threat reasoning statements for frontend display."""
    reasons: list[str] = []

    spf_status = header_analysis.get("spf_status", "n/a")
    dkim_status = header_analysis.get("dkim_status", "n/a")
    dmarc_status = header_analysis.get("dmarc_status", "n/a")
    alignment = header_analysis.get("domain_alignment", "unknown")

    if header_context_available:
        if spf_status in {"fail", "softfail", "none", "n/a", "neutral"}:
            reasons.append("SPF authentication missing, inconclusive, or failed.")
        if dkim_status in {"fail", "none", "n/a"}:
            reasons.append("DKIM signature missing or failed.")
        if dmarc_status in {"fail", "none", "n/a"}:
            reasons.append("DMARC policy result missing or failed.")
        if alignment in {"mismatched", "unknown"}:
            reasons.append("Sender/authenticated domain alignment is weak or unknown.")
        if header_analysis.get("reply_mismatch"):
            reasons.append("Reply-To domain differs from sender domain.")
        if header_analysis.get("return_path_mismatch"):
            reasons.append("Return-Path domain differs from sender domain.")
    else:
        reasons.append("Header authentication context was not available in manual text mode.")

    sender_category = header_analysis.get("sender_domain_category", "unknown")
    if sender_category in {"typosquat", "suspicious"}:
        reasons.append("Sender domain appears suspicious or impersonation-like.")
    if header_analysis.get("brand_impersonation_findings"):
        reasons.append("Brand impersonation signals detected in sender/message context.")
    if header_analysis.get("generic_sender_findings"):
        reasons.append("Generic business/service sender pattern from low-trust domain.")

    if url_analysis.get("url_risk_score", 0) >= 8:
        reasons.append("One or more linked URL domains appear suspicious.")
    if url_analysis.get("mismatched_domain_count", 0) >= 1:
        reasons.append("Linked domains do not align with sender domain context.")
    if url_analysis.get("unique_domain_count", 0) >= 3:
        reasons.append("Email contains multiple external domains.")
    if any(item.get("classification") == "typosquat" for item in url_analysis.get("urls", [])):
        reasons.append("Typosquat/lookalike URL domain detected.")

    if language_analysis.get("credential_hits"):
        reasons.append("Credential-harvesting language cues detected.")
    if language_analysis.get("payment_hits"):
        reasons.append("Payment/invoice lure language detected.")
    if language_analysis.get("document_hits"):
        reasons.append("Document-sharing lure language detected.")
    if language_analysis.get("hr_hits"):
        reasons.append("HR/payroll themed lure language detected.")
    if language_analysis.get("bec_hits"):
        reasons.append("Business email compromise style cues detected.")
    if language_analysis.get("urgency_hits"):
        reasons.append("Urgency/pressure cues detected.")

    if attachment_analysis.get("attachment_risk_score", 0) >= 6:
        reasons.append("Attachment naming/type risk indicators detected.")
    if attachment_analysis.get("has_double_extension"):
        reasons.append("Double-extension attachment filename detected.")
    if attachment_analysis.get("has_risky_exec") or attachment_analysis.get("has_macro"):
        reasons.append("Potentially dangerous executable or macro attachment detected.")

    if verdict == "HAM" and not reasons:
        reasons.append("No high-risk indicators detected across headers, URLs, language, or attachments.")
    elif verdict in {"SPAM", "THREAT"} and not reasons:
        reasons.append("Combined risk score is elevated across multiple heuristics.")

    reasons.append(
        "Risk breakdown: "
        f"ML={risk_breakdown.get('ml_score', 0):.1f}, "
        f"Header={risk_breakdown.get('header_risk', 0):.1f}, "
        f"Domain={risk_breakdown.get('domain_risk', 0):.1f}, "
        f"URL={risk_breakdown.get('url_risk', 0):.1f}, "
        f"Language={risk_breakdown.get('language_risk', 0):.1f}, "
        f"Attachment={risk_breakdown.get('attachment_risk', 0):.1f}."
    )

    return unique_preserve_order(reasons)[:12]


def analyze_content(
    *,
    filename: str,
    subject: str,
    body: str,
    sender: str,
    reply_to: str,
    return_path: str,
    has_html: bool,
    html_urls: list[str] | None,
    authentication_results: list[str] | None,
    received_spf_headers: list[str] | None,
    dkim_signatures: list[str] | None,
    attachment_names: list[str],
    attachment_extensions: list[str],
    input_source: str = "uploaded_email",
) -> dict[str, Any]:
    """Run model inference + multi-signal static analysis and build response payload."""
    combined_text = f"{subject}\n{body}"  # Keep identical with training pipeline.
    cleaned_text = clean_text(combined_text)
    if not cleaned_text:
        raise HTTPException(status_code=400, detail="No usable text could be extracted from email.")

    email_runtime = getattr(app.state, "email_runtime", None) or load_email_runtime()
    app.state.email_runtime = email_runtime
    threshold = float(getattr(app.state, "threshold", email_runtime.get("threshold", DEFAULT_THRESHOLD)))
    app.state.threshold = threshold
    ml_indicators: list[str] = []

    if email_runtime["mode"] == "ensemble":
        email_result = email_runtime["module"].predict_from_parts(subject, body, sender=sender)
        spam_probability = float(email_result["spam_probability"])
        ml_indicators.extend(
            [
                "Email ensemble runtime: LightGBM + XGBoost.",
                *[
                    indicator
                    for indicator in email_result.get("indicators", [])
                    if isinstance(indicator, str) and indicator.strip()
                ],
            ]
        )
    else:
        vectorizer = email_runtime["vectorizer"]
        classifier = email_runtime["classifier"]
        if not hasattr(classifier, "predict_proba"):
            raise HTTPException(status_code=500, detail="Loaded classifier does not support predict_proba.")

        features = vectorizer.transform([cleaned_text])
        class_probabilities = classifier.predict_proba(features)[0]
        spam_index = resolve_spam_class_index(classifier, email_runtime.get("label_map", {}))
        spam_index = min(max(spam_index, 0), len(class_probabilities) - 1)
        spam_probability = float(class_probabilities[spam_index])
        ml_indicators.append(f"Legacy email classifier runtime: {type(classifier).__name__}.")

    header_analysis = analyze_headers(
        sender,
        reply_to,
        return_path,
        subject=subject,
        body_preview=body[:320],
        authentication_results=authentication_results,
        received_spf_headers=received_spf_headers,
        dkim_signatures=dkim_signatures,
    )
    supplemental_urls = html_urls or []
    if has_html and not supplemental_urls:
        supplemental_urls = extract_urls_from_html(combined_text)
    url_analysis = analyze_urls(combined_text, extra_urls=supplemental_urls, sender_domain=header_analysis["from_domain"])
    language_analysis = analyze_language(cleaned_text)
    html_analysis = analyze_html_signals(
        has_html=has_html,
        url_count=url_analysis["url_count"],
        has_phishing=language_analysis["has_phishing"],
        has_marketing=language_analysis["has_marketing"],
        cleaned_text=cleaned_text,
    )
    attachment_analysis = analyze_attachments(attachment_names, attachment_extensions)
    header_context_available = bool(
        sender.strip()
        or reply_to.strip()
        or return_path.strip()
        or authentication_results
        or received_spf_headers
        or dkim_signatures
    )
    if not header_context_available:
        header_analysis = {
            **header_analysis,
            "header_flags": [],
            "header_warnings": [],
            "auth_findings": ["Header authentication unavailable in manual text mode."],
            "strong_authentication": False,
        }

    risk_breakdown = compute_risk_breakdown(
        spam_probability=spam_probability,
        threshold=threshold,
        header_analysis=header_analysis,
        url_analysis=url_analysis,
        html_analysis=html_analysis,
        attachment_analysis=attachment_analysis,
        language_analysis=language_analysis,
        header_context_available=header_context_available,
    )
    risk_score = float(risk_breakdown["final_risk_score"])
    verdict = determine_verdict(risk_score, spam_probability, risk_breakdown=risk_breakdown)
    confidence = compute_confidence(verdict, spam_probability, risk_score)
    threat_reasoning = build_threat_reasoning(
        header_analysis=header_analysis,
        url_analysis=url_analysis,
        attachment_analysis=attachment_analysis,
        language_analysis=language_analysis,
        risk_breakdown=risk_breakdown,
        verdict=verdict,
        header_context_available=header_context_available,
    )

    indicators = build_indicators(
        spam_probability=spam_probability,
        threshold=threshold,
        risk_score=risk_score,
        verdict=verdict,
        header_flags=header_analysis["header_flags"],
        url_flags=url_analysis["url_flags"],
        html_flags=html_analysis["html_flags"],
        attachment_flags=attachment_analysis["attachment_flags"],
        language_flags=language_analysis["language_flags"],
        newsletter_like=html_analysis["newsletter_like"],
        has_phishing=language_analysis["has_phishing"],
        has_suspicious_urls=bool(url_analysis["suspicious_urls"]),
        has_risky_attachments=bool(
            attachment_analysis["has_risky_exec"]
            or attachment_analysis["has_macro"]
            or attachment_analysis["has_compressed"]
        ),
        trusted_or_academic_sender=bool(header_analysis["is_official"] or header_analysis["is_academic"]),
        header_context_available=header_context_available,
    )
    indicators = unique_preserve_order(
        [
            *ml_indicators,
            (
                "Header authentication summary unavailable in manual text mode."
                if not header_context_available
                else (
                    "Header authentication summary: "
                    f"SPF={header_analysis['spf_status'].upper()}, "
                    f"DKIM={header_analysis['dkim_status'].upper()}, "
                    f"DMARC={header_analysis['dmarc_status'].upper()}, "
                    f"ALIGNMENT={header_analysis['domain_alignment'].upper()}."
                )
            ),
            *threat_reasoning,
            *indicators,
        ]
    )

    preview = clean_preview_text(combined_text, max_length=400)
    normalized_sender = sender.strip() or "N/A"
    normalized_reply_to = reply_to.strip() or "N/A"
    normalized_return_path = return_path.strip() or "N/A"

    header_analysis_payload = {
        "from_address": normalized_sender,
        "display_name": header_analysis["display_name"] or "N/A",
        "sender_local_part": header_analysis["sender_local_part"] or "n/a",
        "reply_to": normalized_reply_to,
        "return_path": normalized_return_path,
        "spf_status": header_analysis["spf_status"],
        "dkim_status": header_analysis["dkim_status"],
        "dmarc_status": header_analysis["dmarc_status"],
        "domain_alignment": header_analysis["domain_alignment"],
        "auth_findings": header_analysis["auth_findings"],
        "header_warnings": header_analysis["header_warnings"],
        "from_domain": header_analysis["from_domain"] or "n/a",
        "reply_to_domain": header_analysis["reply_domain"] or "n/a",
        "return_path_domain": header_analysis["return_domain"] or "n/a",
        "sender_domain_category": header_analysis["sender_domain_category"],
        "sender_domain_signals": header_analysis["sender_domain_signals"],
        "brand_impersonation_findings": header_analysis["brand_impersonation_findings"],
        "generic_sender_findings": header_analysis["generic_sender_findings"],
        "domain_findings": header_analysis["domain_findings"],
        "header_risk_score": header_analysis["header_risk_score"],
        "domain_risk_score": header_analysis["domain_risk_score"],
        "strong_authentication": header_analysis["strong_authentication"],
    }
    url_analysis_payload = {
        "urls": url_analysis["urls"],
        "domain_findings": url_analysis["domain_findings"],
        "url_risk_score": url_analysis["url_risk_score"],
        "unique_domain_count": url_analysis["unique_domain_count"],
        "mismatched_domain_count": url_analysis["mismatched_domain_count"],
        "tracking_detected": url_analysis["tracking_detected"],
        "redirect_urls": url_analysis["redirect_urls"],
    }
    language_analysis_payload = {
        "language_risk_score": language_analysis["language_risk_score"],
        "phishing_language_score": language_analysis["phishing_language_score"],
        "suspicious_indicators": language_analysis["suspicious_indicators"],
        "signals": language_analysis["signals"],
        "phishing_hits": language_analysis["phishing_hits"],
        "payment_hits": language_analysis["payment_hits"],
        "document_hits": language_analysis["document_hits"],
        "hr_hits": language_analysis["hr_hits"],
        "bec_hits": language_analysis["bec_hits"],
        "marketing_hits": language_analysis["marketing_hits"],
        "transactional_hits": language_analysis["transactional_hits"],
        "urgency_hits": language_analysis["urgency_hits"],
        "credential_hits": language_analysis["credential_hits"],
        "heuristic": True,
    }
    attachment_analysis_payload = {
        "attachment_count": attachment_analysis["attachment_count"],
        "attachment_names": attachment_analysis["attachment_names"],
        "attachment_extensions": attachment_analysis["attachment_extensions"],
        "attachment_flags": attachment_analysis["attachment_flags"],
        "attachment_findings": attachment_analysis["attachment_findings"],
        "attachment_risk_score": attachment_analysis["attachment_risk_score"],
        "suspicious_filenames": attachment_analysis["suspicious_filenames"],
        "has_risky_exec": attachment_analysis["has_risky_exec"],
        "has_compressed": attachment_analysis["has_compressed"],
        "has_macro": attachment_analysis["has_macro"],
        "has_disk_image": attachment_analysis["has_disk_image"],
        "has_double_extension": attachment_analysis["has_double_extension"],
        "has_password_hint": attachment_analysis["has_password_hint"],
    }
    risk_breakdown_payload = {
        "ml_score": risk_breakdown["ml_score"],
        "header_risk": risk_breakdown["header_risk"],
        "domain_risk": risk_breakdown["domain_risk"],
        "url_risk": risk_breakdown["url_risk"],
        "language_risk": risk_breakdown["language_risk"],
        "attachment_risk": risk_breakdown["attachment_risk"],
        "trust_offset": risk_breakdown["trust_offset"],
        "phishing_combo_bonus": risk_breakdown.get("phishing_combo_bonus", 0.0),
        "final_risk_score": risk_breakdown["final_risk_score"],
    }

    return {
        "analysis_type": "email",
        "asset_type_label": "EMAIL THREAT",
        "classification_label": verdict,
        "filename": filename,
        "input_source": input_source,
        "header_context_available": header_context_available,
        "subject": subject or "(no subject)",
        "sender": normalized_sender,
        "reply_to": normalized_reply_to,
        "return_path": normalized_return_path,
        "verdict": verdict,
        "confidence": round(confidence, 6),
        "threshold": round(threshold, 6),
        "spam_probability": round(spam_probability, 6),
        "risk_score": round(risk_score, 2),
        "has_html": has_html,
        "url_count": url_analysis["url_count"],
        "extracted_urls": url_analysis["extracted_urls"],
        "tracking_urls": url_analysis["tracking_urls"],
        "redirect_urls": url_analysis["redirect_urls"],
        "asset_urls": url_analysis["asset_urls"],
        "suspicious_urls": url_analysis["suspicious_urls"],
        "attachment_count": attachment_analysis["attachment_count"],
        "attachment_names": attachment_analysis["attachment_names"],
        "attachment_extensions": attachment_analysis["attachment_extensions"],
        "spf_status": header_analysis["spf_status"],
        "dkim_status": header_analysis["dkim_status"],
        "dmarc_status": header_analysis["dmarc_status"],
        "domain_alignment": header_analysis["domain_alignment"],
        "header_flags": header_analysis["header_flags"],
        "header_warnings": header_analysis["header_warnings"],
        "url_flags": url_analysis["url_flags"],
        "html_flags": html_analysis["html_flags"],
        "attachment_flags": attachment_analysis["attachment_flags"],
        "language_flags": language_analysis["language_flags"],
        "language_risk_score": language_analysis["language_risk_score"],
        "phishing_language_score": language_analysis["phishing_language_score"],
        "header_analysis": header_analysis_payload,
        "url_analysis": url_analysis_payload,
        "language_analysis": language_analysis_payload,
        "attachment_analysis": attachment_analysis_payload,
        "risk_breakdown": risk_breakdown_payload,
        "threat_reasoning": threat_reasoning,
        "indicators": indicators,
        "preview": preview,
    }


def load_model_artifact() -> dict[str, Any]:
    """Load and validate the serialized model artifact."""
    if not MODEL_PATH.is_file():
        raise RuntimeError(f"Model file not found: {MODEL_PATH.resolve()}")

    artifact = joblib.load(MODEL_PATH)
    required_keys = {"vectorizer", "classifier", "label_map"}
    missing_keys = required_keys.difference(artifact.keys())
    if missing_keys:
        missing = ", ".join(sorted(missing_keys))
        raise RuntimeError(f"Invalid model artifact. Missing keys: {missing}")

    return artifact


def load_email_runtime() -> dict[str, Any]:
    """Prefer the dedicated Email ensemble; fall back to the legacy backend artifact."""
    if email_predict_module is not None:
        try:
            email_predict_module.load_email_artifacts(verbose=False)
            return {
                "mode": "ensemble",
                "module": email_predict_module,
                "threshold": DEFAULT_THRESHOLD,
                "artifacts": (
                    email_predict_module.describe_loaded_artifacts()
                    if hasattr(email_predict_module, "describe_loaded_artifacts")
                    else {}
                ),
            }
        except Exception as exc:
            ensemble_error = str(exc)
    else:
        ensemble_error = EMAIL_PREDICT_IMPORT_ERROR or "Email ensemble module unavailable."

    artifact = load_model_artifact()
    return {
        "mode": "legacy",
        "vectorizer": artifact["vectorizer"],
        "classifier": artifact["classifier"],
        "label_map": artifact.get("label_map", {0: "ham", 1: "spam"}),
        "threshold": float(artifact.get("threshold", DEFAULT_THRESHOLD)),
        "fallback_reason": ensemble_error,
    }


@lru_cache(maxsize=1)
def load_file_model_artifacts() -> dict[str, Any]:
    """Load all malware file-classification models from FILE/models."""
    if not FILE_MODELS_DIR.is_dir():
        raise RuntimeError(f"FILE models directory not found: {FILE_MODELS_DIR}")

    model_entries: list[dict[str, Any]] = []
    for model_path in sorted(FILE_MODELS_DIR.glob("*_model.pkl")):
        model_entries.append(
            {
                "name": model_path.stem.replace("_model", ""),
                "path": str(model_path),
                "model": joblib.load(model_path),
            }
        )

    if not model_entries:
        raise RuntimeError(f"No FILE models found in: {FILE_MODELS_DIR}")

    scaler_path = FILE_MODELS_DIR / "feature_scaler.pkl"
    scaler = joblib.load(scaler_path) if scaler_path.is_file() else None
    kmeans_entry = next((entry for entry in model_entries if "kmeans" in entry["name"].lower()), None)
    return {
        "models": model_entries,
        "scaler": scaler,
        "kmeans_cluster_to_label": infer_file_kmeans_cluster_mapping(
            kmeans_entry["model"] if kmeans_entry is not None else None,
            scaler,
        ),
        "source_dir": str(FILE_MODELS_DIR),
    }


def _build_file_feature_frame(values: list[float]) -> pd.DataFrame:
    return pd.DataFrame([values], columns=FILE_FEATURE_COLUMNS)


def _cluster_malware_score(center: list[float] | tuple[float, ...]) -> float:
    sections, avg_entropy, max_entropy, suspicious_sections, dlls, imports, has_sensitive_api, _, _, has_version = center
    return (
        (float(avg_entropy) * 2.0)
        + float(max_entropy)
        + (float(suspicious_sections) * 1.5)
        + (float(has_sensitive_api) * 1.5)
        - (float(dlls) * 0.05)
        - (float(imports) * 0.01)
        - (float(has_version) * 1.25)
        - (float(sections) * 0.05)
    )


def infer_file_kmeans_cluster_mapping(kmeans_model: Any, scaler: Any) -> dict[int, int]:
    """Infer a stable cluster->label mapping for FILE KMeans inference."""
    if kmeans_model is None or scaler is None or not hasattr(kmeans_model, "cluster_centers_") or file_preprocess is None:
        return {0: 0, 1: 1}

    benign_cluster_votes: list[int] = []
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    for binary_name in FILE_REFERENCE_BENIGN_BINARIES:
        candidate_path = Path(system_root) / "System32" / binary_name
        if not candidate_path.is_file():
            continue

        raw_features = file_preprocess.extract_features(str(candidate_path), label=None)
        if not raw_features:
            continue

        feature_frame = _build_file_feature_frame(raw_features[1:-1])
        cluster_id = int(kmeans_model.predict(scaler.transform(feature_frame))[0])
        benign_cluster_votes.append(cluster_id)

    if benign_cluster_votes:
        benign_cluster = Counter(benign_cluster_votes).most_common(1)[0][0]
        return {
            int(cluster_id): (0 if int(cluster_id) == benign_cluster else 1)
            for cluster_id in range(int(kmeans_model.n_clusters))
        }

    original_centers = scaler.inverse_transform(kmeans_model.cluster_centers_)
    ranked_clusters = sorted(
        range(int(kmeans_model.n_clusters)),
        key=lambda cluster_id: _cluster_malware_score(original_centers[cluster_id]),
        reverse=True,
    )
    mapping = {int(cluster_id): 0 for cluster_id in range(int(kmeans_model.n_clusters))}
    mapping[int(ranked_clusters[0])] = 1
    return mapping


@lru_cache(maxsize=1)
def load_url_model_artifacts() -> dict[str, Any]:
    """Load all URL-classification models and preprocessing assets from URL/models."""
    if not URL_MODELS_DIR.is_dir():
        raise RuntimeError(f"URL models directory not found: {URL_MODELS_DIR}")

    model_entries: list[dict[str, Any]] = []
    skipped_models: list[dict[str, str]] = []
    for model_path in sorted(URL_MODELS_DIR.glob("*_model.pkl")):
        try:
            loaded_model = joblib.load(model_path)
        except Exception as exc:
            skipped_models.append(
                {
                    "name": model_path.stem.replace("_model", ""),
                    "path": str(model_path),
                    "reason": str(exc),
                }
            )
            continue

        model_entries.append(
            {
                "name": model_path.stem.replace("_model", ""),
                "path": str(model_path),
                "model": loaded_model,
            }
        )

    if not model_entries:
        raise RuntimeError(f"No URL models found in: {URL_MODELS_DIR}")

    feature_names_path = URL_MODELS_DIR / "feature_names.pkl"
    if not feature_names_path.is_file():
        raise RuntimeError(f"URL feature_names.pkl not found: {feature_names_path}")

    scaler_path = URL_MODELS_DIR / "scaler.pkl"
    scaler_xgb_path = URL_MODELS_DIR / "scaler_xgb.pkl"
    label_encoder_path = URL_MODELS_DIR / "label_encoder.pkl"
    feature_names_xgb_path = URL_MODELS_DIR / "feature_names_xgb.pkl"
    domain_stats_path = URL_MODELS_DIR / "domain_stats.pkl"

    return {
        "models": model_entries,
        "skipped_models": skipped_models,
        "feature_names": joblib.load(feature_names_path),
        "feature_names_xgb": joblib.load(feature_names_xgb_path) if feature_names_xgb_path.is_file() else None,
        "scaler": joblib.load(scaler_path) if scaler_path.is_file() else None,
        "scaler_xgb": joblib.load(scaler_xgb_path) if scaler_xgb_path.is_file() else None,
        "label_encoder": joblib.load(label_encoder_path) if label_encoder_path.is_file() else None,
        "domain_stats": joblib.load(domain_stats_path) if domain_stats_path.is_file() else None,
        "source_dir": str(URL_MODELS_DIR),
    }


def calculate_string_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0

    probabilities = [text.count(char) / len(text) for char in set(text)]
    return float(-sum(probability * math.log2(probability) for probability in probabilities))


def analyze_url_path_segments(path: str) -> dict[str, int]:
    """Extract benign-vs-suspicious path-shape signals from URL segments."""
    segments = [segment for segment in str(path or "").split("/") if segment]
    suspicious_markers = {"login", "verify", "secure", "update", "confirm", "password"}
    numeric_segments = [segment for segment in segments if segment.isdigit()]
    long_numeric_segments = [segment for segment in numeric_segments if len(segment) >= 8]
    clean_alpha_segments = [
        segment for segment in segments if re.fullmatch(r"[a-z]{1,12}", segment or "") and segment not in suspicious_markers
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
            and not any(marker in segment for segment in segments for marker in suspicious_markers)
        ),
    }


def extract_url_model_features(url: str) -> dict[str, Any]:
    """Extract the same feature set used by the URL training notebooks."""
    normalized = str(url).strip().lower().replace("[", "").replace("]", "")
    address = normalized if "://" in normalized else f"http://{normalized}"

    try:
        parsed = urlparse(address)
    except Exception:
        parsed = urlparse("http://error-url.com")

    hostname = parsed.netloc.replace("www.", "")
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = f"{hostname}{path}"
    if query:
        full_url = f"{full_url}?{query}"
    registered_domain = extract_registered_domain(hostname)
    query_pairs = parse_qsl(query, keep_blank_values=True)
    path_analysis = analyze_url_path_segments(path)
    has_raw_ip = int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname)))

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
        "wallet",
        "invoice",
        "payment",
        "auth",
    ]
    trash_tld = (".tk", ".xyz", ".cc", ".top", ".pw", ".online", ".site", ".biz")
    popular_tld = (".com", ".net", ".org", ".co", ".edu", ".gov", ".info", ".edu.vn")

    return {
        "registered_domain": registered_domain,
        "url_len": len(full_url),
        "hostname_len": len(hostname),
        "path_len": len(path),
        "query_len": len(query),
        "dot_count": full_url.count("."),
        "dash_count": hostname.count("-"),
        "underscore_count": full_url.count("_"),
        "digit_ratio": len(re.findall(r"\d", full_url)) / (len(full_url) + 1),
        "entropy": round(calculate_string_entropy(full_url), 6),
        "is_trash_tld": int(hostname.endswith(trash_tld)),
        "is_popular_tld": int(any(hostname.endswith(tld) for tld in popular_tld)),
        "has_ip": has_raw_ip,
        "has_raw_ip": has_raw_ip,
        "is_exec": int(bool(re.search(r"\.(exe|apk|msi|bin|js|vbs|scr|zip)$", path))),
        "keyword_count": sum(1 for keyword in keywords if keyword in full_url),
        "subdomain_count": len(hostname.split(".")) - 2 if len(hostname.split(".")) > 2 else 0,
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
        "is_academic_domain": int(is_academic_domain(hostname)),
        "has_suspicious_file_ext": int(bool(re.search(r"\.(exe|apk|msi|bin|js|vbs|scr|zip)$", path))),
        **path_analysis,
    }


def enrich_url_features_with_domain_stats(features: dict[str, Any], domain_stats_artifact: Any) -> dict[str, Any]:
    """Apply train-time registered-domain priors used by the URL models."""
    enriched = dict(features)
    stats_payload = domain_stats_artifact if isinstance(domain_stats_artifact, dict) else {}
    stats_map = stats_payload.get("registered_domain_stats", {})
    global_benign_rate = float(stats_payload.get("global_benign_rate", 0.5))
    registered_domain = str(features.get("registered_domain", "") or "")
    domain_stats = stats_map.get(registered_domain)

    if domain_stats:
        enriched["registered_domain_benign_rate"] = float(domain_stats.get("benign_rate", global_benign_rate))
        enriched["registered_domain_seen_count"] = math.log1p(float(domain_stats.get("seen_count", 0.0)))
    else:
        enriched["registered_domain_benign_rate"] = global_benign_rate
        enriched["registered_domain_seen_count"] = 0.0

    return enriched


def extract_file_model_features(raw_bytes: bytes, filename: str) -> dict[str, Any]:
    """Extract static PE features used by the FILE models."""
    suffix = Path(filename or "uploaded.bin").suffix or ".bin"
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(raw_bytes)
            temp_path = Path(temp_file.name)

        pe = pefile.PE(str(temp_path))
        section_count = len(pe.sections)
        entropies = [section.get_entropy() for section in pe.sections]
        avg_entropy = sum(entropies) / section_count if section_count else 0.0
        max_entropy = max(entropies) if entropies else 0.0

        suspicious_sections = 0
        for section in pe.sections:
            if (section.Characteristics & 0x80000000) and (section.Characteristics & 0x20000000):
                suspicious_sections += 1

        import_count = 0
        dll_count = 0
        has_sensitive_api = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if not entry.imports:
                    continue
                import_count += len(entry.imports)
                for imported in entry.imports:
                    if imported.name in FILE_SENSITIVE_APIS:
                        has_sensitive_api = 1

        version_strings: dict[str, str] = {}
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                if getattr(file_info, "Key", b"") != b"StringFileInfo":
                    continue
                for string_table in getattr(file_info, "StringTable", []):
                    for raw_key, raw_value in getattr(string_table, "entries", {}).items():
                        key = raw_key.decode(errors="ignore") if isinstance(raw_key, bytes) else str(raw_key)
                        value = raw_value.decode(errors="ignore") if isinstance(raw_value, bytes) else str(raw_value)
                        if key and value:
                            version_strings[key] = value

        signature_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        lowercase_name = Path(filename or "uploaded.bin").name.lower()
        installer_like_name = any(hint in lowercase_name for hint in FILE_INSTALLER_NAME_HINTS)

        features = {
            "sections": section_count,
            "avg_entropy": round(avg_entropy, 4),
            "max_entropy": round(max_entropy, 4),
            "suspicious_sections": suspicious_sections,
            "dlls": dll_count,
            "imports": import_count,
            "has_sensitive_api": has_sensitive_api,
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "size_of_image": int(pe.OPTIONAL_HEADER.SizeOfImage),
            "has_version_info": 1 if hasattr(pe, "VS_FIXEDFILEINFO") else 0,
            "has_signature_dir": 1 if int(signature_directory.Size) > 0 else 0,
            "signature_size": int(signature_directory.Size),
            "installer_like_name": 1 if installer_like_name else 0,
            "company_name": version_strings.get("CompanyName", ""),
            "product_name": version_strings.get("ProductName", ""),
            "original_filename": version_strings.get("OriginalFilename", ""),
            "file_description": version_strings.get("FileDescription", ""),
        }
        pe.close()
        return features
    except pefile.PEFormatError as exc:
        raise HTTPException(status_code=400, detail=f"Uploaded file is not a supported PE executable: {exc}") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not extract FILE features: {exc}") from exc
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def normalize_file_prediction(raw_prediction: Any, cluster_to_label: dict[int, int] | None = None) -> tuple[str, bool]:
    """Normalize FILE model prediction to a stable label."""
    try:
        numeric_prediction = int(raw_prediction)
    except Exception:
        numeric_prediction = 1 if str(raw_prediction).strip().lower() in {"1", "true", "malware"} else 0

    if cluster_to_label is not None:
        numeric_prediction = int(cluster_to_label.get(numeric_prediction, numeric_prediction))

    is_malicious = numeric_prediction == 1
    return ("MALWARE" if is_malicious else "BENIGN"), is_malicious


def is_file_malicious_class(raw_class: Any) -> bool:
    """Determine whether a FILE model class represents malware."""
    try:
        return int(raw_class) == 1
    except Exception:
        return str(raw_class).strip().lower() in {"1", "true", "malware"}


def decode_url_prediction_label(raw_prediction: Any, label_encoder: Any) -> str:
    """Decode a URL model label to the training-time string representation."""
    decoded_prediction = raw_prediction
    try:
        if label_encoder is not None:
            decoded_prediction = label_encoder.inverse_transform([raw_prediction])[0]
    except Exception:
        decoded_prediction = raw_prediction

    return str(decoded_prediction).strip().lower()


def normalize_url_prediction(raw_prediction: Any, label_encoder: Any) -> tuple[str, bool]:
    """Normalize URL model prediction to a stable label."""
    label = decode_url_prediction_label(raw_prediction, label_encoder)
    is_malicious = label in URL_HARMFUL_LABELS
    if not label:
        try:
            is_malicious = int(raw_prediction) == 1
        except Exception:
            is_malicious = False
        label = "malicious" if is_malicious else "benign"

    display_label = "MALICIOUS" if is_malicious else "BENIGN"
    return display_label, is_malicious


def is_url_malicious_class(raw_class: Any, label_encoder: Any) -> bool:
    """Determine whether a URL model class represents a harmful label."""
    decoded = decode_url_prediction_label(raw_class, label_encoder)
    if decoded:
        return decoded in URL_HARMFUL_LABELS

    try:
        return int(raw_class) == 1
    except Exception:
        return False


def extract_positive_class_probability(
    model: Any,
    model_input: Any,
    is_positive_class: Any,
) -> float | None:
    """Return the probability assigned to the harmful class when available."""
    if not hasattr(model, "predict_proba"):
        return None

    try:
        probabilities = model.predict_proba(model_input)[0]
        classes = list(getattr(model, "classes_", []))
        if len(classes) != len(probabilities):
            return None

        for index, raw_class in enumerate(classes):
            if is_positive_class(raw_class):
                return float(probabilities[index])
    except Exception:
        return None

    return None


def build_model_input(model: Any, base_frame: pd.DataFrame, scaler: Any = None) -> Any:
    """Prepare the input shape/columns expected by a specific model."""
    model_input: Any = base_frame.copy()
    if scaler is not None:
        scaled = scaler.transform(base_frame)
        model_input = scaled

    feature_names_in = getattr(model, "feature_names_in_", None)
    if feature_names_in is not None:
        columns = list(feature_names_in)
        if hasattr(model_input, "shape") and len(columns) == model_input.shape[1]:
            if isinstance(model_input, pd.DataFrame):
                model_input = model_input.copy()
                model_input.columns = columns
            else:
                model_input = pd.DataFrame(model_input, columns=columns)
    elif isinstance(model_input, pd.DataFrame):
        model_input = model_input.to_numpy()

    return model_input


def build_consensus_verdict(harmful_votes: int, total_models: int) -> str:
    """Turn model votes into a frontend-friendly verdict."""
    if total_models <= 0 or harmful_votes <= 0:
        return "HAM"
    if harmful_votes >= max(1, (total_models // 2) + 1):
        return "THREAT"
    return "SUSPICIOUS"


def build_consensus_classification(verdict: str, analysis_type: str) -> str:
    """Return a stable asset classification that matches the ensemble verdict."""
    normalized_type = str(analysis_type or "").strip().lower()
    if verdict == "HAM":
        return "BENIGN"
    if verdict == "SUSPICIOUS":
        return "SUSPICIOUS"
    return "MALWARE" if normalized_type == "file" else "MALICIOUS"


def build_consensus_scores(harmful_votes: int, total_models: int, confidences: list[float]) -> tuple[float, float]:
    """Compute confidence and risk score for ensemble-style responses."""
    vote_ratio = harmful_votes / total_models if total_models else 0.0
    confidence = sum(confidences) / len(confidences) if confidences else vote_ratio
    # Weight vote ratio and confidence as fractions before converting to a percentage.
    risk_score = min(100.0, (vote_ratio * 0.7 + confidence * 0.3) * 100.0)
    return round(confidence, 6), round(risk_score, 2)


def finalize_asset_verdict(
    harmful_votes: int,
    total_models: int,
    risk_score: float,
) -> str:
    """Refine the ensemble verdict after trust/heuristic adjustments are applied."""
    majority_votes = max(1, (total_models // 2) + 1)
    if harmful_votes >= majority_votes and risk_score >= 60.0:
        return "THREAT"
    if risk_score < 28.0:
        return "HAM"
    if harmful_votes > 0 or risk_score >= 28.0:
        return "SUSPICIOUS"
    return "HAM"


def finalize_file_ensemble_verdict(
    harmful_votes: int,
    total_models: int,
    risk_score: float,
) -> tuple[str, str, float, str | None]:
    """Apply FILE-specific consensus rules before returning a public verdict."""
    majority_votes = max(1, (total_models // 2) + 1)
    benign_votes = max(0, total_models - harmful_votes)

    # Treat KMeans as a weak anomaly voter: a 2-of-3 benign consensus should
    # still be returned as benign instead of escalating to SUSPICIOUS.
    if total_models > 0 and benign_votes >= majority_votes:
        adjusted_risk = min(float(risk_score), 24.99)
        note = None
        if harmful_votes > 0:
            note = "Majority benign consensus overrode a minority anomaly vote."
        return "HAM", "BENIGN", adjusted_risk, note

    verdict = finalize_asset_verdict(harmful_votes, total_models, risk_score)
    classification_label = build_consensus_classification(verdict, "file")
    return verdict, classification_label, float(risk_score), None


def build_file_response_confidence(
    verdict: str,
    harmful_votes: int,
    total_models: int,
    malicious_confidence: float,
) -> float:
    """Expose a verdict-aligned confidence value for FILE responses."""
    base_confidence = max(0.0, min(1.0, float(malicious_confidence)))
    if verdict == "HAM":
        return round(1.0 - base_confidence, 6)
    if verdict == "SUSPICIOUS" and total_models > 0:
        return round(max(base_confidence, harmful_votes / total_models), 6)
    return round(base_confidence, 6)


def build_consensus_score_breakdown(
    harmful_votes: int,
    total_models: int,
    confidence: float,
    risk_score: float,
    trust_factor: float = 1.0,
) -> dict[str, Any]:
    """Return a frontend-friendly explanation of the ensemble score."""
    vote_ratio = harmful_votes / total_models if total_models else 0.0
    base_risk_score = (vote_ratio * 0.7 + confidence * 0.3) * 100.0
    vote_component = vote_ratio * 70.0
    confidence_component = confidence * 30.0

    return {
        "harmful_votes": harmful_votes,
        "total_models": total_models,
        "vote_ratio": round(vote_ratio, 6),
        "harmful_vote_percent": round(vote_ratio * 100.0, 2),
        "confidence_percent": round(confidence * 100.0, 2),
        "vote_weight_percent": 70,
        "confidence_weight_percent": 30,
        "vote_component_percent": round(vote_component, 2),
        "confidence_component_percent": round(confidence_component, 2),
        "risk_before_adjustment": round(base_risk_score, 2),
        "trust_adjustment_factor": round(trust_factor, 4),
        "risk_after_adjustment": round(risk_score, 2),
    }


def apply_probability_adjustment(base_probability: float | None, delta: float) -> float | None:
    """Blend model probability with heuristic risk signals without replacing the model outright."""
    if base_probability is None:
        return None
    return float(min(0.99, max(0.01, base_probability + delta)))


def compute_url_probability_adjustment(url: str, features: dict[str, Any]) -> tuple[float, list[str]]:
    """Convert URL heuristics into a bounded probability adjustment instead of a hard override."""
    address = str(url or "").strip().lower()
    parsed = urlparse(address if "://" in address else f"http://{address}")
    host = parsed.netloc.split("@")[-1].split(":")[0].replace("www.", "")
    registered_domain = str(features.get("registered_domain", "") or "").strip().lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    notes: list[str] = []
    risk_delta = 0.0

    brand_hits = sorted([brand for brand in TRUSTED_BRAND_KEYWORDS if brand and brand in address])
    host_is_trusted = bool(
        host
        and (domain_matches_any_suffix(host, TRUSTED_OFFICIAL_DOMAINS) or host.endswith((".gov", ".mil", ".gov.vn")))
    )
    brand_mismatch = bool(brand_hits) and not host_is_trusted
    suspicious_tld = tld in SUSPICIOUS_TLDS or int(features.get("is_trash_tld", 0)) == 1
    has_raw_ip = int(features.get("has_raw_ip", features.get("has_ip", 0))) == 1
    is_https = int(features.get("is_https", 0)) == 1
    keyword_count = int(features.get("keyword_count", 0))
    dash_count = int(features.get("dash_count", 0))
    subdomain_count = int(features.get("subdomain_count", 0))
    query_param_count = int(features.get("query_param_count", 0))
    has_suspicious_file_ext = int(features.get("has_suspicious_file_ext", 0)) == 1
    has_clean_resource_shape = (
        is_https
        and (
            int(features.get("has_single_resource_id_path", 0)) == 1
            or int(features.get("has_mixed_clean_path", 0)) == 1
        )
    )
    has_clean_academic_shape = (
        is_https
        and int(features.get("is_academic_domain", 0)) == 1
        and int(features.get("path_depth", 0)) == 0
        and int(features.get("query_len", 0)) == 0
    )
    giveaway_hit = any(keyword in address for keyword in GIVEAWAY_KEYWORDS)
    is_shortener = bool(
        registered_domain
        and domain_matches_any_suffix(registered_domain, REDIRECT_SHORTENER_DOMAINS | TRUSTED_REDIRECT_DOMAINS)
    )
    has_clean_structure = (
        not suspicious_tld
        and not has_raw_ip
        and int(features.get("is_exec", 0)) == 0
        and int(features.get("has_number_in_host", 0)) == 0
        and keyword_count == 0
        and subdomain_count <= 2
        and query_param_count <= 2
        and not has_suspicious_file_ext
        and int(features.get("percent_encoding_count", 0)) == 0
    )

    if has_raw_ip:
        try:
            host_ip = ipaddress.ip_address(host)
            risk_delta += 0.14 if (host_ip.is_private or host_ip.is_loopback or host_ip.is_reserved) else 0.2
        except ValueError:
            risk_delta += 0.18
        notes.append("Raw-IP hostname increased risk for this URL.")

    if is_shortener and not is_https:
        risk_delta += 0.18
        notes.append("Non-HTTPS shortener increased risk for this URL.")

    if suspicious_tld and brand_mismatch:
        risk_delta += 0.28
        notes.append("Brand-impersonation and disposable-TLD heuristics increased risk for this URL.")
    elif brand_mismatch and (keyword_count >= 1 or dash_count >= 1 or subdomain_count >= 2):
        risk_delta += 0.2
        notes.append("Brand-impersonation heuristics increased risk for this URL.")

    if suspicious_tld and giveaway_hit:
        risk_delta += 0.16
        notes.append("Giveaway wording with suspicious TLD increased risk for this URL.")

    if host_is_trusted and has_clean_structure:
        risk_delta -= 0.32
        notes.append(f"Trusted host heuristic reduced risk for {host}.")
    if has_clean_structure and has_clean_resource_shape:
        risk_delta -= 0.08
        notes.append("Clean HTTPS path structure reduced risk for this URL.")
    if has_clean_structure and has_clean_academic_shape:
        risk_delta -= 0.08
        notes.append("Clean academic HTTPS structure reduced risk for this URL.")

    return max(-0.4, min(0.4, risk_delta)), notes


def compute_file_trust_adjustment(filename: str, features: dict[str, Any], harmful_votes: int, total_models: int) -> tuple[float, str | None]:
    """Reduce false positives for clearly installer-like, signed setup files."""
    lowercase_name = str(filename or "").strip().lower()
    installer_like_name = bool(features.get("installer_like_name")) or any(
        hint in lowercase_name for hint in FILE_INSTALLER_NAME_HINTS
    )
    has_packaging_signals = bool(features.get("has_signature_dir")) and bool(features.get("has_version_info"))
    suspicious_sections = int(features.get("suspicious_sections", 0))
    has_sensitive_api = int(features.get("has_sensitive_api", 0))
    majority_votes = max(1, (total_models // 2) + 1)

    if not installer_like_name or not has_packaging_signals or suspicious_sections > 0:
        return 1.0, None

    if harmful_votes >= total_models:
        return 1.0, None

    if harmful_votes >= majority_votes:
        factor = 0.65 if has_sensitive_api else 0.7
        return factor, "Installer-like signed file heuristic reduced risk for a setup-style binary."

    if harmful_votes > 0:
        factor = 0.8
        return factor, "Installer-like signed file heuristic reduced risk for a setup-style binary."

    return 1.0, None


def compute_url_phishing_floor(url: str, features: dict[str, Any]) -> tuple[float, str | None]:
    """Raise the minimum URL risk when classic phishing traits are present."""
    address = str(url or "").strip().lower()
    parsed = urlparse(address if "://" in address else f"http://{address}")
    host = parsed.netloc.split("@")[-1].split(":")[0].replace("www.", "")

    brand_hits = sorted([brand for brand in TRUSTED_BRAND_KEYWORDS if brand and brand in address])
    host_is_trusted = bool(
        host
        and (domain_matches_any_suffix(host, TRUSTED_OFFICIAL_DOMAINS) or host.endswith((".gov", ".mil", ".gov.vn")))
    )
    brand_mismatch = bool(brand_hits) and not host_is_trusted
    is_trash_tld = int(features.get("is_trash_tld", 0)) == 1
    has_ip = int(features.get("has_ip", 0)) == 1
    keyword_count = int(features.get("keyword_count", 0))
    dash_count = int(features.get("dash_count", 0))

    if has_ip:
        return 78.0, "Raw-IP hostname heuristic increased risk for this URL."

    if is_trash_tld and brand_mismatch and keyword_count >= 2:
        return 64.0, "Brand-impersonation and disposable-TLD heuristics increased risk for this URL."

    if brand_mismatch and (keyword_count >= 3 or dash_count >= 3):
        return 56.0, "Brand-impersonation heuristics increased risk for this URL."

    if is_trash_tld and keyword_count >= 3:
        return 54.0, "Disposable-TLD and phishing-keyword heuristics increased risk for this URL."

    return 0.0, None


def compute_url_trust_adjustment(url: str, features: dict[str, Any], harmful_votes: int, total_models: int) -> tuple[float, str | None]:
    """Dampen minority-vote risk for clearly trusted, structurally clean domains."""
    address = str(url or "").strip().lower()
    parsed = urlparse(address if "://" in address else f"http://{address}")
    host = parsed.netloc.split("@")[-1].split(":")[0].replace("www.", "")
    is_trusted_host = host and (
        domain_matches_any_suffix(host, TRUSTED_OFFICIAL_DOMAINS) or host.endswith((".gov", ".mil", ".gov.vn"))
    )
    majority_votes = max(1, (total_models // 2) + 1)
    has_clean_structure = (
        int(features.get("is_trash_tld", 0)) == 0
        and int(features.get("has_ip", 0)) == 0
        and int(features.get("is_exec", 0)) == 0
        and int(features.get("has_number_in_host", 0)) == 0
        and int(features.get("keyword_count", 0)) == 0
        and int(features.get("subdomain_count", 0)) <= 2
        and int(features.get("query_param_count", 0)) <= 2
        and int(features.get("percent_encoding_count", 0)) == 0
    )
    has_clean_resource_id_shape = (
        int(features.get("is_https", 0)) == 1
        and float(features.get("registered_domain_benign_rate", 0.5)) >= 0.6
        and (
            int(features.get("has_single_resource_id_path", 0)) == 1
            or int(features.get("has_mixed_clean_path", 0)) == 1
        )
    )
    has_clean_shared_host_slug_shape = (
        int(features.get("is_https", 0)) == 1
        and int(features.get("path_depth", 0)) in {2, 3}
        and 2 <= int(features.get("path_token_count", 0)) <= 18
        and int(features.get("query_len", 0)) == 0
        and int(features.get("has_suspicious_file_ext", 0)) == 0
        and int(features.get("numeric_path_segment_count", 0)) == 0
        and float(features.get("special_ratio", 0.0)) <= 0.08
        and int(features.get("has_mixed_clean_path", 0)) == 1
    )
    has_clean_academic_home_shape = (
        int(features.get("is_https", 0)) == 1
        and int(features.get("is_academic_domain", 0)) == 1
        and int(features.get("path_depth", 0)) == 0
        and int(features.get("query_len", 0)) == 0
        and int(features.get("keyword_count", 0)) == 0
        and int(features.get("has_suspicious_file_ext", 0)) == 0
        and int(features.get("subdomain_count", 0)) <= 3
        and float(features.get("registered_domain_benign_rate", 0.5)) >= 0.6
    )

    if is_trusted_host and has_clean_structure and harmful_votes < majority_votes:
        return 0.85, f"Trusted host heuristic applied for {host}; minority-vote risk was reduced."
    if has_clean_structure and has_clean_academic_home_shape:
        if harmful_votes >= total_models and total_models > 0:
            return 0.16, "Clean academic HTTPS landing-page heuristic reduced unanimous URL risk."
        if harmful_votes < majority_votes:
            return 0.4, "Clean academic HTTPS landing-page heuristic reduced split-vote URL risk."
    if has_clean_structure and has_clean_resource_id_shape and harmful_votes < majority_votes:
        return 0.38, "Clean HTTPS resource-ID path heuristic reduced split-vote URL risk."
    if has_clean_structure and has_clean_shared_host_slug_shape:
        if harmful_votes >= total_models and total_models > 0:
            return 0.18, "Clean HTTPS content-slug heuristic reduced unanimous shared-host URL risk."
        if harmful_votes < majority_votes:
            return 0.42, "Clean HTTPS content-slug heuristic reduced split-vote shared-host URL risk."

    return 1.0, None


def analyze_uploaded_file_content(filename: str, raw_bytes: bytes) -> dict[str, Any]:
    """Run all FILE models and return a normalized API payload."""
    artifacts = load_file_model_artifacts()
    features = extract_file_model_features(raw_bytes, filename)
    feature_frame = pd.DataFrame(
        [[
            features["sections"],
            features["avg_entropy"],
            features["max_entropy"],
            features["suspicious_sections"],
            features["dlls"],
            features["imports"],
            features["has_sensitive_api"],
            features["image_base"],
            features["size_of_image"],
            features["has_version_info"],
        ]],
        columns=FILE_FEATURE_COLUMNS,
    )

    model_results: list[dict[str, Any]] = []
    harmful_votes = 0
    confidence_values: list[float] = []

    for entry in artifacts["models"]:
        model = entry["model"]
        is_kmeans_model = "kmeans" in entry["name"].lower()
        use_scaler = is_kmeans_model and artifacts["scaler"] is not None
        model_input = build_model_input(model, feature_frame, scaler=artifacts["scaler"] if use_scaler else None)
        raw_prediction = model.predict(model_input)[0]
        cluster_to_label = artifacts["kmeans_cluster_to_label"] if is_kmeans_model else None
        label, is_malicious = normalize_file_prediction(raw_prediction, cluster_to_label=cluster_to_label)
        confidence = extract_positive_class_probability(model, model_input, is_file_malicious_class)

        if is_malicious:
            harmful_votes += 1
        if confidence is not None:
            confidence_values.append(confidence)
        elif is_malicious:
            # Unsupervised anomaly models do not expose calibrated probabilities.
            confidence_values.append(0.6)

        model_results.append(
            {
                "model": entry["name"],
                "prediction": label,
                "is_malicious": is_malicious,
                "confidence": round(confidence, 6) if confidence is not None else None,
            }
        )

    confidence, risk_score = build_consensus_scores(harmful_votes, len(model_results), confidence_values)
    trust_factor, trust_note = compute_file_trust_adjustment(filename, features, harmful_votes, len(model_results))
    if trust_factor < 1.0:
        risk_score = round(risk_score * trust_factor, 2)

    verdict, classification_label, risk_score, consensus_note = finalize_file_ensemble_verdict(
        harmful_votes,
        len(model_results),
        risk_score,
    )
    response_confidence = build_file_response_confidence(
        verdict,
        harmful_votes,
        len(model_results),
        confidence,
    )
    score_breakdown = build_consensus_score_breakdown(
        harmful_votes=harmful_votes,
        total_models=len(model_results),
        confidence=confidence,
        risk_score=risk_score,
        trust_factor=trust_factor,
    )

    summary: list[str] = [
        f"{harmful_votes}/{len(model_results)} FILE models flagged this sample as malware.",
        f"Entropy profile: avg={features['avg_entropy']}, max={features['max_entropy']}.",
    ]
    if features["suspicious_sections"] > 0:
        summary.append("Executable contains writable-and-executable sections.")
    if features["has_sensitive_api"]:
        summary.append("Sensitive Windows API usage detected in import table.")
    if not features["has_version_info"]:
        summary.append("Version metadata is missing, which is common in suspicious binaries.")
    if trust_note:
        summary.append(trust_note)
    if consensus_note:
        summary.append(consensus_note)
    if artifacts["kmeans_cluster_to_label"]:
        summary.append(f"KMeans cluster mapping: {artifacts['kmeans_cluster_to_label']}.")

    return {
        "analysis_type": "file",
        "asset_type_label": "FILE MALWARE",
        "classification_label": classification_label,
        "verdict": verdict,
        "confidence": response_confidence,
        "risk_score": risk_score,
        "target": filename,
        "model_count": len(model_results),
        "harmful_votes": harmful_votes,
        "model_results": model_results,
        "features": features,
        "score_breakdown": score_breakdown,
        "summary": summary,
        "source_dir": artifacts["source_dir"],
    }


def analyze_url_content(url: str) -> dict[str, Any]:
    """Run all URL models and return a normalized API payload."""
    cleaned_url = str(url).strip()
    if not cleaned_url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    artifacts = load_url_model_artifacts()
    features = enrich_url_features_with_domain_stats(extract_url_model_features(cleaned_url), artifacts.get("domain_stats"))
    feature_frame = pd.DataFrame([features])
    probability_adjustment, adjustment_notes = compute_url_probability_adjustment(cleaned_url, features)

    model_results: list[dict[str, Any]] = []
    harmful_votes = 0
    confidence_values: list[float] = []

    for entry in artifacts["models"]:
        model = entry["model"]
        model_name = entry["name"]
        feature_names = artifacts["feature_names_xgb"] if model_name == "xgb" and artifacts["feature_names_xgb"] else artifacts["feature_names"]
        scaler = artifacts["scaler_xgb"] if model_name == "xgb" and artifacts["scaler_xgb"] is not None else None
        ordered_frame = feature_frame[feature_names]
        model_input = build_model_input(model, ordered_frame, scaler=scaler)
        raw_prediction = model.predict(model_input)[0]
        label, is_malicious = normalize_url_prediction(raw_prediction, artifacts["label_encoder"])
        harm_probability = extract_positive_class_probability(
            model,
            model_input,
            lambda raw_class: is_url_malicious_class(raw_class, artifacts["label_encoder"]),
        )
        adjusted_harm_probability = apply_probability_adjustment(harm_probability, probability_adjustment)

        if adjusted_harm_probability is not None:
            is_malicious = adjusted_harm_probability >= 0.5
            label = "MALICIOUS" if is_malicious else "BENIGN"
            display_confidence = adjusted_harm_probability if is_malicious else 1.0 - adjusted_harm_probability
            confidence_values.append(adjusted_harm_probability)
        else:
            display_confidence = harm_probability

        if is_malicious:
            harmful_votes += 1

        model_results.append(
            {
                "model": entry["name"],
                "prediction": label,
                "is_malicious": is_malicious,
                "confidence": round(display_confidence, 6) if display_confidence is not None else None,
            }
        )

    confidence, risk_score = build_consensus_scores(harmful_votes, len(model_results), confidence_values)
    verdict = finalize_asset_verdict(harmful_votes, len(model_results), risk_score)
    classification_label = build_consensus_classification(verdict, "url")
    score_breakdown = build_consensus_score_breakdown(
        harmful_votes=harmful_votes,
        total_models=len(model_results),
        confidence=confidence,
        risk_score=risk_score,
        trust_factor=1.0,
    )

    summary: list[str] = [
        f"{harmful_votes}/{len(model_results)} URL models flagged this URL as malicious.",
        f"Entropy={features['entropy']}, keyword_count={features['keyword_count']}, subdomains={features['subdomain_count']}.",
    ]
    summary.extend(adjustment_notes)
    if features["is_trash_tld"]:
        summary.append("URL uses a high-risk or disposable TLD.")
    if features["has_raw_ip"] or features["has_ip"]:
        summary.append("URL hostname contains a raw IP address.")
    if features["is_exec"]:
        summary.append("URL path resembles an executable/download payload.")
    if features["has_number_in_host"]:
        summary.append("Hostname contains digits, often seen in suspicious lookalike domains.")
    for skipped in artifacts.get("skipped_models", []):
        summary.append(f"Skipped URL model '{skipped['name']}' because it could not be loaded: {skipped['reason']}.")

    return {
        "analysis_type": "url",
        "asset_type_label": "URL REPUTATION",
        "classification_label": classification_label,
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "target": cleaned_url,
        "model_count": len(model_results),
        "harmful_votes": harmful_votes,
        "model_results": model_results,
        "features": features,
        "score_breakdown": score_breakdown,
        "summary": summary,
        "source_dir": artifacts["source_dir"],
    }


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """Load model once at startup and store in app state."""
    email_runtime = load_email_runtime()
    app_instance.state.email_runtime = email_runtime
    app_instance.state.threshold = float(email_runtime.get("threshold", DEFAULT_THRESHOLD))
    yield


app = FastAPI(
    title="Email Threat Analyzer API",
    description="Hybrid static + ML analysis for raw .eml and pasted email text.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    """Simple health route."""
    return {"status": "ok", "message": "Email threat analyzer API is running."}


@app.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)) -> dict[str, Any]:
    """Analyze an uploaded .eml-like file."""
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

        raw_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file is too large. Maximum allowed size is {MAX_UPLOAD_LABEL}.",
            )

        parsed = parse_email_payload(raw_bytes)
        return analyze_content(
            filename=file.filename,
            subject=parsed["subject"],
            body=parsed["body"],
            sender=parsed["sender"],
            reply_to=parsed["reply_to"],
            return_path=parsed["return_path"],
            has_html=parsed["has_html"],
            html_urls=parsed["html_urls"],
            authentication_results=parsed["authentication_results"],
            received_spf_headers=parsed["received_spf"],
            dkim_signatures=parsed["dkim_signatures"],
            attachment_names=parsed["attachment_names"],
            attachment_extensions=parsed["attachment_extensions"],
            input_source="uploaded_email",
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}") from exc


@app.post("/analyze-text")
async def analyze_text(payload: AnalyzeTextRequest) -> dict[str, Any]:
    """Analyze manually pasted subject/body text using the same ML pipeline."""
    try:
        subject = payload.subject or ""
        body = payload.body or ""
        if not subject.strip() and not body.strip():
            raise HTTPException(status_code=400, detail="Provide at least one of: subject or body.")

        combined_text = f"{subject}\n{body}"
        has_html = bool(re.search(r"<html|<body|<table|<div|<a\s+href|<p\b", combined_text, flags=re.IGNORECASE))

        return analyze_content(
            filename="manual-input",
            subject=subject,
            body=body,
            sender="",
            reply_to="",
            return_path="",
            has_html=has_html,
            html_urls=extract_urls_from_html(combined_text) if has_html else [],
            authentication_results=[],
            received_spf_headers=[],
            dkim_signatures=[],
            attachment_names=[],
            attachment_extensions=[],
            input_source="manual_text",
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}") from exc


@app.post("/analyze-url")
async def analyze_url(payload: AnalyzeUrlRequest) -> dict[str, Any]:
    """Analyze a URL using the models stored in URL/models."""
    try:
        return analyze_url_content(payload.url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}") from exc


@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """Analyze an uploaded executable using the models stored in FILE/models."""
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

        raw_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file is too large. Maximum allowed size is {MAX_UPLOAD_LABEL}.",
            )

        return analyze_uploaded_file_content(file.filename, raw_bytes)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal server error: {exc}") from exc


# Run:
# uvicorn app:app --reload
