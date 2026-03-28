"""Central configuration constants for the email threat analyzer backend."""

from __future__ import annotations

import os
from pathlib import Path
import re


BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT_DIR = BACKEND_DIR.parent


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
    if not raw:
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]


MODEL_FILENAME = "spam_model.joblib"
_model_env = os.getenv("MODEL_PATH", "").strip()
if _model_env:
    _model_env_path = Path(_model_env).expanduser()
    MODEL_PATH = _model_env_path if _model_env_path.is_absolute() else (BACKEND_DIR / _model_env_path).resolve()
else:
    MODEL_PATH = BACKEND_DIR / MODEL_FILENAME

MODEL_FALLBACK_PATHS: list[Path] = [BACKEND_DIR / MODEL_FILENAME, REPO_ROOT_DIR / MODEL_FILENAME]
if MODEL_PATH not in MODEL_FALLBACK_PATHS:
    MODEL_FALLBACK_PATHS.insert(0, MODEL_PATH)

ALLOW_STARTUP_WITHOUT_MODEL = _parse_bool_env("ALLOW_STARTUP_WITHOUT_MODEL", True)

CORS_ALLOW_ORIGINS = _parse_cors_origins()
CORS_ALLOW_CREDENTIALS = _parse_bool_env("CORS_ALLOW_CREDENTIALS", False)

DEFAULT_THRESHOLD = 0.5
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB

RISK_SPAM_THRESHOLD = 72.0
RISK_SUSPICIOUS_THRESHOLD = 45.0

URL_REGEX = re.compile(r"http[s]?://\S+|www\.\S+", flags=re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", flags=re.IGNORECASE)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
NON_ALNUM_REGEX = re.compile(r"[^a-z0-9\s]+")
MULTISPACE_REGEX = re.compile(r"\s+")
SUBJECT_REGEX = re.compile(r"(?im)^subject:\s*(.*)$")
INVISIBLE_CHAR_REGEX = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]")
CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x1F\x7F]")

TRAILING_URL_PUNCTUATION = ")]}.,;:'\"!?`"
LEADING_URL_PUNCTUATION = "([{<'\""
ASSET_URL_HOST_BLOCKLIST = {"fonts.gstatic.com", "fonts.googleapis.com"}
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "work", "gq", "tk", "cf", "ml", "ga", "ru"}
TRACKING_HINTS = ("utm_", "redirect", "trk", "track", "click", "ref=", "fbclid", "gclid", "mc_eid")

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
