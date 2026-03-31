"""Shared email parsing, preprocessing, and lightweight scoring helpers."""

from __future__ import annotations

import html
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any

URL_REGEX = re.compile(r"http[s]?://\S+|www\.\S+", flags=re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", flags=re.IGNORECASE)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
NON_ALNUM_REGEX = re.compile(r"[^a-z0-9_]+")
MULTISPACE_REGEX = re.compile(r"\s+")
SUBJECT_REGEX = re.compile(r"(?im)^subject:\s*(.*)$")

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
    "invoice",
    "payment",
    "gift",
    "claim",
    "reset",
    "click",
}
FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "webtv.net", "earthlink.net"}


def strip_html(html_text: str) -> str:
    """Remove HTML tags and decode HTML entities."""
    return html.unescape(HTML_TAG_REGEX.sub(" ", html_text))


def fallback_subject_body(text: str) -> tuple[str, str]:
    """Fallback parser for malformed raw email payloads."""
    subject_match = SUBJECT_REGEX.search(text)
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def parse_email_bytes(raw_bytes: bytes) -> dict[str, Any]:
    """Extract subject/body/header fields from a raw email payload."""
    fallback_text = raw_bytes.decode("utf-8", errors="ignore")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = str(msg.get("Subject", "") or "")
        sender = str(msg.get("From", "") or "")
        reply_to = str(msg.get("Reply-To", "") or "")
        return_path = str(msg.get("Return-Path", "") or "")
        has_html = False
        body_chunks: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_disposition() == "attachment":
                    continue

                content_type = part.get_content_type()
                try:
                    content = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    content = payload.decode(charset, errors="ignore")

                if not isinstance(content, str):
                    continue

                if content_type == "text/html":
                    has_html = True
                    content = strip_html(content)
                body_chunks.append(content)
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True) or b""
                charset = msg.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="ignore")

            if isinstance(content, str):
                if content_type == "text/html":
                    has_html = True
                    content = strip_html(content)
                body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if not body:
            _, body = fallback_subject_body(fallback_text)

        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "has_html": has_html,
            "raw_text": fallback_text,
        }
    except Exception:
        subject, body = fallback_subject_body(fallback_text)
        return {
            "subject": subject,
            "body": body,
            "sender": "",
            "reply_to": "",
            "return_path": "",
            "has_html": bool(HTML_TAG_REGEX.search(fallback_text)),
            "raw_text": fallback_text,
        }


def parse_email_file(file_path: Path) -> dict[str, Any]:
    """Parse a raw email file from disk."""
    return parse_email_bytes(file_path.read_bytes())


def build_combined_text(subject: str, body: str) -> str:
    """Build the exact text template used for model training and inference."""
    return f"subjecttoken {subject}\nbodytoken {body}".strip()


def clean_text(text: str) -> str:
    """Normalize text while preserving durable email-spam signals."""
    text = html.unescape(text).lower()
    text = URL_REGEX.sub(" urltoken ", text)
    text = EMAIL_REGEX.sub(" emailtoken ", text)
    text = NON_ALNUM_REGEX.sub(" ", text)
    text = MULTISPACE_REGEX.sub(" ", text).strip()
    return text


def extract_urls(text: str) -> list[str]:
    """Extract a simple list of URLs from raw text."""
    return re.findall(r"http[s]?://\S+|www\.\S+", text, flags=re.IGNORECASE)


def parse_sender_domain(sender_value: str) -> str:
    """Return the sender domain when available."""
    _display_name, address = parseaddr(sender_value or "")
    address = address.strip().lower()
    if "@" not in address:
        return ""
    return address.split("@", 1)[1]


def detect_suspicious_signs(
    *,
    subject: str,
    body: str,
    sender: str,
    has_html: bool,
    spam_probability: float,
    threshold: float,
) -> list[str]:
    """Return human-readable suspicious indicators for prediction UX."""
    combined = build_combined_text(subject, body)
    cleaned = clean_text(combined)
    urls = extract_urls(body)
    signs: list[str] = []

    if spam_probability >= threshold:
        signs.append(f"Model spam probability {spam_probability:.2f} is above threshold {threshold:.2f}.")
    else:
        signs.append(f"Model spam probability {spam_probability:.2f} is below threshold {threshold:.2f}.")

    if urls:
        signs.append(f"Contains {len(urls)} URL(s).")
    if len(urls) >= 5:
        signs.append("Email contains many links, which is common in campaigns and phishing lures.")

    sender_domain = parse_sender_domain(sender)
    if sender_domain in FREE_EMAIL_DOMAINS:
        signs.append(f"Sender uses a free email domain ({sender_domain}).")

    keyword_hits = sorted({keyword for keyword in PHISHING_KEYWORDS if keyword in cleaned})
    if keyword_hits:
        preview = ", ".join(keyword_hits[:6])
        signs.append(f"Contains suspicious keywords: {preview}.")

    if has_html:
        signs.append("HTML email content detected.")

    if len(cleaned) > 12000:
        signs.append("Email body is unusually long compared with the training set.")

    return signs


def load_labeled_dataset(dataset_root: Path) -> tuple[list[str], list[int], dict[str, int]]:
    """Load ham/spam folders recursively and return cleaned training texts."""
    texts: list[str] = []
    labels: list[int] = []
    counts = {"ham": 0, "spam": 0}

    for label_name, label_value in (("ham", 0), ("spam", 1)):
        folder = dataset_root / label_name
        if not folder.is_dir():
            raise FileNotFoundError(f"Expected dataset folder to exist: {folder}")

        for file_path in sorted(folder.rglob("*")):
            if not file_path.is_file():
                continue

            parsed = parse_email_file(file_path)
            combined = build_combined_text(parsed["subject"], parsed["body"])
            cleaned = clean_text(combined)
            if not cleaned:
                continue

            texts.append(cleaned)
            labels.append(label_value)
            counts[label_name] += 1

    return texts, labels, counts
