from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

import pandas as pd
from email import policy
from email.parser import BytesParser


NUMERIC_FEATURES = [
    "num_urls",
    "email_length",
    "num_exclamation",
    "upper_case_ratio",
    "url_to_text_ratio",
    "has_generic_greeting",
    "is_free_email",
]
FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com"}
URL_TOKEN_REGEX = re.compile(
    r"(\[link\]|\[url\]|https?://\S+|www\.\S+|\b\w+\.(?:com|net|org|info|biz|xyz|tk)\b)",
    flags=re.IGNORECASE,
)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
MULTISPACE_REGEX = re.compile(r"\s+")
SUBJECT_REGEX = re.compile(r"(?im)^subject:\s*(.*)$")
FROM_REGEX = re.compile(r"(?im)^from:\s*(.*)$")


def strip_html(html_text: str) -> str:
    return html.unescape(HTML_TAG_REGEX.sub(" ", html_text or ""))


def normalize_email_text(text: str) -> str:
    return MULTISPACE_REGEX.sub(" ", str(text or "").strip().lower()).strip()


def normalize_email_text_for_hash(text: str) -> str:
    return normalize_email_text(text)


def _fallback_email_parts(text: str) -> tuple[str, str, str]:
    subject_match = SUBJECT_REGEX.search(text or "")
    sender_match = FROM_REGEX.search(text or "")
    subject = subject_match.group(1).strip() if subject_match else ""
    sender = sender_match.group(1).strip() if sender_match else ""
    parts = re.split(r"\r?\n\r?\n", text or "", maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body, sender


def _decode_part_content(part: Any) -> str:
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
    return payload.decode(charset, errors="ignore")


def extract_email_parts_from_bytes(raw_bytes: bytes) -> tuple[str, str, str]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = str(message.get("Subject", "") or "")
        sender = str(message.get("From", "") or "")
        body_chunks: list[str] = []

        if message.is_multipart():
            for part in message.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_disposition() == "attachment":
                    continue

                content_type = part.get_content_type()
                content = _decode_part_content(part)
                if content_type == "text/html":
                    content = strip_html(content)
                if content:
                    body_chunks.append(content)
        else:
            content_type = message.get_content_type()
            content = _decode_part_content(message)
            if content_type == "text/html":
                content = strip_html(content)
            if content:
                body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if body:
            return subject, body, sender

        fallback_subject, fallback_body, fallback_sender = _fallback_email_parts(
            raw_bytes.decode("utf-8", errors="ignore")
        )
        return subject or fallback_subject, fallback_body, sender or fallback_sender
    except Exception:
        return _fallback_email_parts(raw_bytes.decode("utf-8", errors="ignore"))


def extract_email_parts_from_path(file_path: str | Path) -> tuple[str, str, str]:
    path = Path(file_path).expanduser().resolve()
    return extract_email_parts_from_bytes(path.read_bytes())


def extract_email_parts_from_text(text: str) -> tuple[str, str, str]:
    return extract_email_parts_from_bytes(str(text or "").encode("utf-8", errors="ignore"))


def build_feature_frame(subject: str, body: str, sender: str = "") -> pd.DataFrame:
    safe_subject = str(subject or "")
    safe_body = str(body or "")
    safe_sender = str(sender or "")

    raw_text = f"From: {safe_sender}\nSubject: {safe_subject}\n\n{safe_body}"
    urls = URL_TOKEN_REGEX.findall(raw_text.lower())
    full_text = f"{safe_subject} {safe_body}".strip()
    clean_text = URL_TOKEN_REGEX.sub(" url ", full_text).lower()
    clean_text = MULTISPACE_REGEX.sub(" ", clean_text).strip()

    email_length = len(full_text) if full_text else 1
    upper_case_count = sum(1 for character in full_text if character.isupper())
    sender_domain = safe_sender.split("@")[-1].lower() if "@" in safe_sender else ""

    feature_row = {
        "num_urls": len(urls),
        "email_length": email_length,
        "num_exclamation": full_text.count("!"),
        "upper_case_ratio": round(upper_case_count / email_length, 4),
        "url_to_text_ratio": round(len(urls) / email_length, 6),
        "has_generic_greeting": int(
            bool(re.search(r"(dear|hi|hello)\s+(customer|user|winner|friend|student)", full_text.lower()))
        ),
        "is_free_email": int(sender_domain in FREE_EMAIL_DOMAINS),
        "full_clean_text": clean_text,
    }

    return pd.DataFrame([feature_row])


def build_training_record(row: pd.Series) -> dict[str, str]:
    def safe_text(value: object) -> str:
        if pd.isna(value):
            return ""
        return str(value or "")

    if {"subject", "body"}.issubset(row.index):
        subject = safe_text(row.get("subject", ""))
        body = safe_text(row.get("body", ""))
        sender = safe_text(row.get("sender", ""))
        if not subject and not body:
            if "email" in row.index and safe_text(row.get("email", "")):
                subject, body, sender = extract_email_parts_from_text(safe_text(row.get("email", "")))
            else:
                body = safe_text(row.get("text", row.get("full_clean_text", "")))
    elif "email" in row.index and safe_text(row.get("email", "")):
        subject, body, sender = extract_email_parts_from_text(safe_text(row.get("email", "")))
    else:
        text = safe_text(row.get("text", row.get("full_clean_text", "")))
        subject = safe_text(row.get("title", ""))
        body = text
        sender = safe_text(row.get("sender", ""))

    text = normalize_email_text(f"{subject} {body}")
    return {
        "subject": subject,
        "body": body,
        "sender": sender,
        "text": text,
    }
