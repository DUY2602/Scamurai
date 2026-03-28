"""Email parsing utilities for raw .eml-like inputs."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import re
from typing import Any

from config import SUBJECT_REGEX
from services.text_processing import strip_html, unique_preserve_order


def fallback_subject_body(text: str) -> tuple[str, str]:
    """Fallback extraction for malformed emails."""
    subject_match = SUBJECT_REGEX.search(text)
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def fallback_headers(text: str) -> tuple[str, str, str]:
    """Fallback header extraction for malformed emails."""
    from_match = re.search(r"(?im)^from:\s*(.*)$", text)
    reply_to_match = re.search(r"(?im)^reply-to:\s*(.*)$", text)
    return_path_match = re.search(r"(?im)^return-path:\s*(.*)$", text)
    return (
        from_match.group(1).strip() if from_match else "",
        reply_to_match.group(1).strip() if reply_to_match else "",
        return_path_match.group(1).strip() if return_path_match else "",
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
    """Parse raw email and extract text + metadata for analysis."""
    decoded_text = raw_bytes.decode("utf-8", errors="ignore")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        subject = str(msg.get("Subject", "") or "")
        sender = str(msg.get("From", "") or "")
        reply_to = str(msg.get("Reply-To", "") or "")
        return_path = str(msg.get("Return-Path", "") or "")

        has_html = False
        body_chunks: list[str] = []
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
                    content = strip_html(content)
                if content:
                    body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if not body:
            _, body = fallback_subject_body(decoded_text)

        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "has_html": has_html,
            "attachment_names": attachment_names,
            "attachment_extensions": unique_preserve_order(attachment_extensions),
        }
    except Exception:
        subject, body = fallback_subject_body(decoded_text)
        sender, reply_to, return_path = fallback_headers(decoded_text)
        has_html = bool(re.search(r"<html|<body|<table|<div|<a\s+href|<p\b", decoded_text, flags=re.IGNORECASE))
        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "has_html": has_html,
            "attachment_names": [],
            "attachment_extensions": [],
        }


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
