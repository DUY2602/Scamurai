"""Text preprocessing helpers shared by parsing and scoring modules."""

from __future__ import annotations

from html import unescape

from config import (
    CONTROL_CHAR_REGEX,
    EMAIL_REGEX,
    HTML_TAG_REGEX,
    INVISIBLE_CHAR_REGEX,
    MULTISPACE_REGEX,
    NON_ALNUM_REGEX,
    URL_REGEX,
)


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


def strip_html(html_text: str) -> str:
    """Remove HTML tags and decode HTML entities."""
    return unescape(HTML_TAG_REGEX.sub(" ", html_text))


def clean_text(text: str) -> str:
    """Normalize text exactly as in model training preprocessing."""
    text = unescape(text).lower()
    text = URL_REGEX.sub(" urltoken ", text)
    text = EMAIL_REGEX.sub(" emailtoken ", text)
    text = NON_ALNUM_REGEX.sub(" ", text)
    text = MULTISPACE_REGEX.sub(" ", text).strip()
    return text


def clean_preview_text(text: str, max_length: int = 400) -> str:
    """Generate readable preview text for frontend display."""
    cleaned = unescape(text)
    cleaned = INVISIBLE_CHAR_REGEX.sub("", cleaned)
    cleaned = CONTROL_CHAR_REGEX.sub(" ", cleaned)
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    cleaned = MULTISPACE_REGEX.sub(" ", cleaned).strip()
    return cleaned[:max_length]
