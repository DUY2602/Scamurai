from __future__ import annotations

import argparse
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Email.pipeline import strip_html
from ml_artifact_utils import print_done


WHITESPACE_REGEX = re.compile(r"\s+")


def decode_part(part) -> str:
    """Decode a MIME part with replacement for malformed bytes."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None

    if payload is None:
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
            if isinstance(content, bytes):
                payload = content
            else:
                return str(content or "")
        except Exception:
            payload = b""

    charset = part.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")


def extract_text_parts(message) -> tuple[str, str]:
    """Prefer text/plain, then fallback to stripped text/html."""
    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()
            content = decode_part(part)
            if not content:
                continue
            if content_type == "text/plain":
                plain_chunks.append(content)
            elif content_type == "text/html":
                html_chunks.append(strip_html(content))
    else:
        content_type = message.get_content_type()
        content = decode_part(message)
        if content_type == "text/plain":
            plain_chunks.append(content)
        elif content_type == "text/html":
            html_chunks.append(strip_html(content))

    plain_text = "\n".join(chunk for chunk in plain_chunks if chunk).strip()
    html_text = "\n".join(chunk for chunk in html_chunks if chunk).strip()
    return plain_text, html_text


def normalize_text(text: str) -> str:
    return WHITESPACE_REGEX.sub(" ", str(text or "").strip())


def parse_message_file(file_path: Path) -> dict[str, str]:
    """Parse a raw SpamAssassin message file into text + metadata."""
    raw_bytes = file_path.read_bytes()
    raw_text = raw_bytes.decode("utf-8", errors="replace")

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = str(message.get("Subject", "") or "").strip()
        sender = str(message.get("From", "") or "").strip()
        plain_text, html_text = extract_text_parts(message)
        body = plain_text or html_text
        if not body:
            body = raw_text
    except Exception:
        subject = ""
        sender = ""
        body = raw_text

    full_text = normalize_text(f"{subject} {body}")
    return {
        "subject": normalize_text(subject),
        "sender": normalize_text(sender),
        "text": full_text,
    }


def iter_message_files(directory: Path):
    """Yield raw message files recursively from a SpamAssassin split."""
    if not directory.is_dir():
        return
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            yield path


def ingest_directory(directory: Path, label: int, rows: list[dict[str, str]], stats: dict[str, int]) -> None:
    """Parse every file in one class directory."""
    if not directory or not directory.is_dir():
        return

    for file_path in iter_message_files(directory):
        try:
            parsed = parse_message_file(file_path)
            if not parsed["text"]:
                stats["skipped_empty"] += 1
                continue
            rows.append(
                {
                    "text": parsed["text"],
                    "label": int(label),
                    "source": "spamassassin",
                }
            )
            stats["parsed"] += 1
            if label == 1:
                stats["spam"] += 1
            else:
                stats["ham"] += 1
        except Exception:
            stats["errors"] += 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse SpamAssassin raw email files into a CSV dataset.")
    parser.add_argument("--spam-dir", required=True, type=str, help="Path to the SpamAssassin spam directory.")
    parser.add_argument("--ham-dir", required=True, type=str, help="Path to the SpamAssassin easy_ham directory.")
    parser.add_argument("--hard-ham-dir", default=None, type=str, help="Optional path to the SpamAssassin hard_ham directory.")
    parser.add_argument("--output", required=True, type=str, help="Output CSV path.")
    args = parser.parse_args()

    spam_dir = Path(args.spam_dir).expanduser().resolve()
    ham_dir = Path(args.ham_dir).expanduser().resolve()
    hard_ham_dir = Path(args.hard_ham_dir).expanduser().resolve() if args.hard_ham_dir else None
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []
    stats = {
        "parsed": 0,
        "errors": 0,
        "skipped_empty": 0,
        "spam": 0,
        "ham": 0,
    }

    ingest_directory(spam_dir, label=1, rows=rows, stats=stats)
    ingest_directory(ham_dir, label=0, rows=rows, stats=stats)
    if hard_ham_dir is not None:
        ingest_directory(hard_ham_dir, label=0, rows=rows, stats=stats)

    df = pd.DataFrame(rows, columns=["text", "label", "source"])
    df.to_csv(output_path, index=False, encoding="utf-8")

    total = len(df) or 1
    print(f"Parsed rows:      {len(df)}")
    print(f"Skipped errors:   {stats['errors']}")
    print(f"Skipped empty:    {stats['skipped_empty']}")
    print(f"Spam rows:        {stats['spam']} ({(stats['spam'] / total) * 100:.2f}%)")
    print(f"Ham rows:         {stats['ham']} ({(stats['ham'] / total) * 100:.2f}%)")
    print(f"Output:           {output_path}")
    print_done("parse_spamassassin.py")


if __name__ == "__main__":
    main()
