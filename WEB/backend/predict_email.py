import argparse
import html
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

import joblib


def strip_html(html_text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html_text)
    return html.unescape(text)


def fallback_subject_body(text: str) -> tuple[str, str]:
    subject_match = re.search(r"(?im)^subject:\s*(.*)$", text)
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def extract_subject_body(file_path: Path) -> tuple[str, str]:
    raw_bytes = file_path.read_bytes()

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = msg.get("Subject", "") or ""
        body_chunks = []

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
                    content = strip_html(content)
                body_chunks.append(content)

        body = "\n".join(chunk for chunk in body_chunks if chunk).strip()
        if not body:
            _, body = fallback_subject_body(raw_bytes.decode("utf-8", errors="ignore"))

        return subject, body

    except Exception:
        text = raw_bytes.decode("utf-8", errors="ignore")
        return fallback_subject_body(text)


def clean_text(text: str) -> str:
    text = html.unescape(text)
    text = text.lower()
    text = re.sub(r"http[s]?://\S+|www\.\S+", " urltoken ", text)
    text = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", " emailtoken ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_urls(text: str) -> list[str]:
    return re.findall(r"http[s]?://\S+|www\.\S+", text, flags=re.IGNORECASE)


def get_threshold(model_artifact: dict, cli_threshold: float | None) -> float:
    if cli_threshold is not None:
        return cli_threshold
    return float(model_artifact.get("threshold", 0.5))


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict whether an .eml email is spam or ham.")
    parser.add_argument("email_file", type=Path, help="Path to the .eml or raw email file")
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("spam_model.joblib"),
        help="Path to trained model artifact (.joblib)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Optional decision threshold for spam probability (default: model threshold or 0.5)",
    )
    args = parser.parse_args()

    if not args.email_file.is_file():
        raise FileNotFoundError(f"Email file not found: {args.email_file}")

    if not args.model.is_file():
        raise FileNotFoundError(f"Model file not found: {args.model}")

    model_artifact = joblib.load(args.model)
    vectorizer = model_artifact["vectorizer"]
    classifier = model_artifact["classifier"]
    label_map = model_artifact.get("label_map", {0: "ham", 1: "spam"})
    threshold = get_threshold(model_artifact, args.threshold)

    subject, body = extract_subject_body(args.email_file)
    combined_text = f"{subject}\n{body}".strip()
    cleaned_text = clean_text(combined_text)

    if not cleaned_text:
        raise ValueError("Could not extract usable text from the email file.")

    X = vectorizer.transform([cleaned_text])

    if hasattr(classifier, "predict_proba"):
        spam_probability = float(classifier.predict_proba(X)[0][1])
    else:
        spam_probability = 1.0 if int(classifier.predict(X)[0]) == 1 else 0.0

    predicted_label = 1 if spam_probability >= threshold else 0
    verdict = label_map.get(predicted_label, str(predicted_label)).upper()

    urls = extract_urls(body)
    reasons = []

    if spam_probability >= threshold:
        reasons.append("spam probability is above the decision threshold")
    else:
        reasons.append("spam probability is below the decision threshold")

    if urls:
        reasons.append(f"contains {len(urls)} URL(s)")

    if "verify" in cleaned_text or "account" in cleaned_text or "urgent" in cleaned_text:
        reasons.append("contains suspicious phishing-like language")

    print("=" * 60)
    print("EMAIL SPAM DETECTION RESULT")
    print("=" * 60)
    print(f"File:        {args.email_file}")
    print(f"Subject:     {subject if subject else '(no subject)'}")
    print(f"Threshold:   {threshold:.2f}")
    print(f"Verdict:     {verdict}")
    print(f"Confidence:  {spam_probability:.4f}")

    print("\nReasons:")
    for reason in reasons:
        print(f"- {reason}")

    if urls:
        print("\nExtracted URLs:")
        for url in urls[:10]:
            print(f"- {url}")

    print("\nPreview:")
    preview = combined_text[:500].replace("\n", " ")
    print(preview if preview else "(empty)")
    print("=" * 60)


if __name__ == "__main__":
    main()