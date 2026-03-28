"""Evaluate a trained spam model on an external test dataset."""

from pathlib import Path
from email import policy
from email.parser import BytesParser
import re
import html

import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


MODEL_PATH = Path("spam_model.joblib")
TEST_DIR = Path("test")

URL_REGEX = re.compile(r"http[s]?://\S+|www\.\S+", flags=re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", flags=re.IGNORECASE)
HTML_TAG_REGEX = re.compile(r"<[^>]+>")
NON_ALNUM_REGEX = re.compile(r"[^a-z0-9_]+")
MULTISPACE_REGEX = re.compile(r"\s+")
SUBJECT_REGEX = re.compile(r"(?im)^subject:\s*(.*)$")


def strip_html(html_text: str) -> str:
    """Remove HTML tags and decode HTML entities."""
    text = HTML_TAG_REGEX.sub(" ", html_text)
    return html.unescape(text)


def fallback_subject_body(text: str) -> tuple[str, str]:
    """Fallback subject/body extraction for malformed emails."""
    subject_match = SUBJECT_REGEX.search(text)
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def extract_subject_body(file_path: Path) -> tuple[str, str]:
    """Extract subject and body from a raw email file."""
    raw_bytes = file_path.read_bytes()

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        subject = msg.get("Subject", "") or ""
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
        return fallback_subject_body(raw_bytes.decode("utf-8", errors="ignore"))


def clean_text(text: str) -> str:
    """Normalize text using the same cleaning logic as training."""
    text = html.unescape(text).lower()
    text = URL_REGEX.sub(" urltoken ", text)
    text = EMAIL_REGEX.sub(" emailtoken ", text)
    text = NON_ALNUM_REGEX.sub(" ", text)
    text = MULTISPACE_REGEX.sub(" ", text).strip()
    return text


def load_emails_from_folder(folder: Path, label: int) -> tuple[list[str], list[int], int]:
    """Recursively load and preprocess emails from one class folder."""
    texts: list[str] = []
    labels: list[int] = []
    file_count = 0

    for file_path in sorted(folder.rglob("*")):
        if not file_path.is_file():
            continue

        file_count += 1
        subject, body = extract_subject_body(file_path)
        combined_text = f"subjecttoken {subject}\nbodytoken {body}".strip()
        cleaned = clean_text(combined_text)
        texts.append(cleaned)
        labels.append(label)

    return texts, labels, file_count


def load_external_dataset(test_dir: Path) -> tuple[list[str], list[int], int, int]:
    """Load test/ham and test/spam recursively."""
    ham_dir = test_dir / "ham"
    spam_dir = test_dir / "spam"

    if not ham_dir.is_dir() or not spam_dir.is_dir():
        raise FileNotFoundError(
            f"Expected folders '{ham_dir}' and '{spam_dir}' to exist."
        )

    ham_texts, ham_labels, ham_count = load_emails_from_folder(ham_dir, label=0)
    spam_texts, spam_labels, spam_count = load_emails_from_folder(spam_dir, label=1)

    texts = ham_texts + spam_texts
    labels = ham_labels + spam_labels

    if not texts:
        raise ValueError("No email files found under test/ham and test/spam.")

    return texts, labels, ham_count, spam_count


def evaluate_external_test() -> None:
    """Run external dataset evaluation and print summary metrics."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

    model_artifact = joblib.load(MODEL_PATH)
    vectorizer = model_artifact["vectorizer"]
    classifier = model_artifact["classifier"]
    _label_map = model_artifact.get("label_map", {0: "ham", 1: "spam"})

    texts, y_true, ham_count, spam_count = load_external_dataset(TEST_DIR)
    X_test = vectorizer.transform(texts)
    y_pred = classifier.predict(X_test)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    tn, fp, fn, tp = cm.ravel()
    total_emails = ham_count + spam_count

    print("External Dataset Evaluation")
    print(f"Total emails: {total_emails}")
    print(f"Ham emails: {ham_count}")
    print(f"Spam emails: {spam_count}")
    print("")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1:.4f}")
    print("")
    print("Confusion Matrix:")
    print(cm)
    print("")
    print(f"Spam detected (TP): {tp}")
    print(f"Spam missed (FN): {fn}")
    print(f"Spam detection rate: {tp}/{spam_count}")
    print(f"Ham incorrectly flagged as spam (FP): {fp}")
    print(f"Ham correctly identified (TN): {tn}")


if __name__ == "__main__":
    evaluate_external_test()
