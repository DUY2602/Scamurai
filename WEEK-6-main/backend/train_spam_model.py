"""Train a SpamAssassin-style email spam detection model with TF-IDF + Logistic Regression."""

from __future__ import annotations

import argparse
import html
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Union

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

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
    """Fallback parser for broken emails that cannot be parsed by `email.parser`."""
    subject_match = SUBJECT_REGEX.search(text)
    subject = subject_match.group(1).strip() if subject_match else ""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    body = parts[1] if len(parts) > 1 else text
    return subject, body


def extract_subject_body(file_path: Path) -> tuple[str, str]:
    """Extract subject and body from a raw .eml-like file with robust fallbacks."""
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
    """Normalize text while preserving key spam indicators."""
    text = html.unescape(text).lower()
    text = URL_REGEX.sub(" urltoken ", text)
    text = EMAIL_REGEX.sub(" emailtoken ", text)
    text = NON_ALNUM_REGEX.sub(" ", text)
    text = MULTISPACE_REGEX.sub(" ", text).strip()
    return text


def load_emails_from_folder(folder: Path, label: int) -> tuple[list[str], list[int]]:
    """Load and preprocess all emails from a folder tree."""
    texts: list[str] = []
    labels: list[int] = []

    for file_path in sorted(folder.rglob("*")):
        if not file_path.is_file():
            continue

        subject, body = extract_subject_body(file_path)
        combined_text = f"subjecttoken {subject}\nbodytoken {body}".strip()
        cleaned = clean_text(combined_text)
        if cleaned:
            texts.append(cleaned)
            labels.append(label)

    return texts, labels


def resolve_dataset_dirs(dataset_dir: Path) -> tuple[Path, Path]:
    """Resolve dataset directories, supporting dataset/ and current-directory layout."""
    ham_dir = dataset_dir / "ham"
    spam_dir = dataset_dir / "spam"
    if ham_dir.is_dir() and spam_dir.is_dir():
        return ham_dir, spam_dir

    if dataset_dir == Path("dataset") and Path("ham").is_dir() and Path("spam").is_dir():
        print(
            "Warning: 'dataset/ham' and 'dataset/spam' not found. Falling back to './ham' and './spam'.",
            file=sys.stderr,
        )
        return Path("ham"), Path("spam")

    raise FileNotFoundError(
        f"Could not find ham/spam folders under '{dataset_dir}'. "
        f"Expected: {dataset_dir / 'ham'} and {dataset_dir / 'spam'}."
    )


def parse_threshold(value: str) -> float:
    """Validate probability threshold argument."""
    threshold = float(value)
    if threshold <= 0.0 or threshold >= 1.0:
        raise argparse.ArgumentTypeError("threshold must be in the open interval (0, 1).")
    return threshold


def parse_df_value(value: str) -> Union[int, float]:
    """Parse min_df/max_df from CLI as int count or float proportion."""
    try:
        if "." in value:
            parsed = float(value)
            if parsed <= 0.0 or parsed > 1.0:
                raise argparse.ArgumentTypeError(
                    f"Invalid document frequency proportion '{value}'. Expected 0 < value <= 1."
                )
            return parsed

        parsed_int = int(value)
        if parsed_int < 1:
            raise argparse.ArgumentTypeError(
                f"Invalid document frequency count '{value}'. Expected integer >= 1."
            )
        return parsed_int
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid document frequency value '{value}'. Use integer (e.g. 2) or float (e.g. 0.98)."
        ) from exc


def evaluate_with_threshold(
    y_true: list[int], spam_probabilities: Any, threshold: float
) -> tuple[Any, dict[str, float]]:
    """Convert spam probabilities to labels using a threshold and compute key metrics."""
    y_pred = (spam_probabilities >= threshold).astype(int)
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
    return y_pred, metrics


def print_metric_block(label: str, metrics: dict[str, float]) -> None:
    """Print standard metric block."""
    print(label)
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1-score:  {metrics['f1']:.4f}")


def main() -> None:
    """Train and evaluate a spam classifier from raw email files."""
    parser = argparse.ArgumentParser(description="Train an email spam detection model.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset"),
        help="Dataset root containing 'ham/' and 'spam/' folders. Default: dataset",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of dataset to reserve for testing. Default: 0.2",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for train/test split. Default: 42",
    )
    parser.add_argument(
        "--min-df",
        type=parse_df_value,
        default=2,
        help="TF-IDF min_df as integer count or float proportion. Default: 2",
    )
    parser.add_argument(
        "--max-df",
        type=parse_df_value,
        default=0.98,
        help="TF-IDF max_df as integer count or float proportion. Default: 0.98",
    )
    parser.add_argument(
        "--threshold",
        type=parse_threshold,
        default=0.5,
        help="Spam probability threshold for classification. Default: 0.5",
    )
    parser.add_argument(
        "--model-out",
        type=Path,
        default=Path("spam_model.joblib"),
        help="Output path for saved model artifact. Default: spam_model.joblib",
    )
    args = parser.parse_args()

    ham_dir, spam_dir = resolve_dataset_dirs(args.dataset_dir)
    ham_texts, ham_labels = load_emails_from_folder(ham_dir, label=0)
    spam_texts, spam_labels = load_emails_from_folder(spam_dir, label=1)

    texts = ham_texts + spam_texts
    labels = ham_labels + spam_labels

    if not texts:
        raise ValueError("No email files were loaded. Check dataset paths and file contents.")

    X_train_texts, X_test_texts, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=labels,
    )

    vectorizer = TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2),
        min_df=args.min_df,
        max_df=args.max_df,
        sublinear_tf=True,
    )
    X_train = vectorizer.fit_transform(X_train_texts)
    X_test = vectorizer.transform(X_test_texts)

    classifier = LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        solver="liblinear",
        C=1.5,
    )
    classifier.fit(X_train, y_train)

    spam_probabilities = classifier.predict_proba(X_test)[:, 1]

    y_pred_default, metrics_default = evaluate_with_threshold(y_test, spam_probabilities, threshold=0.5)
    y_pred_current, metrics_current = evaluate_with_threshold(
        y_test, spam_probabilities, threshold=args.threshold
    )

    print(f"Loaded emails: {len(texts)} (ham={len(ham_texts)}, spam={len(spam_texts)})")
    print(
        "Vectorizer config: "
        f"ngram_range=(1,2), min_df={args.min_df}, max_df={args.max_df}, sublinear_tf=True"
    )
    print("Classifier config: LogisticRegression(class_weight='balanced', solver='liblinear', C=1.5)")
    print("")

    print_metric_block("Metrics at threshold=0.50", metrics_default)
    if args.threshold != 0.5:
        print("")
        print_metric_block(f"Metrics at threshold={args.threshold:.2f}", metrics_current)
        precision_delta = metrics_current["precision"] - metrics_default["precision"]
        recall_delta = metrics_current["recall"] - metrics_default["recall"]
        print(
            "Threshold impact vs 0.50: "
            f"precision {precision_delta:+.4f}, recall {recall_delta:+.4f}"
        )
    else:
        print("")
        print("Threshold impact vs 0.50: precision +0.0000, recall +0.0000")

    print("")
    print(f"Confusion Matrix (threshold={args.threshold:.2f}, labels=[ham, spam]):")
    print(confusion_matrix(y_test, y_pred_current, labels=[0, 1]))
    print("")
    print("Classification Report:")
    print(
        classification_report(
            y_test,
            y_pred_current,
            target_names=["ham", "spam"],
            digits=4,
            zero_division=0,
        )
    )

    model_artifact: dict[str, Any] = {
        "vectorizer": vectorizer,
        "classifier": classifier,
        "label_map": {0: "ham", 1: "spam"},
        "threshold": args.threshold,
    }
    joblib.dump(model_artifact, args.model_out)
    print(f"Saved model to: {args.model_out.resolve()}")


if __name__ == "__main__":
    main()
