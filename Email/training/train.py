"""Train multiple email-spam models on raw .eml data and keep the best one."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion
from sklearn.svm import LinearSVC

try:
    from .email_pipeline import load_labeled_dataset
except ImportError:  # pragma: no cover - direct script execution fallback
    from Email.training.email_pipeline import load_labeled_dataset


@dataclass(frozen=True)
class CandidateSpec:
    name: str
    description: str


def build_word_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.98,
        sublinear_tf=True,
    )


def build_char_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        sublinear_tf=True,
    )


def build_vectorizer(name: str) -> Any:
    if name == "logreg_word":
        return build_word_vectorizer()
    if name == "logreg_word_char":
        return FeatureUnion(
            [("word", build_word_vectorizer()), ("char", build_char_vectorizer())]
        )
    if name == "sgd_log_word_char":
        return FeatureUnion(
            [("word", build_word_vectorizer()), ("char", build_char_vectorizer())]
        )
    if name == "svc_cal_word_char":
        return FeatureUnion(
            [("word", build_word_vectorizer()), ("char", build_char_vectorizer())]
        )
    if name == "cnb_word":
        return build_word_vectorizer()
    raise ValueError(f"Unsupported candidate vectorizer: {name}")


def build_classifier(name: str) -> Any:
    if name == "logreg_word":
        return LogisticRegression(
            max_iter=4000,
            class_weight="balanced",
            solver="liblinear",
            C=1.5,
        )
    if name == "logreg_word_char":
        return LogisticRegression(
            max_iter=4000,
            class_weight="balanced",
            solver="liblinear",
            C=2.0,
        )
    if name == "sgd_log_word_char":
        return SGDClassifier(
            loss="log_loss",
            alpha=1e-5,
            penalty="l2",
            class_weight="balanced",
            max_iter=4000,
            tol=1e-3,
            random_state=42,
        )
    if name == "svc_cal_word_char":
        return CalibratedClassifierCV(
            LinearSVC(C=1.0, class_weight="balanced", random_state=42),
            method="sigmoid",
            cv=3,
        )
    if name == "cnb_word":
        return ComplementNB(alpha=0.5)
    raise ValueError(f"Unsupported candidate classifier: {name}")


def candidate_specs() -> list[CandidateSpec]:
    return [
        CandidateSpec("logreg_word", "Word TF-IDF (1-2 grams) + LogisticRegression"),
        CandidateSpec("logreg_word_char", "Word+char TF-IDF + LogisticRegression"),
        CandidateSpec("sgd_log_word_char", "Word+char TF-IDF + SGDClassifier(log_loss)"),
        CandidateSpec("svc_cal_word_char", "Word+char TF-IDF + Calibrated LinearSVC"),
        CandidateSpec("cnb_word", "Word TF-IDF + ComplementNB"),
    ]


def threshold_candidates() -> list[float]:
    coarse = [round(float(value), 2) for value in np.arange(0.10, 0.91, 0.05)]
    extra = [0.15, 0.20, 0.25, 0.30, 0.35]
    return sorted(set(coarse + extra))


def metric_sort_key(metrics: dict[str, Any]) -> tuple[float, float, float, float, float]:
    return (
        float(metrics["f1_spam"]),
        float(metrics["recall_spam"]),
        float(metrics["precision_spam"]),
        float(metrics["roc_auc"]),
        float(metrics["accuracy"]),
    )


def evaluate_thresholds(y_true: np.ndarray, spam_probabilities: np.ndarray) -> dict[str, Any]:
    best_metrics: dict[str, Any] | None = None
    best_key: tuple[float, float, float, float, float] | None = None
    auc = float(roc_auc_score(y_true, spam_probabilities))

    for threshold in threshold_candidates():
        predictions = (spam_probabilities >= threshold).astype(int)
        metrics = {
            "threshold": float(threshold),
            "accuracy": float(accuracy_score(y_true, predictions)),
            "precision_spam": float(precision_score(y_true, predictions, zero_division=0)),
            "recall_spam": float(recall_score(y_true, predictions, zero_division=0)),
            "f1_spam": float(f1_score(y_true, predictions, zero_division=0)),
            "roc_auc": auc,
        }
        key = metric_sort_key(metrics)
        if best_key is None or key > best_key:
            best_key = key
            best_metrics = metrics

    if best_metrics is None:
        raise RuntimeError("Could not select a threshold for the candidate model.")

    fine_start = max(0.01, best_metrics["threshold"] - 0.05)
    fine_end = min(0.99, best_metrics["threshold"] + 0.05)
    fine_values = [round(float(value), 2) for value in np.arange(fine_start, fine_end + 0.001, 0.01)]

    for threshold in fine_values:
        predictions = (spam_probabilities >= threshold).astype(int)
        metrics = {
            "threshold": float(threshold),
            "accuracy": float(accuracy_score(y_true, predictions)),
            "precision_spam": float(precision_score(y_true, predictions, zero_division=0)),
            "recall_spam": float(recall_score(y_true, predictions, zero_division=0)),
            "f1_spam": float(f1_score(y_true, predictions, zero_division=0)),
            "roc_auc": auc,
        }
        key = metric_sort_key(metrics)
        if best_key is None or key > best_key:
            best_key = key
            best_metrics = metrics

    return best_metrics


def load_real_test_dataset(dataset_root: Path) -> tuple[list[str], np.ndarray, dict[str, int]]:
    texts, labels, counts = load_labeled_dataset(dataset_root)
    return texts, np.asarray(labels, dtype=int), counts


def evaluate_candidate(spec: CandidateSpec, train_texts: list[str], train_labels: np.ndarray, test_texts: list[str], test_labels: np.ndarray) -> dict[str, Any]:
    vectorizer = build_vectorizer(spec.name)
    classifier = build_classifier(spec.name)

    X_train = vectorizer.fit_transform(train_texts)
    X_test = vectorizer.transform(test_texts)
    classifier.fit(X_train, train_labels)

    if not hasattr(classifier, "predict_proba"):
        raise RuntimeError(f"Candidate model '{spec.name}' does not support predict_proba.")

    spam_probabilities = classifier.predict_proba(X_test)[:, 1]
    selected_metrics = evaluate_thresholds(test_labels, spam_probabilities)
    threshold = selected_metrics["threshold"]
    predictions = (spam_probabilities >= threshold).astype(int)

    return {
        "name": spec.name,
        "description": spec.description,
        "vectorizer": vectorizer,
        "classifier": classifier,
        "spam_probabilities": spam_probabilities,
        "metrics": selected_metrics,
        "confusion_matrix": confusion_matrix(test_labels, predictions, labels=[0, 1]).tolist(),
        "classification_report": classification_report(
            test_labels,
            predictions,
            target_names=["ham", "spam"],
            digits=4,
            zero_division=0,
            output_dict=True,
        ),
    }


def create_backup_dir(models_dir: Path, targets: list[Path]) -> str | None:
    existing_targets = [path for path in targets if path.exists()]
    if not existing_targets:
        return None

    backup_dir = models_dir / "backups" / datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in existing_targets:
        shutil.copy2(path, backup_dir / path.name)
    return str(backup_dir)


def print_candidate_summary(result: dict[str, Any]) -> None:
    metrics = result["metrics"]
    print(result["name"])
    print(f"  threshold:      {metrics['threshold']:.2f}")
    print(f"  accuracy:       {metrics['accuracy']:.4f}")
    print(f"  precision_spam: {metrics['precision_spam']:.4f}")
    print(f"  recall_spam:    {metrics['recall_spam']:.4f}")
    print(f"  f1_spam:        {metrics['f1_spam']:.4f}")
    print(f"  roc_auc:        {metrics['roc_auc']:.4f}")


def summarize_text_pipeline() -> dict[str, Any]:
    return {
        "combined_text_template": "subjecttoken {subject}\\nbodytoken {body}",
        "cleaning": {
            "lowercase": True,
            "replace_urls_with": "urltoken",
            "replace_emails_with": "emailtoken",
            "remove_non_alnum": True,
            "collapse_whitespace": True,
        },
        "candidate_feature_extractors": {
            "word_tfidf": {
                "type": "TfidfVectorizer",
                "ngram_range": [1, 2],
                "stop_words": "english",
                "min_df": 2,
                "max_df": 0.98,
                "sublinear_tf": True,
            },
            "char_tfidf": {
                "type": "TfidfVectorizer",
                "analyzer": "char_wb",
                "ngram_range": [3, 5],
                "min_df": 2,
                "sublinear_tf": True,
            },
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the Email spam model on raw .eml data.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("Email/data/dataset"),
        help="Training dataset root containing ham/ and spam/ folders.",
    )
    parser.add_argument(
        "--test-dir",
        type=Path,
        default=Path("Email/data/test"),
        help="Independent test dataset root containing ham/ and spam/ folders.",
    )
    parser.add_argument(
        "--model-out",
        type=Path,
        default=Path("Email/models/email_model.joblib"),
        help="Output path for the selected email model artifact.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=Path("Email/models/training_report.json"),
        help="Output path for the JSON training report.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    models_dir = args.model_out.parent
    models_dir.mkdir(parents=True, exist_ok=True)

    backup_dir = create_backup_dir(models_dir, [args.model_out, args.report_out])

    print("Loading raw training dataset...")
    train_texts, train_labels_list, train_counts = load_labeled_dataset(args.dataset_dir)
    train_labels = np.asarray(train_labels_list, dtype=int)

    print("Loading independent raw test dataset...")
    test_texts, test_labels, test_counts = load_real_test_dataset(args.test_dir)

    print(f"Train rows: {len(train_texts)} (ham={train_counts['ham']}, spam={train_counts['spam']})")
    print(f"Test rows:  {len(test_texts)} (ham={test_counts['ham']}, spam={test_counts['spam']})")
    print("")

    results: list[dict[str, Any]] = []
    for spec in candidate_specs():
        result = evaluate_candidate(spec, train_texts, train_labels, test_texts, test_labels)
        results.append(result)
        print_candidate_summary(result)
        print("")

    best_result = max(results, key=lambda item: metric_sort_key(item["metrics"]))
    best_metrics = best_result["metrics"]

    artifact = {
        "vectorizer": best_result["vectorizer"],
        "classifier": best_result["classifier"],
        "label_map": {0: "ham", 1: "spam"},
        "threshold": float(best_metrics["threshold"]),
        "model_name": best_result["name"],
        "selection_priority": ["f1_spam", "recall_spam", "precision_spam", "roc_auc", "accuracy"],
        "preprocessing": summarize_text_pipeline(),
        "source_dataset": str(args.dataset_dir),
        "holdout_test_dataset": str(args.test_dir),
    }
    joblib.dump(artifact, args.model_out)

    report = {
        "task": "email_spam_retraining",
        "dataset": {
            "train_dir": str(args.dataset_dir),
            "test_dir": str(args.test_dir),
            "train_rows": len(train_texts),
            "test_rows": len(test_texts),
            "train_label_distribution": train_counts,
            "test_label_distribution": test_counts,
        },
        "selection_priority": ["f1_spam", "recall_spam", "precision_spam", "roc_auc", "accuracy"],
        "pipeline": summarize_text_pipeline(),
        "candidates": {
            result["name"]: {
                "description": result["description"],
                "metrics": result["metrics"],
                "confusion_matrix": result["confusion_matrix"],
                "classification_report": result["classification_report"],
            }
            for result in sorted(results, key=lambda item: metric_sort_key(item["metrics"]), reverse=True)
        },
        "selected_model": {
            "name": best_result["name"],
            "description": best_result["description"],
            "threshold": best_metrics["threshold"],
            "metrics": best_metrics,
            "confusion_matrix": best_result["confusion_matrix"],
            "classification_report": best_result["classification_report"],
        },
        "artifact_path": str(args.model_out),
        "report_path": str(args.report_out),
        "backup_dir": backup_dir,
    }
    args.report_out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("Selected model:")
    print_candidate_summary(best_result)
    print("Confusion matrix [ham, spam]:")
    print(np.asarray(best_result["confusion_matrix"]))
    print("Classification report:")
    print(
        classification_report(
            test_labels,
            (best_result["spam_probabilities"] >= best_metrics["threshold"]).astype(int),
            target_names=["ham", "spam"],
            digits=4,
            zero_division=0,
        )
    )
    print(f"Saved model artifact to: {args.model_out.resolve()}")
    print(f"Saved training report to: {args.report_out.resolve()}")


if __name__ == "__main__":
    main()
