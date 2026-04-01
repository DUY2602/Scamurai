from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from Email.pipeline import (
    NUMERIC_FEATURES,
    build_feature_frame,
    build_training_record,
    extract_email_parts_from_path,
    normalize_email_text,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"
TRAIN_SPLIT_PATH = DATA_DIR / "email_train.csv"
TEST_DIR = DATA_DIR / "test"
OVERLAP_ARCHIVE_DIR = DATA_DIR / "test_overlap_removed"
TRAINING_REPORT_PATH = MODELS_DIR / "training_report.json"
BEST_MODEL_PATH = MODELS_DIR / "best_model.pkl"
BEST_MODEL_META_PATH = MODELS_DIR / "best_model_metadata.json"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
LEGACY_DIR = MODELS_DIR / "legacy"
LEGACY_MODEL_FILES = ["lgb_model.pkl", "xgb_model.pkl"]


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def archive_legacy_models() -> dict[str, str]:
    LEGACY_DIR.mkdir(parents=True, exist_ok=True)
    moved: dict[str, str] = {}
    for file_name in LEGACY_MODEL_FILES:
        source = MODELS_DIR / file_name
        target = LEGACY_DIR / file_name
        if source.exists():
            if target.exists():
                target.unlink()
            shutil.move(str(source), str(target))
            moved[file_name] = str(target)
        elif target.exists():
            moved[file_name] = str(target)
    return moved


def build_train_hashes() -> set[str]:
    train_df = pd.read_csv(TRAIN_SPLIT_PATH)
    hashes: set[str] = set()
    for row in train_df.to_dict(orient="records"):
        record = build_training_record(pd.Series(row))
        normalized_text = normalize_email_text(record["text"])
        hashes.add(hashlib.sha256(normalized_text.encode("utf-8")).hexdigest())
    return hashes


def iter_labeled_test_files():
    for label in ("ham", "spam"):
        label_dir = TEST_DIR / label
        if not label_dir.is_dir():
            continue
        for file_path in sorted(label_dir.rglob("*")):
            if file_path.is_file():
                yield label, file_path


def normalized_hash_for_email(file_path: Path) -> str:
    subject, body, _sender = extract_email_parts_from_path(file_path)
    normalized_text = normalize_email_text(f"{subject} {body}")
    return hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()


def move_overlap_files(train_hashes: set[str]) -> dict[str, Any]:
    moved_records: list[dict[str, str]] = []
    moved_by_label = {"ham": 0, "spam": 0}
    moved_hashes: set[str] = set()

    for label, file_path in iter_labeled_test_files():
        text_hash = normalized_hash_for_email(file_path)
        if text_hash not in train_hashes:
            continue

        relative_path = file_path.relative_to(TEST_DIR)
        destination = OVERLAP_ARCHIVE_DIR / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(file_path), str(destination))

        moved_by_label[label] += 1
        moved_hashes.add(text_hash)
        moved_records.append(
            {
                "label": label,
                "source": str(file_path),
                "destination": str(destination),
            }
        )

    archived_by_label = {"ham": 0, "spam": 0}
    archived_hashes: set[str] = set()
    for label in ("ham", "spam"):
        label_dir = OVERLAP_ARCHIVE_DIR / label
        if not label_dir.is_dir():
            continue
        for archived_file in label_dir.rglob("*"):
            if archived_file.is_file():
                archived_by_label[label] += 1
                archived_hashes.add(normalized_hash_for_email(archived_file))

    return {
        "moved_total": int(len(moved_records)),
        "unique_overlap_texts_moved_this_run": int(len(moved_hashes)),
        "moved_by_label": moved_by_label,
        "archive_dir": str(OVERLAP_ARCHIVE_DIR),
        "archived_total": int(sum(archived_by_label.values())),
        "archived_by_label": archived_by_label,
        "archived_unique_overlap_texts": int(len(archived_hashes)),
        "records_sample": moved_records[:10],
    }


def evaluate_clean_test() -> dict[str, Any]:
    model = joblib.load(BEST_MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    scaler = joblib.load(SCALER_PATH)
    metadata = load_json(BEST_MODEL_META_PATH)

    rows: list[dict[str, Any]] = []
    for label, file_path in iter_labeled_test_files():
        subject, body, sender = extract_email_parts_from_path(file_path)
        feature_frame = build_feature_frame(subject, body, sender=sender)
        X_input = hstack(
            [
                vectorizer.transform(feature_frame["full_clean_text"]),
                csr_matrix(scaler.transform(feature_frame[NUMERIC_FEATURES])),
            ]
        ).tocsr()

        if hasattr(model, "predict_proba"):
            spam_probability = float(model.predict_proba(X_input)[0][1])
        else:
            prediction = int(model.predict(X_input)[0])
            spam_probability = 1.0 if prediction == 1 else 0.0
        predicted = 1 if spam_probability >= 0.5 else 0

        rows.append(
            {
                "label": label,
                "subject": str(subject or ""),
                "body_preview": " ".join(str(body or "").split()[:20]),
                "path": str(file_path),
                "spam_probability": spam_probability,
                "predicted": predicted,
            }
        )

    evaluation_df = pd.DataFrame(rows)
    if evaluation_df.empty:
        raise RuntimeError("Email/data/test is empty after overlap removal; cannot evaluate clean test set.")

    y_true = (evaluation_df["label"] == "spam").astype(int).to_numpy()
    y_pred = evaluation_df["predicted"].astype(int).to_numpy()
    y_proba = evaluation_df["spam_probability"].astype(float).to_numpy()

    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    report_dict = classification_report(
        y_true,
        y_pred,
        target_names=["ham", "spam"],
        digits=4,
        zero_division=0,
        output_dict=True,
    )

    missed_spam = evaluation_df[(evaluation_df["label"] == "spam") & (evaluation_df["predicted"] == 0)].head(3)

    return {
        "model_type": type(model).__name__,
        "selected_model": metadata.get("selected_model", type(model).__name__),
        "rows": int(len(evaluation_df)),
        "label_distribution": {str(k): int(v) for k, v in evaluation_df["label"].value_counts().to_dict().items()},
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_spam": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_spam": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_spam": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)),
        "confusion_matrix": matrix.tolist(),
        "classification_report": report_dict,
        "classification_report_text": classification_report(
            y_true,
            y_pred,
            target_names=["ham", "spam"],
            digits=4,
            zero_division=0,
        ),
        "missed_spam_examples": missed_spam[["path", "subject", "body_preview", "spam_probability"]].to_dict(orient="records"),
    }


def update_training_report(legacy_info: dict[str, str], overlap_info: dict[str, Any], clean_metrics: dict[str, Any]) -> dict[str, Any]:
    report = load_json(TRAINING_REPORT_PATH)
    report["runtime_model"] = {
        "best_model_path": str(BEST_MODEL_PATH),
        "vectorizer_path": str(VECTORIZER_PATH),
        "scaler_path": str(SCALER_PATH),
        "legacy_models_archived": legacy_info,
    }
    report["clean_external_test"] = {
        "test_dir": str(TEST_DIR),
        "overlap_cleanup": overlap_info,
        "metrics": clean_metrics,
    }
    TRAINING_REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def print_summary(legacy_info: dict[str, str], overlap_info: dict[str, Any], clean_metrics: dict[str, Any]) -> None:
    print("=== Legacy models archived ===")
    print(json.dumps(legacy_info, indent=2))
    print("\n=== Overlap cleanup ===")
    print(json.dumps(overlap_info, indent=2))
    print("\n=== Clean external test ===")
    print(clean_metrics["classification_report_text"])
    print("Confusion matrix:")
    print(np.asarray(clean_metrics["confusion_matrix"]))
    print(f"ROC-AUC: {clean_metrics['roc_auc']:.4f}")


def main() -> None:
    legacy_info = archive_legacy_models()
    overlap_info = move_overlap_files(build_train_hashes())
    clean_metrics = evaluate_clean_test()
    update_training_report(legacy_info, overlap_info, clean_metrics)
    print_summary(legacy_info, overlap_info, clean_metrics)
    print("Done: clean_external_test.py")


if __name__ == "__main__":
    main()
