from __future__ import annotations

import argparse
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
from lightgbm import LGBMClassifier
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import LinearSVC

from Email.data_prep.email_dedup_split import (
    deduplicate_dataset,
    detect_input_path,
    load_dataset,
    normalize_records,
    save_split,
    split_dataset,
)
from Email.pipeline import NUMERIC_FEATURES, build_feature_frame, build_training_record
from ml_artifact_utils import print_done, save_json


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"
BACKUP_DIR = MODELS_DIR / "backup"
TRAIN_PATH = DATA_DIR / "email_train.csv"
VAL_PATH = DATA_DIR / "email_val.csv"
TEST_PATH = DATA_DIR / "email_test.csv"
HARDCASE_PATH = DATA_DIR / "email_hardcase_test.csv"
BEST_MODEL_PATH = MODELS_DIR / "best_model.pkl"
BEST_MODEL_META_PATH = MODELS_DIR / "best_model_metadata.json"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
HARDCASE_SAVE_THRESHOLD = 0.60


def ensure_splits_exist() -> None:
    if TRAIN_PATH.is_file() and VAL_PATH.is_file() and TEST_PATH.is_file():
        return
    print("Split files not found. Running email_dedup_split.py first...")
    raw_df = load_dataset(detect_input_path(None))
    normalized_df = normalize_records(raw_df)
    dedup_df, _ = deduplicate_dataset(normalized_df, threshold=0.85, num_perm=128)
    train_df, val_df, test_df = split_dataset(dedup_df, random_state=42)
    save_split(train_df, TRAIN_PATH)
    save_split(val_df, VAL_PATH)
    save_split(test_df, TEST_PATH)


def load_split(path: Path) -> pd.DataFrame:
    if path.is_file():
        return pd.read_csv(path)
    raise FileNotFoundError(f"Missing expected split file: {path}")


def load_hardcase(path: Path) -> pd.DataFrame:
    if path.is_file():
        df = pd.read_csv(path)
        if {"subject", "body"}.issubset(df.columns):
            return df
        records = []
        for row in df.to_dict(orient="records"):
            text = str(row.get("text", "") or "")
            subject = ""
            body = text
            if text.lower().startswith("subject:") and " body:" in text.lower():
                prefix, body = text.split(" Body:", 1)
                subject = prefix.replace("Subject:", "", 1).strip()
                body = body.strip()
            records.append(
                {
                    "subject": subject,
                    "body": body,
                    "sender": "",
                    "text": text,
                    "label": str(row.get("label", "ham")).strip().lower(),
                    "group": str(row.get("group", "unknown")).strip().lower(),
                }
            )
        return pd.DataFrame(records)
    raise FileNotFoundError(f"Missing expected hardcase file: {path}")


def prepare_split_frame(df: pd.DataFrame) -> pd.DataFrame:
    if {"subject", "body", "sender", "text"}.issubset(df.columns):
        frame = df.copy()
    else:
        rows = []
        for row in df.to_dict(orient="records"):
            record = build_training_record(pd.Series(row))
            rows.append(
                {
                    "subject": record["subject"],
                    "body": record["body"],
                    "sender": record["sender"],
                    "text": record["text"],
                    "label": str(row.get("label", "ham")).strip().lower(),
                }
            )
        frame = pd.DataFrame(rows)
    frame["label"] = frame["label"].str.lower().str.strip()
    return frame


def featurize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    feature_rows: list[pd.DataFrame] = []
    for row in df.itertuples(index=False):
        frame = build_feature_frame(row.subject, row.body, sender=getattr(row, "sender", ""))
        feature_rows.append(frame)
    output = pd.concat(feature_rows, ignore_index=True) if feature_rows else pd.DataFrame(columns=NUMERIC_FEATURES + ["full_clean_text"])
    return output


def fit_vectorizer_and_scaler(train_features: pd.DataFrame) -> tuple[TfidfVectorizer, StandardScaler]:
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    scaler = StandardScaler()
    vectorizer.fit(train_features["full_clean_text"])
    scaler.fit(train_features[NUMERIC_FEATURES])
    return vectorizer, scaler


def transform_features(features: pd.DataFrame, vectorizer: TfidfVectorizer, scaler: StandardScaler):
    tfidf = vectorizer.transform(features["full_clean_text"])
    numeric = scaler.transform(features[NUMERIC_FEATURES])
    return hstack([tfidf, csr_matrix(numeric)]).tocsr()


def build_model_factory(name: str):
    if name == "lightgbm":
        return lambda: LGBMClassifier(
            n_estimators=300,
            learning_rate=0.08,
            num_leaves=63,
            class_weight="balanced",
            random_state=42,
            verbose=-1,
        )
    if name == "logistic_regression":
        return lambda: LogisticRegression(
            max_iter=2500,
            class_weight="balanced",
            random_state=42,
            solver="liblinear",
        )
    if name == "linear_svc":
        return lambda: CalibratedClassifierCV(
            estimator=LinearSVC(class_weight="balanced", random_state=42),
            method="sigmoid",
            cv=3,
        )
    raise KeyError(f"Unsupported model name: {name}")


def evaluate_predictions(model_name: str, split_name: str, y_true, y_pred, y_proba, label_encoder: LabelEncoder) -> dict[str, Any]:
    report_dict = classification_report(
        y_true,
        y_pred,
        target_names=label_encoder.classes_,
        digits=4,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred)
    roc_auc = float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else float("nan")

    print(f"\n{'=' * 72}")
    print(f"{model_name} - {split_name}")
    print(f"{'=' * 72}")
    print(
        classification_report(
            y_true,
            y_pred,
            target_names=label_encoder.classes_,
            digits=4,
            zero_division=0,
        )
    )
    print("Confusion matrix:")
    print(matrix)
    print(f"ROC-AUC: {roc_auc:.4f}" if not np.isnan(roc_auc) else "ROC-AUC: n/a")

    return {
        "classification_report": report_dict,
        "confusion_matrix": matrix.tolist(),
        "roc_auc": None if np.isnan(roc_auc) else roc_auc,
        "macro_f1": float(report_dict["macro avg"]["f1-score"]),
    }


def run_cross_validation(train_df: pd.DataFrame, label_encoder: LabelEncoder, cv_folds: int) -> dict[str, dict[str, float]]:
    results: dict[str, dict[str, float]] = {}
    splitter = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
    y = label_encoder.transform(train_df["label"])
    model_names = ["lightgbm", "logistic_regression", "linear_svc"]

    for model_name in model_names:
        precision_scores: list[float] = []
        recall_scores: list[float] = []
        f1_scores: list[float] = []
        factory = build_model_factory(model_name)

        for fold_index, (train_idx, val_idx) in enumerate(splitter.split(train_df["text"], y), start=1):
            fold_train = train_df.iloc[train_idx].reset_index(drop=True)
            fold_val = train_df.iloc[val_idx].reset_index(drop=True)
            fold_train_features = featurize_dataframe(fold_train)
            fold_val_features = featurize_dataframe(fold_val)
            vectorizer, scaler = fit_vectorizer_and_scaler(fold_train_features)
            X_fold_train = transform_features(fold_train_features, vectorizer, scaler)
            X_fold_val = transform_features(fold_val_features, vectorizer, scaler)
            y_fold_train = label_encoder.transform(fold_train["label"])
            y_fold_val = label_encoder.transform(fold_val["label"])

            model = factory()
            model.fit(X_fold_train, y_fold_train)
            fold_pred = model.predict(X_fold_val)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_fold_val,
                fold_pred,
                average="macro",
                zero_division=0,
            )
            precision_scores.append(float(precision))
            recall_scores.append(float(recall))
            f1_scores.append(float(f1))
            print(
                f"CV fold {fold_index}/{cv_folds} - {model_name}: "
                f"precision={precision:.4f} recall={recall:.4f} f1={f1:.4f}"
            )

        results[model_name] = {
            "precision_mean": float(np.mean(precision_scores)),
            "precision_std": float(np.std(precision_scores)),
            "recall_mean": float(np.mean(recall_scores)),
            "recall_std": float(np.std(recall_scores)),
            "f1_mean": float(np.mean(f1_scores)),
            "f1_std": float(np.std(f1_scores)),
        }

    print("\nCross-validation summary:")
    for model_name, metrics in results.items():
        print(
            f"  {model_name:<20} "
            f"precision={metrics['precision_mean']:.4f}±{metrics['precision_std']:.4f} "
            f"recall={metrics['recall_mean']:.4f}±{metrics['recall_std']:.4f} "
            f"f1={metrics['f1_mean']:.4f}±{metrics['f1_std']:.4f}"
        )
    return results


def backup_existing_best_model() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_stamp = BACKUP_DIR / "best_model_backup"
    backup_stamp.mkdir(parents=True, exist_ok=True)
    for source in [BEST_MODEL_PATH, BEST_MODEL_META_PATH, VECTORIZER_PATH, SCALER_PATH, LABEL_ENCODER_PATH]:
        if source.is_file():
            shutil.copy2(source, backup_stamp / source.name)
    return backup_stamp


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrain email classifiers on leak-resistant splits and hardcase evaluation.")
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--no-save", action="store_true", help="Run training and evaluation without overwriting model artifacts.")
    args = parser.parse_args()

    ensure_splits_exist()
    train_df = prepare_split_frame(load_split(TRAIN_PATH))
    val_df = prepare_split_frame(load_split(VAL_PATH))
    test_df = prepare_split_frame(load_split(TEST_PATH))
    hardcase_df = prepare_split_frame(load_hardcase(HARDCASE_PATH))

    label_encoder = LabelEncoder()
    label_encoder.fit(["ham", "spam"])
    joblib.dump(label_encoder, LABEL_ENCODER_PATH)

    print(f"Train rows: {len(train_df)}")
    print(f"Validation rows: {len(val_df)}")
    print(f"Test rows: {len(test_df)}")
    print(f"Hardcase rows: {len(hardcase_df)}")
    print(f"Label classes: {list(label_encoder.classes_)}")

    cv_summary = run_cross_validation(train_df, label_encoder, cv_folds=args.cv_folds)

    train_features = featurize_dataframe(train_df)
    val_features = featurize_dataframe(val_df)
    test_features = featurize_dataframe(test_df)
    hardcase_features = featurize_dataframe(hardcase_df)
    vectorizer, scaler = fit_vectorizer_and_scaler(train_features)

    X_train = transform_features(train_features, vectorizer, scaler)
    X_val = transform_features(val_features, vectorizer, scaler)
    X_test = transform_features(test_features, vectorizer, scaler)
    X_hardcase = transform_features(hardcase_features, vectorizer, scaler)

    y_train = label_encoder.transform(train_df["label"])
    y_val = label_encoder.transform(val_df["label"])
    y_test = label_encoder.transform(test_df["label"])
    y_hardcase = label_encoder.transform(hardcase_df["label"])

    candidate_models = {
        "lightgbm": build_model_factory("lightgbm")(),
        "logistic_regression": build_model_factory("logistic_regression")(),
        "linear_svc": build_model_factory("linear_svc")(),
    }
    evaluation_summary: dict[str, Any] = {"cv": cv_summary, "validation": {}, "hardcase": {}, "test": {}}

    best_name = ""
    best_val_macro_f1 = -1.0
    for model_name, model in candidate_models.items():
        model.fit(X_train, y_train)
        val_pred = model.predict(X_val)
        val_proba = model.predict_proba(X_val)[:, 1]
        hardcase_pred = model.predict(X_hardcase)
        hardcase_proba = model.predict_proba(X_hardcase)[:, 1]

        evaluation_summary["validation"][model_name] = evaluate_predictions(
            model_name,
            "validation",
            y_val,
            val_pred,
            val_proba,
            label_encoder,
        )
        evaluation_summary["hardcase"][model_name] = evaluate_predictions(
            model_name,
            "hardcase",
            y_hardcase,
            hardcase_pred,
            hardcase_proba,
            label_encoder,
        )

        macro_f1 = evaluation_summary["validation"][model_name]["macro_f1"]
        if macro_f1 > best_val_macro_f1:
            best_val_macro_f1 = macro_f1
            best_name = model_name

    print(f"\nBest model selected on validation macro F1: {best_name} ({best_val_macro_f1:.4f})")

    refit_train_df = pd.concat([train_df, val_df], ignore_index=True)
    refit_features = featurize_dataframe(refit_train_df)
    vectorizer, scaler = fit_vectorizer_and_scaler(refit_features)
    X_refit = transform_features(refit_features, vectorizer, scaler)
    y_refit = label_encoder.transform(refit_train_df["label"])
    best_model = build_model_factory(best_name)()
    best_model.fit(X_refit, y_refit)

    X_test_final = transform_features(test_features, vectorizer, scaler)
    test_pred = best_model.predict(X_test_final)
    test_proba = best_model.predict_proba(X_test_final)[:, 1]
    evaluation_summary["test"][best_name] = evaluate_predictions(
        best_name,
        "test",
        y_test,
        test_pred,
        test_proba,
        label_encoder,
    )

    metadata = {
        "selected_model": best_name,
        "validation_macro_f1": best_val_macro_f1,
        "hardcase_macro_f1": evaluation_summary["hardcase"][best_name]["macro_f1"],
        "hardcase_save_threshold": HARDCASE_SAVE_THRESHOLD,
        "cv_summary": cv_summary,
        "numeric_features": NUMERIC_FEATURES,
        "vectorizer": {
            "max_features": vectorizer.max_features,
            "ngram_range": list(vectorizer.ngram_range),
            "vocabulary_size": len(vectorizer.vocabulary_),
        },
        "label_classes": label_encoder.classes_.tolist(),
    }
    save_json(DATA_DIR / "email_retrain_summary.json", evaluation_summary)

    hardcase_macro_f1 = float(evaluation_summary["hardcase"][best_name]["macro_f1"])
    can_save = hardcase_macro_f1 >= HARDCASE_SAVE_THRESHOLD
    decision = "SAVE" if can_save and not args.no_save else "NOT SAVE"
    if args.no_save:
        decision_reason = "--no-save was set"
    elif not can_save:
        decision_reason = f"hardcase macro F1 below threshold {HARDCASE_SAVE_THRESHOLD:.2f}"
    else:
        decision_reason = "threshold met"

    print(f"\nhardcase F1 = {hardcase_macro_f1:.4f} -> {decision} ({decision_reason})")

    if not args.no_save and can_save:
        backup_dir = backup_existing_best_model()
        joblib.dump(best_model, BEST_MODEL_PATH)
        joblib.dump(vectorizer, VECTORIZER_PATH)
        joblib.dump(scaler, SCALER_PATH)
        joblib.dump(label_encoder, LABEL_ENCODER_PATH)
        BEST_MODEL_META_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        print(f"Saved best model artifacts. Backup: {backup_dir}")
    else:
        print("Skipping artifact save.")

    print_done("email_retrain.py")


if __name__ == "__main__":
    main()
