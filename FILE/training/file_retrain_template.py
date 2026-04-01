from __future__ import annotations

import argparse
import json
import random
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
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold, train_test_split
from xgboost import XGBClassifier, __version__ as xgb_version

from ml_artifact_utils import compute_file_md5, print_done, save_json, save_xgboost_model


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models" / "retrain_template"
DATASET_CANDIDATES = [
    DATA_DIR / "malware_data_final.csv",
    DATA_DIR / "file_dataset.csv",
    DATA_DIR / "malware_dataset.csv",
]
BASE_FEATURE_COLUMNS = [
    "Sections",
    "AvgEntropy",
    "MaxEntropy",
    "SuspiciousSections",
    "DLLs",
    "Imports",
    "HasSensitiveAPI",
    "ImageBase",
    "SizeOfImage",
    "HasVersionInfo",
]
EXTRA_FEATURE_COLUMNS = [
    "is_packed",
    "max_section_entropy",
    "section_size_ratio",
    "has_tls",
    "import_category_score",
]


def detect_dataset() -> Path | None:
    for candidate in DATASET_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def build_mock_dataset(rows_per_class: int = 120) -> pd.DataFrame:
    rng = random.Random(42)
    records = []
    for index in range(rows_per_class):
        records.append(
            {
                "MD5": f"mock-benign-{index:04d}",
                "Sections": rng.randint(4, 8),
                "AvgEntropy": round(rng.uniform(3.0, 5.8), 4),
                "MaxEntropy": round(rng.uniform(4.5, 6.8), 4),
                "SuspiciousSections": 0,
                "DLLs": rng.randint(15, 60),
                "Imports": rng.randint(80, 450),
                "HasSensitiveAPI": rng.randint(0, 1),
                "ImageBase": rng.choice([4194304, 5368709120]),
                "SizeOfImage": rng.randint(49152, 524288),
                "HasVersionInfo": 1,
                "Family": f"benign_family_{index % 10}",
                "Label": 0,
            }
        )
        records.append(
            {
                "MD5": f"mock-malware-{index:04d}",
                "Sections": rng.randint(2, 6),
                "AvgEntropy": round(rng.uniform(6.0, 7.8), 4),
                "MaxEntropy": round(rng.uniform(7.0, 8.0), 4),
                "SuspiciousSections": rng.randint(1, 3),
                "DLLs": rng.randint(1, 15),
                "Imports": rng.randint(5, 80),
                "HasSensitiveAPI": 1,
                "ImageBase": rng.choice([4194304, 5368709120]),
                "SizeOfImage": rng.randint(8192, 262144),
                "HasVersionInfo": rng.randint(0, 1),
                "Family": f"malware_family_{index % 12}",
                "Label": 1,
            }
        )
    return pd.DataFrame(records)


def load_dataset(dataset_path: Path | None) -> tuple[pd.DataFrame, str]:
    if dataset_path is not None and dataset_path.is_file():
        return pd.read_csv(dataset_path), "real"
    print("WARNING: FILE dataset is missing. Running in mock-data mode.")
    return build_mock_dataset(), "mock"


def detect_label_column(df: pd.DataFrame) -> str:
    for candidate in ["Label", "label", "target", "class"]:
        if candidate in df.columns:
            return candidate
    raise KeyError("Could not find a label column in the FILE dataset.")


def detect_group_column(df: pd.DataFrame) -> str | None:
    for candidate in ["Family", "family", "sha256", "SHA256", "MD5", "md5"]:
        if candidate in df.columns:
            return candidate
    return None


def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, str, str | None]:
    label_column = detect_label_column(df)
    group_column = detect_group_column(df)
    working = df.copy()

    for column in BASE_FEATURE_COLUMNS:
        if column not in working.columns:
            working[column] = 0

    working["is_packed"] = (working["MaxEntropy"].astype(float) > 7.0).astype(int)
    working["max_section_entropy"] = working["MaxEntropy"].astype(float)
    working["section_size_ratio"] = (
        working["SizeOfImage"].astype(float) / working["Sections"].replace(0, np.nan).astype(float)
    ).fillna(0.0)
    if "HasTLS" in working.columns:
        has_tls_series = working["HasTLS"]
    elif "has_tls" in working.columns:
        has_tls_series = working["has_tls"]
    else:
        has_tls_series = pd.Series(np.zeros(len(working)), index=working.index)
    working["has_tls"] = has_tls_series.fillna(0).astype(int)
    working["import_category_score"] = (
        working["HasSensitiveAPI"].astype(float) * 2.0
        + (working["Imports"].astype(float) / 50.0)
        + (working["DLLs"].astype(float) / 20.0)
    )

    feature_columns = BASE_FEATURE_COLUMNS + EXTRA_FEATURE_COLUMNS
    working[label_column] = working[label_column].astype(int)
    return working[feature_columns + [label_column] + ([group_column] if group_column else [])], label_column, group_column


def grouped_split(
    df: pd.DataFrame,
    label_column: str,
    group_column: str | None,
    random_state: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    if group_column is None:
        train_df, temp_df = train_test_split(
            df,
            test_size=0.30,
            stratify=df[label_column],
            random_state=random_state,
        )
        val_df, test_df = train_test_split(
            temp_df,
            test_size=0.50,
            stratify=temp_df[label_column],
            random_state=random_state,
        )
        return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=random_state)
    train_idx, temp_idx = next(splitter.split(df, groups=df[group_column]))
    train_df = df.iloc[train_idx].reset_index(drop=True)
    temp_df = df.iloc[temp_idx].reset_index(drop=True)

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=random_state + 1)
    val_idx, test_idx = next(splitter.split(temp_df, groups=temp_df[group_column]))
    val_df = temp_df.iloc[val_idx].reset_index(drop=True)
    test_df = temp_df.iloc[test_idx].reset_index(drop=True)

    print(f"Group split column: {group_column}")
    print(f"Train/Test group overlap: {len(set(train_df[group_column]) & set(test_df[group_column]))}")
    return train_df, val_df, test_df


def print_distribution(name: str, labels: pd.Series) -> None:
    counts = labels.value_counts()
    total = len(labels) or 1
    print(f"\n{name} class distribution:")
    for label, count in counts.items():
        print(f"  {label:<2} {count:>6} ({(count / total) * 100:6.2f}%)")


def train_models(X_train: pd.DataFrame, y_train: np.ndarray) -> tuple[LGBMClassifier, XGBClassifier]:
    negative_count = int(np.sum(y_train == 0))
    positive_count = int(np.sum(y_train == 1))
    scale_pos_weight = float(negative_count / positive_count) if positive_count else 1.0

    lgb_model = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        class_weight="balanced",
        random_state=42,
        verbose=-1,
    )
    xgb_model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        objective="binary:logistic",
        eval_metric="auc",
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        verbosity=0,
    )

    lgb_model.fit(X_train, y_train)
    xgb_model.fit(X_train, y_train)
    return lgb_model, xgb_model


def evaluate(name: str, model, X_eval: pd.DataFrame, y_eval: np.ndarray) -> dict[str, Any]:
    y_pred = model.predict(X_eval)
    y_proba = model.predict_proba(X_eval)[:, 1]
    report = classification_report(y_eval, y_pred, digits=4, zero_division=0, output_dict=True)
    matrix = confusion_matrix(y_eval, y_pred)
    roc_auc = float(roc_auc_score(y_eval, y_proba))

    print(f"\n{'=' * 72}")
    print(name)
    print(f"{'=' * 72}")
    print(classification_report(y_eval, y_pred, digits=4, zero_division=0))
    print("Confusion matrix:")
    print(matrix)
    print(f"ROC-AUC: {roc_auc:.4f}")
    return {
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "roc_auc": roc_auc,
    }


def run_cv(train_df: pd.DataFrame, label_column: str, feature_columns: list[str], cv_folds: int) -> dict[str, Any]:
    splitter = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
    y = train_df[label_column].to_numpy()
    metrics = {"lightgbm": {"precision": [], "recall": [], "f1": []}, "xgboost": {"precision": [], "recall": [], "f1": []}}

    for fold_index, (fold_train_idx, fold_val_idx) in enumerate(splitter.split(train_df[feature_columns], y), start=1):
        fold_train = train_df.iloc[fold_train_idx].reset_index(drop=True)
        fold_val = train_df.iloc[fold_val_idx].reset_index(drop=True)
        lgb_model, xgb_model = train_models(fold_train[feature_columns], fold_train[label_column].to_numpy())
        for model_name, model in [("lightgbm", lgb_model), ("xgboost", xgb_model)]:
            predictions = model.predict(fold_val[feature_columns])
            precision, recall, f1, _ = precision_recall_fscore_support(
                fold_val[label_column],
                predictions,
                average="macro",
                zero_division=0,
            )
            metrics[model_name]["precision"].append(float(precision))
            metrics[model_name]["recall"].append(float(recall))
            metrics[model_name]["f1"].append(float(f1))
            print(
                f"CV fold {fold_index}/{cv_folds} - {model_name}: "
                f"precision={precision:.4f} recall={recall:.4f} f1={f1:.4f}"
            )

    summary = {}
    print("\nCV summary:")
    for model_name, model_metrics in metrics.items():
        summary[model_name] = {
            "precision_mean": float(np.mean(model_metrics["precision"])),
            "precision_std": float(np.std(model_metrics["precision"])),
            "recall_mean": float(np.mean(model_metrics["recall"])),
            "recall_std": float(np.std(model_metrics["recall"])),
            "f1_mean": float(np.mean(model_metrics["f1"])),
            "f1_std": float(np.std(model_metrics["f1"])),
        }
        print(
            f"  {model_name:<10} "
            f"precision={summary[model_name]['precision_mean']:.4f}±{summary[model_name]['precision_std']:.4f} "
            f"recall={summary[model_name]['recall_mean']:.4f}±{summary[model_name]['recall_std']:.4f} "
            f"f1={summary[model_name]['f1_mean']:.4f}±{summary[model_name]['f1_std']:.4f}"
        )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproducible FILE model training template with dataset audit and metadata.")
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--allow-mock-save", action="store_true", help="Allow saving artifacts even when the dataset is mocked.")
    parser.add_argument("--cv-folds", type=int, default=5)
    args = parser.parse_args()

    dataset_path = detect_dataset()
    raw_df, dataset_mode = load_dataset(dataset_path)
    prepared_df, label_column, group_column = prepare_features(raw_df)
    feature_columns = BASE_FEATURE_COLUMNS + EXTRA_FEATURE_COLUMNS
    train_df, val_df, test_df = grouped_split(prepared_df, label_column, group_column, random_state=42)

    print(f"Dataset mode: {dataset_mode}")
    print(f"Rows: {len(prepared_df)}")
    print_distribution("Train", train_df[label_column])
    print_distribution("Validation", val_df[label_column])
    print_distribution("Test", test_df[label_column])

    cv_summary = run_cv(train_df, label_column, feature_columns, cv_folds=args.cv_folds)
    lgb_model, xgb_model = train_models(train_df[feature_columns], train_df[label_column].to_numpy())
    val_results = {
        "lightgbm": evaluate("LightGBM - validation", lgb_model, val_df[feature_columns], val_df[label_column].to_numpy()),
        "xgboost": evaluate("XGBoost - validation", xgb_model, val_df[feature_columns], val_df[label_column].to_numpy()),
    }

    refit_df = pd.concat([train_df, val_df], ignore_index=True)
    lgb_model, xgb_model = train_models(refit_df[feature_columns], refit_df[label_column].to_numpy())
    test_results = {
        "lightgbm": evaluate("LightGBM - test", lgb_model, test_df[feature_columns], test_df[label_column].to_numpy()),
        "xgboost": evaluate("XGBoost - test", xgb_model, test_df[feature_columns], test_df[label_column].to_numpy()),
    }

    unseen_family_results = None
    if group_column is not None:
        unseen_groups = sorted(set(test_df[group_column]) - set(train_df[group_column]))
        if unseen_groups:
            subset = test_df[test_df[group_column].isin(unseen_groups)].reset_index(drop=True)
            if not subset.empty:
                unseen_family_results = {
                    "lightgbm": evaluate("LightGBM - unseen family subset", lgb_model, subset[feature_columns], subset[label_column].to_numpy()),
                    "xgboost": evaluate("XGBoost - unseen family subset", xgb_model, subset[feature_columns], subset[label_column].to_numpy()),
                }

    dataset_md5 = compute_file_md5(dataset_path) if dataset_path is not None and dataset_path.is_file() else "mock-data"
    metadata = {
        "dataset_mode": dataset_mode,
        "dataset_path": str(dataset_path) if dataset_path is not None else None,
        "dataset_md5": dataset_md5,
        "label_column": label_column,
        "group_column": group_column,
        "feature_columns": feature_columns,
        "xgboost_version": xgb_version,
        "cv_summary": cv_summary,
        "validation": val_results,
        "test": test_results,
        "unseen_family_subset": unseen_family_results,
    }
    save_json(DATA_DIR / "file_retrain_template_summary.json", metadata)

    if not args.no_save and (dataset_mode == "real" or args.allow_mock_save):
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(lgb_model, MODELS_DIR / "lgbm.pkl")
        save_xgboost_model(xgb_model, MODELS_DIR / "xgb.ubj", legacy_pickle_path=MODELS_DIR / "xgb.pkl")
        joblib.dump(feature_columns, MODELS_DIR / "feature_names.pkl")
        save_json(MODELS_DIR / "model_metadata.json", metadata)
        print(f"Saved template artifacts to {MODELS_DIR}")
    elif dataset_mode == "mock":
        print("Skipping artifact save because the script is running on mock data. Use --allow-mock-save to override.")
    else:
        print("Skipping artifact save because --no-save was set.")

    print_done("file_retrain_template.py")


if __name__ == "__main__":
    main()
