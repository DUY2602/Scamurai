"""Retrain URL classification models and emit backend-compatible artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from URL.utils.preprocess import FEATURE_COLUMNS, extract_features

ARTIFACT_FILES = [
    "lgbm_model.pkl",
    "xgb_model.pkl",
    "xgb_model.ubj",  # XGBoost universal binary format
    "feature_names.pkl",
    "feature_names_xgb.pkl",
    "scaler.pkl",
    "scaler_xgb.pkl",
    "label_encoder.pkl",
    "training_report.json",
]

LEGACY_ARTIFACT_FILES = [
    "kmeans_model.pkl",
]

HARDCASE_URLS: list[dict[str, Any]] = [
    {"url": "https://www.google.com", "target": "benign", "weight": 40.0},
    {
        "url": "https://www.google.com/search?q=RESTful&oq=RESTful&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQRRg7MgYIAhBFGDvSAQgzMDU5ajBqN6gCALACAA&sourceid=chrome&ie=UTF-8",
        "target": "benign",
        "weight": 95.0,
    },
    {
        "url": "https://www.google.com/search?q=paypal+login+help&sourceid=chrome&ie=UTF-8",
        "target": "benign",
        "weight": 80.0,
    },
    {
        "url": "https://mail.google.com/mail/u/0/#search/github/FMfcgzQfBsvSLljXgwBfwMRBPkgBQZMN",
        "target": "benign",
        "weight": 70.0,
    },
    {"url": "https://swinburne.instructure.com/courses/71633", "target": "benign", "weight": 55.0},
    {
        "url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "target": "benign",
        "weight": 45.0,
    },
    {"url": "https://github.com/login?return_to=%2Fsettings%2Fprofile", "target": "benign", "weight": 45.0},
    {"url": "https://secure-paypal-login-account-update.xyz/verify", "target": "harm", "weight": 80.0},
    {"url": "http://192.168.1.20/login/verify", "target": "harm", "weight": 80.0},
    {"url": "https://appleid-confirm-account-update.cc/login", "target": "harm", "weight": 70.0},
    {"url": "https://verify-chase-bank-account-update.biz/signin", "target": "harm", "weight": 70.0},
    {"url": "https://microsoft-security-alert-login.top/verify", "target": "harm", "weight": 70.0},
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrain URL threat-detection models.")
    parser.add_argument(
        "--data-path",
        type=Path,
        default=Path("URL/data/processed_malicious_url.csv"),
        help="Path to the processed URL training dataset CSV.",
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path("URL/models"),
        help="Directory where trained model artifacts will be saved.",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Holdout size for evaluation.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--sample-frac",
        type=float,
        default=1.0,
        help="Optional fraction of rows to use for faster experiments. Default uses all rows.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not copy existing model artifacts into a timestamped backup folder before overwrite.",
    )
    parser.add_argument(
        "--hardcase-scale",
        type=float,
        default=1.0,
        help="Multiplier for challenge-case sample weights. Default: 1.0",
    )
    return parser.parse_args()


def backup_existing_artifacts(models_dir: Path) -> Path | None:
    backup_candidates = ARTIFACT_FILES + LEGACY_ARTIFACT_FILES
    existing = [models_dir / file_name for file_name in backup_candidates if (models_dir / file_name).exists()]
    if not existing:
        return None

    backup_dir = models_dir / "backups" / datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    for artifact in existing:
        shutil.copy2(artifact, backup_dir / artifact.name)
    return backup_dir


def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
) -> dict[str, Any]:
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics: dict[str, Any] = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": report,
    }
    if y_prob is not None:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_prob)), 4)
    return metrics


def evaluate_soft_voting_thresholds(
    y_true: np.ndarray,
    avg_prob: np.ndarray,
    harmful_label: int,
    benign_label: int,
    thresholds: list[float],
) -> tuple[dict[str, dict[str, Any]], float, np.ndarray]:
    threshold_reports: dict[str, dict[str, Any]] = {}
    selected_threshold: float | None = None
    selected_score: tuple[float, float, float] | None = None

    for threshold in thresholds:
        y_pred = np.where(avg_prob >= threshold, harmful_label, benign_label)
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        harmful_metrics = report[str(harmful_label)]
        threshold_reports[f"{threshold:.2f}"] = {
            "threshold": float(threshold),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": report,
            "roc_auc": round(float(roc_auc_score(y_true, avg_prob)), 4),
        }

        precision = float(harmful_metrics["precision"])
        recall = float(harmful_metrics["recall"])
        f1_value = float(harmful_metrics["f1-score"])
        if recall >= 0.80 and precision >= 0.65:
            candidate_score = (f1_value, recall, precision)
            if selected_score is None or candidate_score > selected_score:
                selected_score = candidate_score
                selected_threshold = float(threshold)

    if selected_threshold is None:
        fallback_threshold = thresholds[0]
        best_fallback_score: tuple[float, float, float] | None = None
        for threshold in thresholds:
            report = threshold_reports[f"{threshold:.2f}"]["classification_report"]
            harmful_metrics = report[str(harmful_label)]
            precision = float(harmful_metrics["precision"])
            recall = float(harmful_metrics["recall"])
            f1_value = float(harmful_metrics["f1-score"])
            candidate_score = (float(precision >= 0.65), recall, f1_value)
            if best_fallback_score is None or candidate_score > best_fallback_score:
                best_fallback_score = candidate_score
                fallback_threshold = threshold
        selected_threshold = float(fallback_threshold)

    selected_pred = np.where(avg_prob >= selected_threshold, harmful_label, benign_label)
    return threshold_reports, selected_threshold, selected_pred


def refresh_processed_dataset(data_path: Path) -> pd.DataFrame:
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "target" not in df.columns:
        required_columns = FEATURE_COLUMNS + ["target"]
        missing_columns = [column for column in required_columns if column not in df.columns]
        if missing_columns:
            raise ValueError(f"Dataset is missing required columns: {missing_columns}")
        return df

    print(f"Refreshing processed dataset at {data_path} with {len(FEATURE_COLUMNS)} URL features...")
    feature_rows = [extract_features(url) for url in df["url"].astype(str)]
    feature_frame = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
    refreshed_df = pd.concat([df[["url", "target"]].reset_index(drop=True), feature_frame], axis=1)
    refreshed_df.to_csv(data_path, index=False, encoding="utf-8")
    return refreshed_df


def build_hardcase_frame(scale: float) -> tuple[pd.DataFrame, np.ndarray]:
    rows: list[dict[str, Any]] = []
    weights: list[float] = []
    for item in HARDCASE_URLS:
        row = extract_features(item["url"])
        row["target"] = item["target"]
        rows.append(row)
        weights.append(float(item["weight"]) * scale)
    return pd.DataFrame(rows), np.asarray(weights, dtype=float)


def extract_domain(url: str) -> str:
    normalized = str(url or "").strip().lower().replace("[", "").replace("]", "")
    address = normalized if "://" in normalized else f"http://{normalized}"
    try:
        parsed = urlparse(address)
    except Exception:
        parsed = urlparse("http://invalid.local")

    hostname = (parsed.hostname or "").strip(".")
    if not hostname:
        return "__missing__"

    if hostname.replace(".", "").isdigit():
        return hostname

    parts = [part for part in hostname.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def split_by_domain(df: pd.DataFrame, test_size: float, random_state: int) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    if "url" not in df.columns:
        raise ValueError("Domain-based split requires a 'url' column in the processed dataset.")

    split_df = df.copy()
    split_df["domain"] = split_df["url"].astype(str).map(extract_domain)

    unique_domains = split_df["domain"].dropna().astype(str).unique()
    shuffled_domains = np.array(unique_domains, dtype=object)
    rng = np.random.default_rng(random_state)
    rng.shuffle(shuffled_domains)

    split_index = int(len(shuffled_domains) * (1.0 - test_size))
    split_index = min(max(split_index, 1), max(len(shuffled_domains) - 1, 1))

    train_domains = set(shuffled_domains[:split_index].tolist())
    test_domains = set(shuffled_domains[split_index:].tolist())

    train_df = split_df[split_df["domain"].isin(train_domains)].drop(columns=["domain"]).reset_index(drop=True)
    test_df = split_df[split_df["domain"].isin(test_domains)].drop(columns=["domain"]).reset_index(drop=True)

    overlap = train_domains & test_domains
    split_summary = {
        "train_domains": int(len(train_domains)),
        "test_domains": int(len(test_domains)),
        "domain_overlap": int(len(overlap)),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "train_label_distribution": {str(label): int(count) for label, count in train_df["target"].value_counts().to_dict().items()},
        "test_label_distribution": {str(label): int(count) for label, count in test_df["target"].value_counts().to_dict().items()},
    }

    if len(overlap) != 0:
        raise RuntimeError(f"Domain split failed; overlap detected: {sorted(list(overlap))[:5]}")

    return train_df, test_df, split_summary


def print_model_metrics(
    model_name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None,
    target_names: list[str],
) -> None:
    print(f"\n=== {model_name} ===")
    print(classification_report(y_true, y_pred, target_names=target_names, zero_division=0))
    if y_prob is not None:
        print(f"ROC AUC: {roc_auc_score(y_true, y_prob):.4f}")


def print_soft_voting_threshold_metrics(
    threshold_reports: dict[str, dict[str, Any]],
    target_names: list[str],
    harmful_label: int,
) -> None:
    print("\n=== Soft Voting Threshold Sweep ===")
    for threshold_key, report_bundle in threshold_reports.items():
        report = report_bundle["classification_report"]
        harmful_metrics = report[str(harmful_label)]
        print(f"\nThreshold {threshold_key}")
        print("Confusion matrix:")
        print(np.asarray(report_bundle["confusion_matrix"]))
        print(
            f"Harm precision={harmful_metrics['precision']:.4f} "
            f"recall={harmful_metrics['recall']:.4f} "
            f"f1={harmful_metrics['f1-score']:.4f}"
        )
        print("Classification report:")
        print(
            pd.DataFrame(report).transpose().loc[
                [str(0), str(1), "accuracy", "macro avg", "weighted avg"]
            ].rename(index={str(0): target_names[0], str(1): target_names[1]})
        )


def main() -> None:
    args = parse_args()
    if not (0 < args.sample_frac <= 1.0):
        raise ValueError("--sample-frac must be in the range (0, 1].")
    if args.hardcase_scale <= 0:
        raise ValueError("--hardcase-scale must be > 0.")

    models_dir = args.models_dir
    models_dir.mkdir(parents=True, exist_ok=True)

    backup_dir = None if args.no_backup else backup_existing_artifacts(models_dir)

    df = refresh_processed_dataset(args.data_path)
    required_columns = FEATURE_COLUMNS + ["target"]
    missing_columns = [column for column in required_columns if column not in df.columns]
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {missing_columns}")

    df = df.dropna(subset=required_columns).copy()
    if args.sample_frac < 1.0:
        df = df.sample(frac=args.sample_frac, random_state=args.random_state).reset_index(drop=True)

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["target"].astype(str))
    target_names = label_encoder.classes_.tolist()
    harmful_label = int(label_encoder.transform(["harm"])[0])
    benign_label = int(label_encoder.transform(["benign"])[0])

    train_df, test_df, split_summary = split_by_domain(
        df,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    X_train = train_df[FEATURE_COLUMNS]
    X_test = test_df[FEATURE_COLUMNS]
    y_train = label_encoder.transform(train_df["target"].astype(str))
    y_test = label_encoder.transform(test_df["target"].astype(str))

    hardcase_frame, hardcase_weights = build_hardcase_frame(args.hardcase_scale)
    hardcase_targets = label_encoder.transform(hardcase_frame["target"].astype(str))
    X_train = pd.concat([X_train, hardcase_frame[FEATURE_COLUMNS]], ignore_index=True)
    y_train = np.concatenate([y_train, hardcase_targets])
    train_sample_weight = np.concatenate([np.ones(len(X_train) - len(hardcase_frame), dtype=float), hardcase_weights])

    scaler = StandardScaler()
    scaler_xgb = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    X_train_xgb = scaler_xgb.fit_transform(X_train)
    X_test_xgb = scaler_xgb.transform(X_test)

    X_train_scaled_frame = pd.DataFrame(X_train_scaled, columns=FEATURE_COLUMNS)
    X_test_scaled_frame = pd.DataFrame(X_test_scaled, columns=FEATURE_COLUMNS)
    X_train_xgb_frame = pd.DataFrame(X_train_xgb, columns=FEATURE_COLUMNS)
    X_test_xgb_frame = pd.DataFrame(X_test_xgb, columns=FEATURE_COLUMNS)

    lgbm = LGBMClassifier(
        n_estimators=250,
        learning_rate=0.05,
        num_leaves=31,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_alpha=0.05,
        reg_lambda=0.2,
        class_weight="balanced",
        random_state=args.random_state,
        n_jobs=-1,
        verbosity=-1,
    )
    lgbm.fit(X_train_scaled_frame, y_train, sample_weight=train_sample_weight)
    lgbm_test_pred = lgbm.predict(X_test_scaled_frame)
    lgbm_test_prob = lgbm.predict_proba(X_test_scaled_frame)[:, harmful_label]

    negative_count = int((y_train == benign_label).sum())
    positive_count = int((y_train == harmful_label).sum())
    scale_pos_weight = negative_count / max(positive_count, 1)

    xgb = XGBClassifier(
        n_estimators=220,
        learning_rate=0.05,
        max_depth=8,
        min_child_weight=1,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_alpha=0.05,
        reg_lambda=1.0,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=args.random_state,
        n_jobs=-1,
        tree_method="hist",
        scale_pos_weight=scale_pos_weight,
    )
    xgb.fit(X_train_xgb_frame, y_train, sample_weight=train_sample_weight)
    xgb_test_pred = xgb.predict(X_test_xgb_frame)
    xgb_test_prob = xgb.predict_proba(X_test_xgb_frame)[:, harmful_label]

    ensemble_test_prob = (lgbm_test_prob + xgb_test_prob) / 2.0
    threshold_candidates = [0.40, 0.45, 0.50]
    soft_voting_thresholds, selected_threshold, ensemble_test_pred = evaluate_soft_voting_thresholds(
        y_test,
        ensemble_test_prob,
        harmful_label,
        benign_label,
        threshold_candidates,
    )

    # Extract feature importance from both models
    lgbm_importance = dict(zip(FEATURE_COLUMNS, lgbm.feature_importances_.tolist()))
    xgb_importance_array = xgb.feature_importances_
    xgb_importance = dict(zip(FEATURE_COLUMNS, xgb_importance_array.tolist()))

    # Compute ensemble feature importance (average)
    ensemble_importance = {
        feature: round((lgbm_importance[feature] + xgb_importance[feature]) / 2.0, 6)
        for feature in FEATURE_COLUMNS
    }

    report: dict[str, Any] = {
        "task": "url_retraining",
        "data_path": str(args.data_path),
        "models_dir": str(models_dir),
        "backup_dir": str(backup_dir) if backup_dir else None,
        "dataset": {
            "rows": int(len(df)),
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "target_classes": target_names,
            "label_distribution": {
                class_name: int(count)
                for class_name, count in zip(*np.unique(df["target"].astype(str), return_counts=True), strict=False)
            },
            "hardcase_rows": int(len(hardcase_frame)),
            "domain_split": split_summary,
        },
        "lightgbm": evaluate_predictions(y_test, lgbm_test_pred, lgbm_test_prob),
        "xgboost": evaluate_predictions(y_test, xgb_test_pred, xgb_test_prob),
        "ensemble": evaluate_predictions(y_test, ensemble_test_pred, ensemble_test_prob),
        "ensemble_soft_voting": {
            "probability_source": "avg_prob = (lgbm_prob + xgb_prob) / 2",
            "threshold_candidates": threshold_candidates,
            "selected_threshold": selected_threshold,
            "threshold_reports": soft_voting_thresholds,
        },
        "feature_importance": {
            "lgbm": lgbm_importance,
            "xgboost": xgb_importance,
            "ensemble_avg": ensemble_importance,
            "ranked": sorted(ensemble_importance.items(), key=lambda x: x[1], reverse=True),
        },
        "metadata": {
            "feature_columns": FEATURE_COLUMNS,
            "scale_pos_weight": round(float(scale_pos_weight), 6),
            "sample_frac": args.sample_frac,
            "hardcase_scale": args.hardcase_scale,
        },
    }

    joblib.dump(lgbm, models_dir / "lgbm_model.pkl")
    joblib.dump(xgb, models_dir / "xgb_model.pkl")
    # Save XGBoost in universal binary format (preferred)
    xgb.get_booster().save_model(str(models_dir / "xgb_model.ubj"))
    joblib.dump(FEATURE_COLUMNS, models_dir / "feature_names.pkl")
    joblib.dump(FEATURE_COLUMNS, models_dir / "feature_names_xgb.pkl")
    joblib.dump(scaler, models_dir / "scaler.pkl")
    joblib.dump(scaler_xgb, models_dir / "scaler_xgb.pkl")
    joblib.dump(label_encoder, models_dir / "label_encoder.pkl")

    legacy_kmeans_path = models_dir / "kmeans_model.pkl"
    if legacy_kmeans_path.exists():
        legacy_kmeans_path.unlink()

    (models_dir / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print_model_metrics("LightGBM", y_test, lgbm_test_pred, lgbm_test_prob, target_names)
    print_model_metrics("XGBoost", y_test, xgb_test_pred, xgb_test_prob, target_names)
    print_model_metrics(f"Ensemble (Soft Voting @ {selected_threshold:.2f})", y_test, ensemble_test_pred, ensemble_test_prob, target_names)
    print_soft_voting_threshold_metrics(soft_voting_thresholds, target_names, harmful_label)
    print(f"\nSelected soft-voting threshold: {selected_threshold:.2f}")
    print("\n=== Domain Split Summary ===")
    print(json.dumps(split_summary, indent=2))

    print("\n=== training_report.json ===")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
