from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from ml_artifact_utils import print_done, save_json, save_xgboost_model
from URL.url_feature_engineering import build_url_risk_features
from URL.utils.preprocess import process_and_save_csv


ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"
RAW_DATA_PATH = DATA_DIR / "malicious_url.csv"
PROCESSED_DATA_PATH = DATA_DIR / "processed_malicious_url.csv"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.pkl"
FEATURE_NAMES_XGB_PATH = MODELS_DIR / "feature_names_xgb.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
LGB_MODEL_PATH = MODELS_DIR / "lgbm_model.pkl"
XGB_MODEL_PATH = MODELS_DIR / "xgb_model.pkl"
XGB_MODEL_UBJ_PATH = MODELS_DIR / "xgb_model.ubj"
SCALER_XGB_PATH = MODELS_DIR / "scaler_xgb.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
MODEL_METADATA_PATH = MODELS_DIR / "model_metadata.json"
BACKUP_DIR = MODELS_DIR / "backup_v2"

NON_FEATURE_COLUMNS = {"url", "target", "hostname", "registered_domain", "normalized_url"}
NEW_RISK_FEATURES = [
    "brand_impersonation_score",
    "typosquat_distance",
    "tld_risk_score",
    "subdomain_brand_mismatch",
]


def ensure_processed_dataset(max_rows: int = 0, random_state: int = 42) -> pd.DataFrame:
    if not PROCESSED_DATA_PATH.is_file():
        process_and_save_csv(str(RAW_DATA_PATH), str(PROCESSED_DATA_PATH))

    if max_rows > 0:
        per_class_target = max(1, max_rows // 2)
        sampled_chunks: list[pd.DataFrame] = []
        collected = {"benign": 0, "harm": 0}
        for chunk in pd.read_csv(PROCESSED_DATA_PATH, chunksize=50000):
            chunk = chunk.drop_duplicates(subset=["url"])
            chunk["target"] = chunk["target"].str.lower()
            chunk_parts = []
            for label in ["benign", "harm"]:
                remaining = per_class_target - collected[label]
                if remaining <= 0:
                    continue
                subset = chunk[chunk["target"] == label]
                if subset.empty:
                    continue
                take = min(len(subset), remaining)
                chunk_parts.append(subset.sample(n=take, random_state=random_state))
                collected[label] += take
            if chunk_parts:
                sampled_chunks.append(pd.concat(chunk_parts, ignore_index=True))
            if all(count >= per_class_target for count in collected.values()):
                break

        if sampled_chunks:
            sampled_df = pd.concat(sampled_chunks, ignore_index=True)
            sampled_df = sampled_df.drop_duplicates(subset=["url"]).reset_index(drop=True)
            print(f"Loaded sampled processed dataset: {len(sampled_df)} rows")
            return sampled_df

    return pd.read_csv(PROCESSED_DATA_PATH).drop_duplicates(subset=["url"]).reset_index(drop=True)


def ensure_risk_features(df: pd.DataFrame) -> pd.DataFrame:
    enriched = df.copy()
    missing = [feature for feature in NEW_RISK_FEATURES if feature not in enriched.columns]
    if not missing:
        return enriched

    derived_rows = [
        build_url_risk_features(
            hostname=row.hostname,
            registered_domain=row.registered_domain,
        )
        for row in enriched.itertuples(index=False)
    ]
    derived_df = pd.DataFrame(derived_rows)
    for column in NEW_RISK_FEATURES:
        enriched[column] = derived_df[column]
    return enriched


def load_source_feature_names(df: pd.DataFrame) -> list[str]:
    if FEATURE_NAMES_PATH.is_file():
        feature_names = list(joblib.load(FEATURE_NAMES_PATH))
        print(f"Loaded source-of-truth features from {FEATURE_NAMES_PATH} ({len(feature_names)} columns)")
        return feature_names
    fallback = [column for column in df.columns if column not in NON_FEATURE_COLUMNS and column != "is_https"]
    print("WARNING: feature_names.pkl missing. Falling back to processed dataset columns.")
    return fallback


def print_drift_report(source_features: list[str], built_features: list[str], label: str) -> dict[str, list[str]]:
    missing = sorted(set(source_features) - set(built_features))
    extra = sorted(set(built_features) - set(source_features))
    print(f"\nFeature drift check [{label}]")
    print(f"  Source features: {len(source_features)}")
    print(f"  Built features:  {len(built_features)}")
    print(f"  Missing: {missing}")
    print(f"  Extra:   {extra}")
    return {"missing": missing, "extra": extra}


def find_best_group_split(
    df: pd.DataFrame,
    *,
    group_column: str,
    label_column: str,
    test_size: float,
    random_state: int,
    attempts: int = 32,
) -> tuple[np.ndarray, np.ndarray]:
    overall_positive_rate = float((df[label_column] == "harm").mean())
    best_indices: tuple[np.ndarray, np.ndarray] | None = None
    best_score = float("inf")

    for offset in range(attempts):
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state + offset)
        train_idx, test_idx = next(splitter.split(df, groups=df[group_column]))
        train_groups = set(df.iloc[train_idx][group_column])
        test_groups = set(df.iloc[test_idx][group_column])
        overlap = train_groups & test_groups
        if overlap:
            continue

        train_rate = float((df.iloc[train_idx][label_column] == "harm").mean())
        test_rate = float((df.iloc[test_idx][label_column] == "harm").mean())
        score = abs(train_rate - overall_positive_rate) + abs(test_rate - overall_positive_rate)
        if score < best_score:
            best_score = score
            best_indices = (train_idx, test_idx)

    if best_indices is None:
        raise RuntimeError("Could not compute a non-overlapping GroupShuffleSplit.")

    return best_indices


def split_grouped_dataset(df: pd.DataFrame, random_state: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train_val_idx, test_idx = find_best_group_split(
        df,
        group_column="registered_domain",
        label_column="target",
        test_size=0.15,
        random_state=random_state,
    )
    train_val_df = df.iloc[train_val_idx].reset_index(drop=True)
    test_df = df.iloc[test_idx].reset_index(drop=True)

    train_idx, val_idx = find_best_group_split(
        train_val_df,
        group_column="registered_domain",
        label_column="target",
        test_size=0.1764705882,  # 15% of original total after removing 15% test
        random_state=random_state + 1000,
    )
    train_df = train_val_df.iloc[train_idx].reset_index(drop=True)
    val_df = train_val_df.iloc[val_idx].reset_index(drop=True)

    train_domains = set(train_df["registered_domain"])
    val_domains = set(val_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    print("\nGrouped split summary:")
    print(f"  Train rows={len(train_df)} unique_domains={len(train_domains)}")
    print(f"  Val rows={len(val_df)} unique_domains={len(val_domains)}")
    print(f"  Test rows={len(test_df)} unique_domains={len(test_domains)}")
    print(f"  Train/Val overlap={len(train_domains & val_domains)}")
    print(f"  Train/Test overlap={len(train_domains & test_domains)}")
    print(f"  Val/Test overlap={len(val_domains & test_domains)}")

    return train_df, val_df, test_df


def print_class_distribution(name: str, labels: pd.Series) -> None:
    counts = labels.value_counts()
    total = len(labels) or 1
    print(f"\n{name} class distribution:")
    for label, count in counts.items():
        print(f"  {label:<6} {count:>8} ({(count / total) * 100:6.2f}%)")


def evaluate_split(name: str, y_true, y_pred, y_proba, label_encoder: LabelEncoder) -> dict[str, Any]:
    report_dict = classification_report(
        y_true,
        y_pred,
        target_names=label_encoder.classes_,
        output_dict=True,
        digits=4,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred)
    roc_auc = float(roc_auc_score(y_true, y_proba))

    print(f"\n{'=' * 72}")
    print(name)
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
    print(f"ROC-AUC: {roc_auc:.4f}")

    return {
        "classification_report": report_dict,
        "confusion_matrix": matrix.tolist(),
        "roc_auc": roc_auc,
        "harm_precision": float(report_dict["harm"]["precision"]),
        "harm_recall": float(report_dict["harm"]["recall"]),
        "macro_f1": float(report_dict["macro avg"]["f1-score"]),
    }


def build_models(y_train: np.ndarray) -> tuple[LGBMClassifier, XGBClassifier]:
    negative_count = int(np.sum(y_train == 0))
    positive_count = int(np.sum(y_train == 1))
    scale_pos_weight = float(negative_count / positive_count) if positive_count else 1.0

    lgb_model = LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=63,
        class_weight="balanced",
        random_state=42,
        verbose=-1,
    )
    xgb_model = XGBClassifier(
        n_estimators=350,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.85,
        objective="binary:logistic",
        eval_metric="auc",
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        verbosity=0,
    )
    return lgb_model, xgb_model


def run_cv(train_df: pd.DataFrame, feature_cols: list[str], label_encoder: LabelEncoder, cv_folds: int) -> dict[str, Any]:
    try:
        from sklearn.model_selection import StratifiedGroupKFold

        splitter = StratifiedGroupKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        split_iter = splitter.split(train_df[feature_cols], label_encoder.transform(train_df["target"]), groups=train_df["registered_domain"])
    except Exception:
        splitter = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        split_iter = splitter.split(train_df[feature_cols], label_encoder.transform(train_df["target"]))

    results = {"lightgbm": {"precision": [], "recall": [], "f1": []}, "xgboost": {"precision": [], "recall": [], "f1": []}}
    for fold_index, (cv_train_idx, cv_val_idx) in enumerate(split_iter, start=1):
        cv_train = train_df.iloc[cv_train_idx].reset_index(drop=True)
        cv_val = train_df.iloc[cv_val_idx].reset_index(drop=True)
        y_cv_train = label_encoder.transform(cv_train["target"])
        y_cv_val = label_encoder.transform(cv_val["target"])
        X_cv_train = cv_train[feature_cols]
        X_cv_val = cv_val[feature_cols]
        scaler = StandardScaler()
        X_cv_train_scaled = scaler.fit_transform(X_cv_train)
        X_cv_val_scaled = scaler.transform(X_cv_val)

        lgb_model, xgb_model = build_models(y_cv_train)
        lgb_model.fit(X_cv_train, y_cv_train)
        xgb_model.fit(X_cv_train_scaled, y_cv_train)

        for model_name, model, X_eval in [
            ("lightgbm", lgb_model, X_cv_val),
            ("xgboost", xgb_model, X_cv_val_scaled),
        ]:
            predictions = model.predict(X_eval)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_cv_val,
                predictions,
                average="macro",
                zero_division=0,
            )
            results[model_name]["precision"].append(float(precision))
            results[model_name]["recall"].append(float(recall))
            results[model_name]["f1"].append(float(f1))
            print(
                f"CV fold {fold_index}/{cv_folds} - {model_name}: "
                f"precision={precision:.4f} recall={recall:.4f} f1={f1:.4f}"
            )

    summary = {}
    print("\nCV summary:")
    for model_name, metrics in results.items():
        summary[model_name] = {
            "precision_mean": float(np.mean(metrics["precision"])),
            "precision_std": float(np.std(metrics["precision"])),
            "recall_mean": float(np.mean(metrics["recall"])),
            "recall_std": float(np.std(metrics["recall"])),
            "f1_mean": float(np.mean(metrics["f1"])),
            "f1_std": float(np.std(metrics["f1"])),
        }
        print(
            f"  {model_name:<10} "
            f"precision={summary[model_name]['precision_mean']:.4f}±{summary[model_name]['precision_std']:.4f} "
            f"recall={summary[model_name]['recall_mean']:.4f}±{summary[model_name]['recall_std']:.4f} "
            f"f1={summary[model_name]['f1_mean']:.4f}±{summary[model_name]['f1_std']:.4f}"
        )
    return summary


def train_variant(
    *,
    label: str,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: list[str],
    label_encoder: LabelEncoder,
) -> dict[str, Any]:
    X_train = train_df[feature_cols]
    X_val = val_df[feature_cols]
    y_train = label_encoder.transform(train_df["target"])
    y_val = label_encoder.transform(val_df["target"])

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    lgb_model, xgb_model = build_models(y_train)
    lgb_model.fit(X_train, y_train)
    xgb_model.fit(X_train_scaled, y_train)

    results = {
        "label": label,
        "feature_cols": feature_cols,
        "scaler": scaler,
        "lgb_model": lgb_model,
        "xgb_model": xgb_model,
        "validation": {},
    }
    for model_name, model, X_eval in [
        ("lightgbm", lgb_model, X_val),
        ("xgboost", xgb_model, X_val_scaled),
    ]:
        y_pred = model.predict(X_eval)
        y_proba = model.predict_proba(X_eval)[:, 1]
        results["validation"][model_name] = evaluate_split(
            f"{label} - {model_name} - validation",
            y_val,
            y_pred,
            y_proba,
            label_encoder,
        )

    return results


def evaluate_best_variant(
    variant: dict[str, Any],
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    label_encoder: LabelEncoder,
) -> dict[str, Any]:
    combined_train = pd.concat([train_df, val_df], ignore_index=True)
    feature_cols = variant["feature_cols"]
    X_refit = combined_train[feature_cols]
    X_test = test_df[feature_cols]
    y_refit = label_encoder.transform(combined_train["target"])
    y_test = label_encoder.transform(test_df["target"])

    scaler = StandardScaler()
    X_refit_scaled = scaler.fit_transform(X_refit)
    X_test_scaled = scaler.transform(X_test)

    lgb_model, xgb_model = build_models(y_refit)
    lgb_model.fit(X_refit, y_refit)
    xgb_model.fit(X_refit_scaled, y_refit)

    assert len(feature_cols) == X_refit.shape[1], "Feature count drift detected after refit."

    results = {
        "feature_cols": feature_cols,
        "scaler": scaler,
        "lgb_model": lgb_model,
        "xgb_model": xgb_model,
        "test": {},
    }
    for model_name, model, X_eval in [
        ("lightgbm", lgb_model, X_test),
        ("xgboost", xgb_model, X_test_scaled),
    ]:
        y_pred = model.predict(X_eval)
        y_proba = model.predict_proba(X_eval)[:, 1]
        results["test"][model_name] = evaluate_split(
            f"Best variant - {model_name} - test",
            y_test,
            y_pred,
            y_proba,
            label_encoder,
        )
    return results


def backup_existing_artifacts() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    for source in [FEATURE_NAMES_PATH, FEATURE_NAMES_XGB_PATH, LABEL_ENCODER_PATH, LGB_MODEL_PATH, XGB_MODEL_PATH, XGB_MODEL_UBJ_PATH, SCALER_PATH, SCALER_XGB_PATH, MODEL_METADATA_PATH]:
        if source.is_file():
            shutil.copy2(source, BACKUP_DIR / source.name)
    return BACKUP_DIR


def main() -> None:
    parser = argparse.ArgumentParser(description="Train URL models using deploy-aligned feature names and group-aware splits.")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--max-rows", type=int, default=0, help="Optional cap for smoke runs.")
    parser.add_argument("--no-save", action="store_true")
    args = parser.parse_args()

    df = ensure_processed_dataset(max_rows=args.max_rows, random_state=args.random_state)
    df = ensure_risk_features(df)
    if args.max_rows > 0 and len(df) > args.max_rows:
        df = (
            df.groupby("target", group_keys=False)
            .apply(lambda frame: frame.sample(min(len(frame), max(1, args.max_rows // 2)), random_state=args.random_state))
            .reset_index(drop=True)
        )
        print(f"Using sampled dataset for smoke run: {len(df)} rows")

    print_class_distribution("Full dataset", df["target"])
    source_features = load_source_feature_names(df)
    baseline_features = [feature for feature in source_features if feature in df.columns and feature not in {"is_https", "registered_domain_benign_rate", "registered_domain_seen_count"}]
    upgraded_features = baseline_features + [feature for feature in NEW_RISK_FEATURES if feature not in baseline_features]
    baseline_drift = print_drift_report(source_features, baseline_features, "baseline")
    upgraded_drift = print_drift_report(source_features, upgraded_features, "upgraded")

    label_encoder = LabelEncoder()
    label_encoder.fit(["benign", "harm"])
    train_df, val_df, test_df = split_grouped_dataset(df, random_state=args.random_state)
    print_class_distribution("Train", train_df["target"])
    print_class_distribution("Validation", val_df["target"])
    print_class_distribution("Test", test_df["target"])

    cv_summary = run_cv(train_df, baseline_features, label_encoder, cv_folds=args.cv_folds)
    baseline_variant = train_variant(
        label="baseline",
        train_df=train_df,
        val_df=val_df,
        feature_cols=baseline_features,
        label_encoder=label_encoder,
    )
    upgraded_variant = train_variant(
        label="upgraded",
        train_df=train_df,
        val_df=val_df,
        feature_cols=upgraded_features,
        label_encoder=label_encoder,
    )

    comparison = {
        "baseline": {
            model_name: {
                "harm_precision": metrics["harm_precision"],
                "harm_recall": metrics["harm_recall"],
                "macro_f1": metrics["macro_f1"],
            }
            for model_name, metrics in baseline_variant["validation"].items()
        },
        "upgraded": {
            model_name: {
                "harm_precision": metrics["harm_precision"],
                "harm_recall": metrics["harm_recall"],
                "macro_f1": metrics["macro_f1"],
            }
            for model_name, metrics in upgraded_variant["validation"].items()
        },
    }
    print("\nHarm precision/recall comparison:")
    print(json.dumps(comparison, indent=2))

    baseline_score = np.mean([baseline_variant["validation"][name]["macro_f1"] for name in ["lightgbm", "xgboost"]])
    upgraded_score = np.mean([upgraded_variant["validation"][name]["macro_f1"] for name in ["lightgbm", "xgboost"]])
    chosen_variant = upgraded_variant if upgraded_score >= baseline_score else baseline_variant
    chosen_name = chosen_variant["label"]
    print(f"\nChosen variant: {chosen_name}")

    final_results = evaluate_best_variant(chosen_variant, train_df, val_df, test_df, label_encoder)
    metadata = {
        "variant": chosen_name,
        "source_feature_names": source_features,
        "baseline_drift": baseline_drift,
        "upgraded_drift": upgraded_drift,
        "cv_summary": cv_summary,
        "comparison": comparison,
        "feature_count": len(final_results["feature_cols"]),
        "label_classes": label_encoder.classes_.tolist(),
    }
    save_json(DATA_DIR / "url_train_v2_summary.json", metadata)

    if not args.no_save:
        backup_dir = backup_existing_artifacts()
        joblib.dump(final_results["feature_cols"], FEATURE_NAMES_PATH)
        joblib.dump(final_results["feature_cols"], FEATURE_NAMES_XGB_PATH)
        joblib.dump(final_results["scaler"], SCALER_PATH)
        joblib.dump(final_results["scaler"], SCALER_XGB_PATH)
        joblib.dump(label_encoder, LABEL_ENCODER_PATH)
        joblib.dump(final_results["lgb_model"], LGB_MODEL_PATH)
        save_xgboost_model(final_results["xgb_model"], XGB_MODEL_UBJ_PATH, legacy_pickle_path=XGB_MODEL_PATH)
        save_json(MODEL_METADATA_PATH, metadata)
        print(f"Saved URL artifacts. Backup: {backup_dir}")
    else:
        print("Skipping artifact save because --no-save was set.")

    print_done("url_train_v2.py")


if __name__ == "__main__":
    main()
