from __future__ import annotations

import math
import os

import joblib
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from utils.preprocess import process_and_save_csv


ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
MODELS_DIR = os.path.join(ROOT, "models")

RAW_DATA_PATH = os.path.join(DATA_DIR, "malicious_url.csv")
PROCESSED_DATA_PATH = os.path.join(DATA_DIR, "processed_malicious_url.csv")
DOMAIN_STATS_PATH = os.path.join(MODELS_DIR, "domain_stats.pkl")

NON_FEATURE_COLUMNS = {"url", "target", "hostname", "registered_domain", "normalized_url"}


def ensure_processed_data() -> None:
    print("Regenerating processed URL dataset...")
    process_and_save_csv(RAW_DATA_PATH, PROCESSED_DATA_PATH)


def compute_domain_stats(train_df: pd.DataFrame) -> tuple[dict[str, dict[str, float]], float]:
    grouped = (
        train_df.groupby("registered_domain")["target"]
        .agg(
            total="count",
            benign_count=lambda series: int((series == "benign").sum()),
        )
        .reset_index()
    )
    global_benign_rate = float((train_df["target"] == "benign").mean())

    stats: dict[str, dict[str, float]] = {}
    for row in grouped.itertuples(index=False):
        benign_rate = (row.benign_count + 1.0) / (row.total + 2.0)
        stats[str(row.registered_domain)] = {
            "benign_rate": float(benign_rate),
            "seen_count": float(row.total),
        }
    return stats, global_benign_rate


def apply_domain_stats(df: pd.DataFrame, domain_stats: dict[str, dict[str, float]], global_benign_rate: float) -> pd.DataFrame:
    enriched = df.copy()
    benign_rates = []
    seen_counts = []

    for domain in enriched["registered_domain"].fillna(""):
        stats = domain_stats.get(str(domain), None)
        if stats is None:
            benign_rates.append(global_benign_rate)
            seen_counts.append(0.0)
        else:
            benign_rates.append(float(stats["benign_rate"]))
            seen_counts.append(math.log1p(float(stats["seen_count"])))

    enriched["registered_domain_benign_rate"] = benign_rates
    enriched["registered_domain_seen_count"] = seen_counts
    return enriched


def split_and_build_features():
    df = pd.read_csv(PROCESSED_DATA_PATH).drop_duplicates(subset=["url"]).copy()
    df["target"] = df["target"].str.lower()

    train_df, test_df = train_test_split(
        df,
        test_size=0.2,
        stratify=df["target"],
        random_state=42,
    )

    domain_stats, global_benign_rate = compute_domain_stats(train_df)
    train_df = apply_domain_stats(train_df, domain_stats, global_benign_rate)
    test_df = apply_domain_stats(test_df, domain_stats, global_benign_rate)

    feature_cols = [column for column in train_df.columns if column not in NON_FEATURE_COLUMNS]

    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(train_df["target"])
    y_test = label_encoder.transform(test_df["target"])

    X_train = train_df[feature_cols]
    X_test = test_df[feature_cols]

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    return {
        "df": df,
        "feature_cols": feature_cols,
        "train_df": train_df,
        "test_df": test_df,
        "X_train": X_train,
        "X_test": X_test,
        "X_train_scaled": X_train_scaled,
        "X_test_scaled": X_test_scaled,
        "y_train": y_train,
        "y_test": y_test,
        "label_encoder": label_encoder,
        "scaler": scaler,
        "domain_stats": domain_stats,
        "global_benign_rate": global_benign_rate,
    }


def build_full_training_features(df: pd.DataFrame):
    full_df = df.copy()
    domain_stats, global_benign_rate = compute_domain_stats(full_df)
    full_df = apply_domain_stats(full_df, domain_stats, global_benign_rate)

    feature_cols = [column for column in full_df.columns if column not in NON_FEATURE_COLUMNS]
    label_encoder = LabelEncoder()
    y_full = label_encoder.fit_transform(full_df["target"])
    X_full = full_df[feature_cols]

    scaler = StandardScaler()
    X_full_scaled = scaler.fit_transform(X_full)

    return {
        "full_df": full_df,
        "feature_cols": feature_cols,
        "X_full": X_full,
        "X_full_scaled": X_full_scaled,
        "y_full": y_full,
        "label_encoder": label_encoder,
        "scaler": scaler,
        "domain_stats": domain_stats,
        "global_benign_rate": global_benign_rate,
    }


def fit_lightgbm(X_train: pd.DataFrame, y_train):
    model = LGBMClassifier(
        n_estimators=260,
        learning_rate=0.035,
        num_leaves=47,
        subsample=0.85,
        colsample_bytree=0.7,
        min_child_samples=90,
        min_split_gain=0.05,
        reg_alpha=0.6,
        reg_lambda=2.5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    model.fit(X_train, y_train)
    return model


def fit_xgboost(X_train_scaled, y_train):
    positive_count = int((y_train == 1).sum())
    negative_count = int((y_train == 0).sum())
    scale_pos_weight = float(negative_count / positive_count) if positive_count else 1.0

    model = XGBClassifier(
        n_estimators=350,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.85,
        min_child_weight=3,
        reg_lambda=1.5,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
        scale_pos_weight=scale_pos_weight,
    )
    model.fit(X_train_scaled, y_train)
    return model


def save_artifacts(feature_cols, scaler, label_encoder, models, domain_stats, global_benign_rate) -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(feature_cols, os.path.join(MODELS_DIR, "feature_names.pkl"))
    joblib.dump(feature_cols, os.path.join(MODELS_DIR, "feature_names_xgb.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_xgb.pkl"))
    joblib.dump(label_encoder, os.path.join(MODELS_DIR, "label_encoder.pkl"))
    joblib.dump(
        {
            "registered_domain_stats": domain_stats,
            "global_benign_rate": global_benign_rate,
        },
        DOMAIN_STATS_PATH,
    )

    for name, model in models.items():
        joblib.dump(model, os.path.join(MODELS_DIR, f"{name}_model.pkl"))


def print_eval(name, model, X_test, y_test, label_encoder) -> None:
    y_pred = model.predict(X_test)
    report = classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        digits=4,
        zero_division=0,
    )
    print(f"\n{name.upper()} evaluation")
    print(report)


def main() -> None:
    ensure_processed_data()
    data = split_and_build_features()

    print(f"Processed rows: {len(data['df'])}")
    print(f"Feature count: {len(data['feature_cols'])}")
    print(f"Features: {data['feature_cols']}")
    print(f"Label classes: {list(data['label_encoder'].classes_)}")

    models = {
        "lgbm": fit_lightgbm(data["X_train"], data["y_train"]),
        "xgb": fit_xgboost(data["X_train_scaled"], data["y_train"]),
    }

    print_eval("lgbm", models["lgbm"], data["X_test"], data["y_test"], data["label_encoder"])
    print_eval("xgb", models["xgb"], data["X_test_scaled"], data["y_test"], data["label_encoder"])

    print("\nRefitting final deploy models on the full dataset...")
    full_data = build_full_training_features(data["df"])
    final_models = {
        "lgbm": fit_lightgbm(full_data["X_full"], full_data["y_full"]),
        "xgb": fit_xgboost(full_data["X_full_scaled"], full_data["y_full"]),
    }

    save_artifacts(
        full_data["feature_cols"],
        full_data["scaler"],
        full_data["label_encoder"],
        final_models,
        full_data["domain_stats"],
        full_data["global_benign_rate"],
    )
    print("\nSaved updated URL model artifacts to URL/models")


if __name__ == "__main__":
    main()
