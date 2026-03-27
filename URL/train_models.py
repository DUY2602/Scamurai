from __future__ import annotations

import os
from collections import Counter

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from utils.models import MappedKMeansClassifier
from utils.preprocess import process_and_save_csv


ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
MODELS_DIR = os.path.join(ROOT, "models")

RAW_DATA_PATH = os.path.join(DATA_DIR, "malicious_url.csv")
PROCESSED_DATA_PATH = os.path.join(DATA_DIR, "processed_malicious_url.csv")


def ensure_processed_data():
    print("Regenerating processed URL dataset...")
    process_and_save_csv(RAW_DATA_PATH, PROCESSED_DATA_PATH)


def build_feature_matrix():
    df = pd.read_csv(PROCESSED_DATA_PATH)
    feature_cols = [c for c in df.columns if c not in {"url", "target"}]

    X = df[feature_cols]
    y = df["target"].str.lower()

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return df, feature_cols, X, X_scaled, y_encoded, label_encoder, scaler


def fit_kmeans(X_train_scaled, y_train):
    sample_size = min(len(X_train_scaled), 120_000)
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X_train_scaled), size=sample_size, replace=False)

    kmeans = KMeans(n_clusters=2, n_init=10, random_state=42)
    kmeans.fit(X_train_scaled[idx])

    train_clusters = kmeans.predict(X_train_scaled)
    cluster_to_label = {}
    for cluster_id in range(kmeans.n_clusters):
        labels = y_train[train_clusters == cluster_id]
        cluster_to_label[cluster_id] = Counter(labels).most_common(1)[0][0]

    return MappedKMeansClassifier(kmeans, cluster_to_label)

def fit_lightgbm(X_train, y_train):
    model = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=63,
        subsample=0.9,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    model.fit(X_train, y_train)
    return model


def fit_xgboost(X_train, y_train):
    model = XGBClassifier(
        n_estimators=250,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)
    return model


def save_artifacts(feature_cols, scaler, label_encoder, models):
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(feature_cols, os.path.join(MODELS_DIR, "feature_names.pkl"))
    joblib.dump(feature_cols, os.path.join(MODELS_DIR, "feature_names_xgb.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_xgb.pkl"))
    joblib.dump(label_encoder, os.path.join(MODELS_DIR, "label_encoder.pkl"))

    for name, model in models.items():
        joblib.dump(model, os.path.join(MODELS_DIR, f"{name}_model.pkl"))


def print_eval(name, model, X_test, y_test, label_encoder):
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


def main():
    ensure_processed_data()
    df, feature_cols, X, X_scaled, y, label_encoder, scaler = build_feature_matrix()

    print(f"Processed rows: {len(df)}")
    print(f"Features: {feature_cols}")
    print(f"Label classes: {list(label_encoder.classes_)}")

    X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled = train_test_split(
        X,
        y,
        X_scaled,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )

    models = {
        "kmeans": fit_kmeans(X_train_scaled, y_train),
        "lgbm": fit_lightgbm(X_train, y_train),
        "xgb": fit_xgboost(X_train, y_train),
    }

    print_eval("kmeans", models["kmeans"], X_test_scaled, y_test, label_encoder)
    print_eval("lgbm", models["lgbm"], X_test, y_test, label_encoder)
    print_eval("xgb", models["xgb"], X_test, y_test, label_encoder)

    save_artifacts(feature_cols, scaler, label_encoder, models)
    print("\nSaved updated URL model artifacts to URL/models")


if __name__ == "__main__":
    main()
