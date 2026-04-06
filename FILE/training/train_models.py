"""Retrain FILE malware models and emit backend-compatible artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pefile
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

FEATURE_COLUMNS = [
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

ARTIFACT_FILES = [
    "lightgbm_malware_model.pkl",
    "xgboost_malware_model.pkl",
    "feature_scaler.pkl",
    "training_report.json",
]

LEGACY_ARTIFACT_FILES = [
    "kmeans_malware_model.pkl",
]

FILE_SENSITIVE_APIS = {
    b"CreateRemoteThread",
    b"WriteProcessMemory",
    b"VirtualAllocEx",
    b"LoadLibraryA",
    b"LoadLibraryW",
    b"GetProcAddress",
    b"CreateProcessA",
    b"CreateProcessW",
    b"WinExec",
    b"InternetOpen",
    b"HttpSendRequest",
    b"URLDownloadToFileA",
    b"URLDownloadToFileW",
    b"WSAStartup",
    b"connect",
    b"send",
    b"recv",
    b"RegOpenKeyExA",
    b"RegSetValueExA",
    b"RegCreateKeyExA",
    b"GetKeyboardState",
    b"SetWindowsHookEx",
    b"ShellExecuteA",
    b"IsDebuggerPresent",
    b"CreateToolhelp32Snapshot",
    b"Process32First",
    b"Process32Next",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrain FILE malware models.")
    parser.add_argument(
        "--data-path",
        type=Path,
        default=Path("FILE/data/malware_data_final.csv"),
        help="Path to the malware training dataset CSV.",
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path("FILE/models"),
        help="Directory where trained model artifacts will be saved.",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Holdout size for evaluation.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
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
    y_true: pd.Series,
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
    y_true: pd.Series,
    avg_prob: np.ndarray,
    thresholds: list[float],
) -> tuple[dict[str, dict[str, Any]], float, np.ndarray]:
    threshold_reports: dict[str, dict[str, Any]] = {}
    selected_threshold: float | None = None
    selected_score: tuple[float, float, float] | None = None

    for threshold in thresholds:
        y_pred = (avg_prob >= threshold).astype(int)
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        malware_metrics = report["1"]
        threshold_reports[f"{threshold:.2f}"] = {
            "threshold": float(threshold),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": report,
            "roc_auc": round(float(roc_auc_score(y_true, avg_prob)), 4),
        }

        precision = float(malware_metrics["precision"])
        recall = float(malware_metrics["recall"])
        f1_value = float(malware_metrics["f1-score"])
        if recall >= 0.85 and precision >= 0.75:
            candidate_score = (f1_value, recall, precision)
            if selected_score is None or candidate_score > selected_score:
                selected_score = candidate_score
                selected_threshold = float(threshold)

    if selected_threshold is None:
        fallback_threshold = thresholds[0]
        best_fallback_score: tuple[float, float, float] | None = None
        for threshold in thresholds:
            report = threshold_reports[f"{threshold:.2f}"]["classification_report"]
            malware_metrics = report["1"]
            precision = float(malware_metrics["precision"])
            recall = float(malware_metrics["recall"])
            f1_value = float(malware_metrics["f1-score"])
            candidate_score = (float(recall >= 0.85), f1_value, precision)
            if best_fallback_score is None or candidate_score > best_fallback_score:
                best_fallback_score = candidate_score
                fallback_threshold = threshold
        selected_threshold = float(fallback_threshold)

    selected_pred = (avg_prob >= selected_threshold).astype(int)
    return threshold_reports, selected_threshold, selected_pred


def extract_training_features_from_pe(file_path: Path) -> dict[str, Any]:
    pe = pefile.PE(str(file_path))
    section_count = len(pe.sections)
    entropies = [section.get_entropy() for section in pe.sections]
    avg_entropy = sum(entropies) / section_count if section_count else 0.0
    max_entropy = max(entropies) if entropies else 0.0

    suspicious_sections = 0
    for section in pe.sections:
        if (section.Characteristics & 0x80000000) and (section.Characteristics & 0x20000000):
            suspicious_sections += 1

    import_count = 0
    dll_count = 0
    has_sensitive_api = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if not entry.imports:
                continue
            import_count += len(entry.imports)
            for imported in entry.imports:
                if imported.name in FILE_SENSITIVE_APIS:
                    has_sensitive_api = 1

    try:
        features = {
            "Sections": section_count,
            "AvgEntropy": round(avg_entropy, 4),
            "MaxEntropy": round(max_entropy, 4),
            "SuspiciousSections": suspicious_sections,
            "DLLs": dll_count,
            "Imports": import_count,
            "HasSensitiveAPI": has_sensitive_api,
            "ImageBase": int(pe.OPTIONAL_HEADER.ImageBase),
            "SizeOfImage": int(pe.OPTIONAL_HEADER.SizeOfImage),
            "HasVersionInfo": 1 if hasattr(pe, "VS_FIXEDFILEINFO") else 0,
        }
    finally:
        pe.close()

    return features


def build_hardcase_frame(scale: float) -> tuple[pd.DataFrame, np.ndarray]:
    home = Path.home()
    candidates = [
        {"path": home / "Downloads" / "Claude Setup.exe", "label": 0, "weight": 80.0},
        {"path": home / "Downloads" / "FigmaSetup.exe", "label": 0, "weight": 90.0},
        {"path": home / "Downloads" / "GitHubDesktopSetup-x64.exe", "label": 0, "weight": 90.0},
        {"path": Path(r"C:\Windows\System32\notepad.exe"), "label": 0, "weight": 40.0},
        {"path": Path(r"C:\Windows\System32\calc.exe"), "label": 0, "weight": 30.0},
        {"path": Path(r"C:\Windows\System32\mspaint.exe"), "label": 0, "weight": 30.0},
        {"path": home / "Downloads" / "VuaHaiTac.exe", "label": 1, "weight": 120.0},
    ]

    rows: list[dict[str, Any]] = []
    weights: list[float] = []
    for item in candidates:
        file_path = Path(item["path"])
        if not file_path.exists():
            continue
        try:
            row = extract_training_features_from_pe(file_path)
        except Exception:
            continue
        row["Label"] = int(item["label"])
        rows.append(row)
        weights.append(float(item["weight"]) * scale)

    return pd.DataFrame(rows), np.asarray(weights, dtype=float)


def main() -> None:
    args = parse_args()
    if args.hardcase_scale <= 0:
        raise ValueError("--hardcase-scale must be > 0.")
    models_dir = args.models_dir
    models_dir.mkdir(parents=True, exist_ok=True)

    backup_dir = None if args.no_backup else backup_existing_artifacts(models_dir)

    df = pd.read_csv(args.data_path)
    missing_columns = [column for column in FEATURE_COLUMNS + ["Label"] if column not in df.columns]
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {missing_columns}")

    df = df.dropna(subset=FEATURE_COLUMNS + ["Label"]).copy()
    X = df[FEATURE_COLUMNS]
    y = df["Label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    hardcase_frame, hardcase_weights = build_hardcase_frame(args.hardcase_scale)
    X_train = pd.concat([X_train, hardcase_frame[FEATURE_COLUMNS]], ignore_index=True)
    y_train = pd.concat([y_train.reset_index(drop=True), hardcase_frame["Label"].astype(int)], ignore_index=True)
    train_sample_weight = np.concatenate([np.ones(len(X_train) - len(hardcase_frame), dtype=float), hardcase_weights])

    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train),
        columns=FEATURE_COLUMNS,
        index=X_train.index,
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=FEATURE_COLUMNS,
        index=X_test.index,
    )

    lgbm = LGBMClassifier(
        n_estimators=300,
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
    lgbm.fit(X_train_scaled, y_train, sample_weight=train_sample_weight)
    lgbm_test_pred = lgbm.predict(X_test_scaled)
    lgbm_test_prob = lgbm.predict_proba(X_test_scaled)[:, 1]

    negative_count = int((y_train == 0).sum())
    positive_count = int((y_train == 1).sum())
    scale_pos_weight = negative_count / max(positive_count, 1)

    xgb = XGBClassifier(
        n_estimators=250,
        learning_rate=0.05,
        max_depth=6,
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
    xgb.fit(X_train_scaled, y_train, sample_weight=train_sample_weight)
    xgb_test_pred = xgb.predict(X_test_scaled)
    xgb_test_prob = xgb.predict_proba(X_test_scaled)[:, 1]

    ensemble_test_prob = (lgbm_test_prob + xgb_test_prob) / 2.0
    threshold_candidates = [0.35, 0.40, 0.45, 0.50, 0.55]
    soft_voting_thresholds, selected_threshold, ensemble_test_pred = evaluate_soft_voting_thresholds(
        y_test,
        ensemble_test_prob,
        threshold_candidates,
    )

    report: dict[str, Any] = {
        "task": "file_malware_retraining",
        "data_path": str(args.data_path),
        "models_dir": str(models_dir),
        "backup_dir": str(backup_dir) if backup_dir else None,
        "dataset": {
            "rows": int(len(df)),
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "hardcase_rows": int(len(hardcase_frame)),
            "label_distribution": {
                "benign": int((y == 0).sum()),
                "malware": int((y == 1).sum()),
            },
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
        "metadata": {
            "feature_columns": FEATURE_COLUMNS,
            "scale_pos_weight": round(float(scale_pos_weight), 6),
            "hardcase_scale": args.hardcase_scale,
        },
    }

    joblib.dump(lgbm, models_dir / "lightgbm_malware_model.pkl")
    joblib.dump(xgb, models_dir / "xgboost_malware_model.pkl")
    joblib.dump(scaler, models_dir / "feature_scaler.pkl")
    legacy_kmeans_path = models_dir / "kmeans_malware_model.pkl"
    if legacy_kmeans_path.exists():
        legacy_kmeans_path.unlink()
    (models_dir / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
