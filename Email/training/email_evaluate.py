"""
Email Model Evaluation Script
==============================
Evaluates the production email model (best_model.pkl) against the held-out
test split, generates a comprehensive JSON report, and prints a human-readable
summary to stdout.

Usage:
    python Email/training/email_evaluate.py
    python Email/training/email_evaluate.py --threshold 0.35
    python Email/training/email_evaluate.py --output Email/models/eval_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

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

from Email.pipeline import NUMERIC_FEATURES, build_feature_frame, build_training_record

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT_DIR / "models"
DATA_DIR = ROOT_DIR / "data"

BEST_MODEL_PATH = MODELS_DIR / "best_model.pkl"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
META_PATH = MODELS_DIR / "best_model_metadata.json"
TEST_CSV = DATA_DIR / "email_test.csv"
DEFAULT_REPORT_PATH = MODELS_DIR / "email_eval_report.json"

# ---------------------------------------------------------------------------
# Hard-coded inference examples for sanity checks
# ---------------------------------------------------------------------------
SANITY_CASES = [
    {
        "subject": "Team sync tomorrow at 10am",
        "body": "Hi everyone, let's meet tomorrow at 10am for the weekly sync.",
        "sender": "boss@company.com",
        "expected": "ham",
    },
    {
        "subject": "Your package has shipped",
        "body": "Your order #12345 has been dispatched and will arrive Thursday.",
        "sender": "noreply@fedex.com",
        "expected": "ham",
    },
    {
        "subject": "Invoice for last month",
        "body": "Please find attached the invoice for services rendered in March.",
        "sender": "billing@vendor.com",
        "expected": "ham",
    },
    {
        "subject": "CONGRATULATIONS!! You have WON $1,000,000",
        "body": "Dear winner! Click here NOW to claim your prize. Limited time offer!!!",
        "sender": "promo@free-winner.xyz",
        "expected": "spam",
    },
    {
        "subject": "Cheap Viagra -- special offer just for you",
        "body": "Buy now and get 80% off. Click the link below. Act fast!",
        "sender": "deals@pillshop.biz",
        "expected": "spam",
    },
    {
        "subject": "Make $5000 a day working from home!!!",
        "body": "This amazing opportunity will change your life. Join thousands who already earn.",
        "sender": "rich@getmoney.net",
        "expected": "spam",
    },
    {
        "subject": "Your bank account has been suspended",
        "body": "Please verify your account immediately by clicking here: http://phishing-site.xyz/login",
        "sender": "security@paypa1-support.com",
        "expected": "spam",
    },
    {
        "subject": "Lunch tomorrow?",
        "body": "Hey, are you free for lunch tomorrow? I was thinking of trying that new place.",
        "sender": "friend@gmail.com",
        "expected": "ham",
    },
]

THRESHOLD_SWEEP = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_metadata() -> dict[str, Any]:
    if META_PATH.is_file():
        return json.loads(META_PATH.read_text(encoding="utf-8"))
    return {}


def _load_artifacts():
    model = joblib.load(BEST_MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    scaler = joblib.load(SCALER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    return model, vectorizer, scaler, label_encoder


def _transform(feature_frame: pd.DataFrame, vectorizer, scaler):
    tfidf = vectorizer.transform(feature_frame["full_clean_text"])
    numeric = scaler.transform(feature_frame[NUMERIC_FEATURES])
    return hstack([tfidf, csr_matrix(numeric)]).tocsr()


def _safe_predict_proba(model, X) -> np.ndarray:
    """Predict probabilities, falling back to dense array if sparse causes issues."""
    if hasattr(model, "predict_proba"):
        try:
            return model.predict_proba(X)[:, 1]
        except Exception:
            return model.predict_proba(X.toarray())[:, 1]
    # decision_function fallback (e.g. LinearSVC)
    try:
        scores = np.ravel(model.decision_function(X))
    except Exception:
        scores = np.ravel(model.decision_function(X.toarray()))
    return 1.0 / (1.0 + np.exp(-scores))


def _predict_proba_single(subject: str, body: str, sender: str, model, vectorizer, scaler) -> float:
    ff = build_feature_frame(subject, body, sender=sender)
    X = _transform(ff, vectorizer, scaler)
    return float(_safe_predict_proba(model, X)[0])


def _load_test_dataframe() -> pd.DataFrame:
    if not TEST_CSV.is_file():
        raise FileNotFoundError(f"Test CSV not found: {TEST_CSV}")
    df = pd.read_csv(TEST_CSV)
    if not {"subject", "body", "label"}.issubset(df.columns):
        rows = []
        for row in df.to_dict(orient="records"):
            record = build_training_record(pd.Series(row))
            label_col = "label" if "label" in row else "target"
            raw_label = str(row.get(label_col, "ham")).strip().lower()
            label = "spam" if raw_label in ["1", "spam", "true", "malicious"] else "ham"
            rows.append({
                "subject": record["subject"],
                "body": record["body"],
                "sender": record["sender"],
                "label": label,
            })
        df = pd.DataFrame(rows)
    df["label"] = df["label"].str.strip().str.lower()
    df = df[df["label"].isin(["ham", "spam"])].reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Evaluation routines
# ---------------------------------------------------------------------------

def evaluate_test_split(model, vectorizer, scaler, label_encoder, threshold: float) -> dict[str, Any]:
    print(f"\nLoading test split: {TEST_CSV}")
    df = _load_test_dataframe()
    print(f"  Rows: {len(df):,}   ham: {(df['label']=='ham').sum():,}   spam: {(df['label']=='spam').sum():,}")

    print("  Featurizing and scoring...")
    feature_rows = [
        build_feature_frame(r.subject, r.body, sender=getattr(r, "sender", ""))
        for r in df.itertuples(index=False)
    ]
    full_ff = pd.concat(feature_rows, ignore_index=True)
    X = _transform(full_ff, vectorizer, scaler)
    y_true = label_encoder.transform(df["label"])
    y_proba = _safe_predict_proba(model, X)
    y_pred = (y_proba >= threshold).astype(int)

    report = classification_report(
        y_true, y_pred,
        target_names=label_encoder.classes_,
        digits=4, output_dict=True, zero_division=0,
    )
    cm = confusion_matrix(y_true, y_pred)
    roc_auc = float(roc_auc_score(y_true, y_proba))
    tn, fp, fn, tp = cm.ravel()

    return {
        "threshold": threshold,
        "total_samples": len(df),
        "ham_samples": int((df["label"] == "ham").sum()),
        "spam_samples": int((df["label"] == "spam").sum()),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "roc_auc": roc_auc,
        "precision_spam": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_spam": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_spam": float(f1_score(y_true, y_pred, zero_division=0)),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }


def sweep_thresholds(model, vectorizer, scaler, label_encoder) -> list[dict[str, Any]]:
    print("\nRunning threshold sweep...")
    df = _load_test_dataframe()
    feature_rows = [
        build_feature_frame(r.subject, r.body, sender=getattr(r, "sender", ""))
        for r in df.itertuples(index=False)
    ]
    full_ff = pd.concat(feature_rows, ignore_index=True)
    X = _transform(full_ff, vectorizer, scaler)
    y_true = label_encoder.transform(df["label"])
    y_proba = _safe_predict_proba(model, X)
    roc_auc = float(roc_auc_score(y_true, y_proba))

    rows = []
    for t in THRESHOLD_SWEEP:
        y_pred = (y_proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        rows.append({
            "threshold": t,
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision_spam": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall_spam": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_spam": float(f1_score(y_true, y_pred, zero_division=0)),
            "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
            "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
            "roc_auc": roc_auc,
        })
    return rows


def run_sanity_checks(model, vectorizer, scaler, label_encoder, threshold: float) -> list[dict[str, Any]]:
    print("\nRunning sanity checks...")
    results = []
    for case in SANITY_CASES:
        prob = _predict_proba_single(
            case["subject"], case["body"], case["sender"],
            model, vectorizer, scaler,
        )
        pred_idx = 1 if prob >= threshold else 0
        predicted = str(label_encoder.inverse_transform([pred_idx])[0])
        correct = predicted == case["expected"]
        status = "PASS" if correct else "FAIL"
        print(f"  [{status}] '{case['subject'][:50]}' -> {predicted.upper()} "
              f"(prob={prob:.4f}, expected={case['expected'].upper()})")
        results.append({
            "subject": case["subject"],
            "expected": case["expected"],
            "predicted": predicted,
            "spam_probability": prob,
            "correct": correct,
        })
    passed = sum(r["correct"] for r in results)
    print(f"\n  Sanity result: {passed}/{len(results)} passed")
    return results


# ---------------------------------------------------------------------------
# Pretty print
# ---------------------------------------------------------------------------

def print_summary(metrics: dict[str, Any], sweep: list[dict[str, Any]], meta: dict[str, Any]) -> None:
    sep = "=" * 70
    print(f"\n{sep}")
    print("  EMAIL MODEL -- EVALUATION REPORT")
    print(sep)
    print(f"  Model type   : {meta.get('selected_model', 'unknown').upper()}")
    print(f"  Threshold    : {metrics['threshold']:.2f}")
    print(f"  Test samples : {metrics['total_samples']:,}  "
          f"(ham={metrics['ham_samples']:,}  spam={metrics['spam_samples']:,})")
    print(sep)
    print(f"  Accuracy              : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)")
    print(f"  ROC-AUC               : {metrics['roc_auc']:.4f}")
    print(f"  Macro F1              : {metrics['macro_f1']:.4f}")
    print(f"  Spam Precision        : {metrics['precision_spam']:.4f}")
    print(f"  Spam Recall           : {metrics['recall_spam']:.4f}")
    print(f"  Spam F1               : {metrics['f1_spam']:.4f}")
    print(f"  False Positive Rate   : {metrics['false_positive_rate']:.4f}  "
          f"({metrics['false_positive_rate']*100:.2f}% ham flagged as spam)")
    print(f"  False Negative Rate   : {metrics['false_negative_rate']:.4f}  "
          f"({metrics['false_negative_rate']*100:.2f}% spam missed)")
    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted Ham   Predicted Spam")
    print(f"  Actual Ham        {metrics['true_negatives']:>12,}   {metrics['false_positives']:>14,}")
    print(f"  Actual Spam       {metrics['false_negatives']:>12,}   {metrics['true_positives']:>14,}")
    print(f"\n{sep}")
    print("  THRESHOLD SWEEP SUMMARY")
    print(sep)
    print(f"  {'Thresh':>6}  {'Accuracy':>8}  {'Prec':>6}  {'Recall':>6}  "
          f"{'F1':>6}  {'MacroF1':>7}  {'FPR':>6}  {'FNR':>6}")
    print(f"  {'-'*6}  {'-'*8}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*7}  {'-'*6}  {'-'*6}")
    for row in sweep:
        marker = " <-- selected" if abs(row["threshold"] - metrics["threshold"]) < 0.001 else ""
        print(f"  {row['threshold']:>6.2f}  "
              f"{row['accuracy']:>8.4f}  "
              f"{row['precision_spam']:>6.4f}  "
              f"{row['recall_spam']:>6.4f}  "
              f"{row['f1_spam']:>6.4f}  "
              f"{row['macro_f1']:>7.4f}  "
              f"{row['false_positive_rate']:>6.4f}  "
              f"{row['false_negative_rate']:>6.4f}{marker}")
    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the production Email spam model.")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Decision threshold (default: value from best_model_metadata.json).")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH,
                        help=f"Path to write JSON report. Default: {DEFAULT_REPORT_PATH}")
    parser.add_argument("--no-sanity", action="store_true",
                        help="Skip sanity-check inference cases.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    meta = _load_metadata()
    threshold = args.threshold if args.threshold is not None else float(meta.get("selected_threshold", 0.5))

    print(f"\nLoading artifacts from: {MODELS_DIR}")
    model, vectorizer, scaler, label_encoder = _load_artifacts()
    model_name = meta.get("selected_model", type(model).__name__)
    print(f"  Model : {model_name.upper()}  |  Threshold : {threshold:.2f}")

    # Core test-set metrics
    metrics = evaluate_test_split(model, vectorizer, scaler, label_encoder, threshold)

    # Threshold sweep (reuses same test set — fast)
    sweep = sweep_thresholds(model, vectorizer, scaler, label_encoder)

    # Sanity checks on hard-coded examples
    sanity = [] if args.no_sanity else run_sanity_checks(model, vectorizer, scaler, label_encoder, threshold)

    # Print human-readable summary
    print_summary(metrics, sweep, meta)

    # Write JSON report
    report = {
        "model": model_name,
        "threshold": threshold,
        "metadata": meta,
        "test_metrics": metrics,
        "threshold_sweep": sweep,
        "sanity_checks": sanity,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n  JSON report saved -> {args.output.resolve()}")
    print("=" * 70)


if __name__ == "__main__":
    main()
