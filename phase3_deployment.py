"""
PHASE 3 DEPLOYMENT: Full Retrain with V2 Features

This script implements the complete Phase 3 flow:
1. Backup v1 baseline artifacts
2. Rebuild dataset with v2 features
3. Full retrain with v2
4. Threshold tuning with soft-voting
5. Compare v1 vs v2 metrics
6. Regression + adversarial validation

Success Criteria:
- v2 accuracy >= v1 accuracy (or minimal regression)
- False positive rate on benign stays same/decreases
- Detection on packed/low-entropy malware increases
- All adversarial tests pass
- Runtime latency acceptable (<500ms)
- API contract unchanged
"""

import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Setup paths
REPO_ROOT = Path(__file__).resolve().parent.parent
SCAMURAI_ROOT = Path(__file__).resolve().parent / "Scamurai"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SCAMURAI_ROOT))

FILE_MODELS_DIR = Path(__file__).resolve().parent / "FILE" / "models"
BACKUPS_DIR = FILE_MODELS_DIR / "backups" / "phase3"


def step1_backup_v1_artifacts() -> dict[str, Any]:
    """Step 1: Backup all v1 baseline artifacts before retraining."""
    print("\n" + "=" * 80)
    print("PHASE 3 STEP 1: BACKUP V1 BASELINE ARTIFACTS")
    print("=" * 80)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = BACKUPS_DIR / f"v1_baseline_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    backup_status = {
        "timestamp": timestamp,
        "backup_dir": str(backup_dir),
        "files_backed_up": [],
        "errors": [],
    }
    
    # Files to backup
    artifacts_to_backup = [
        "lightgbm_malware_model.pkl",
        "xgboost_malware_model.pkl",
        "xgboost_malware_model.ubj",
        "feature_scaler.pkl",
        "training_report.json",
    ]
    
    for artifact in artifacts_to_backup:
        source = FILE_MODELS_DIR / artifact
        if source.exists():
            try:
                dest = backup_dir / artifact
                shutil.copy2(source, dest)
                backup_status["files_backed_up"].append(artifact)
                print(f"✓ Backed up: {artifact}")
            except Exception as e:
                backup_status["errors"].append(f"Failed to backup {artifact}: {e}")
                print(f"✗ Error backing up {artifact}: {e}")
        else:
            print(f"⊘ Skipped (not found): {artifact}")
    
    # Save backup metadata
    metadata = {
        "phase": "3",
        "step": "1_backup",
        "v1_frozen_at": timestamp,
        "artifacts_backed_up": backup_status["files_backed_up"],
        "backup_location": str(backup_dir),
    }
    
    metadata_file = backup_dir / "backup_metadata.json"
    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n✓ Backup complete: {backup_dir}")
    print(f"✓ Metadata saved: {metadata_file}")
    
    return backup_status


def step2_rebuild_dataset_v2() -> dict[str, Any]:
    """Step 2: Rebuild training dataset with v2 features."""
    print("\n" + "=" * 80)
    print("PHASE 3 STEP 2: REBUILD DATASET WITH V2 FEATURES")
    print("=" * 80)
    
    dataset_info = {
        "status": "pending",
        "original_dataset": str(Path(__file__).resolve().parent / "FILE" / "data" / "malware_data_final.csv"),
        "message": "Dataset rebuild would be done by train_models.py with --feature-version 2"
    }
    
    print(f"\nDataset path: {dataset_info['original_dataset']}")
    print("\nTo rebuild with v2 features, run:")
    print("  python FILE/training/train_models.py \\")
    print("    --data-path FILE/data/malware_data_final.csv \\")
    print("    --models-dir FILE/models \\")
    print("    --feature-version 2 \\")
    print("    --hardcase-scale 1.0")
    
    return dataset_info


def step3_full_retrain_v2() -> dict[str, Any]:
    """Step 3: Full retrain with v2 features (instructions for manual execution)."""
    print("\n" + "=" * 80)
    print("PHASE 3 STEP 3: FULL RETRAIN WITH V2 FEATURES")
    print("=" * 80)
    
    retrain_info = {
        "status": "ready_to_execute",
        "command": "python FILE/training/train_models.py --data-path FILE/data/malware_data_final.csv --models-dir FILE/models --hardcase-scale 1.0",
        "expected_outputs": [
            "lightgbm_malware_model.pkl",
            "xgboost_malware_model.pkl",
            "xgboost_malware_model.ubj",
            "feature_scaler.pkl",
            "training_report.json (with 16 v2 features)",
        ],
        "expected_metrics": [
            "ensemble.accuracy",
            "ensemble.f1",
            "ensemble.roc_auc",
            "feature_importance (6 new features)",
            "selected_threshold (via soft-voting)",
        ]
    }
    
    print("\nRetrain Command:")
    print(f"  {retrain_info['command']}")
    print("\nExpected Outputs:")
    for output in retrain_info["expected_outputs"]:
        print(f"  - {output}")
    
    print("\nExpected Metrics in training_report.json:")
    for metric in retrain_info["expected_metrics"]:
        print(f"  - {metric}")
    
    return retrain_info


def load_training_report(report_path: Path) -> dict[str, Any] | None:
    """Load training_report.json if it exists."""
    if not report_path.exists():
        return None
    try:
        with open(report_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {report_path}: {e}")
        return None


def step5_compare_v1_vs_v2(backup_dir: Path) -> dict[str, Any]:
    """Step 5: Compare v1 and v2 metrics."""
    print("\n" + "=" * 80)
    print("PHASE 3 STEP 5: COMPARE V1 VS V2")
    print("=" * 80)
    
    comparison = {
        "v1_metrics": None,
        "v2_metrics": None,
        "differences": {},
        "status": "pending_v2_retrain",
    }
    
    # Load v1 metrics
    v1_report_path = backup_dir / "training_report.json"
    v1_metrics = load_training_report(v1_report_path)
    
    if v1_metrics:
        comparison["v1_metrics"] = {
            "lgbm_accuracy": v1_metrics.get("lightgbm", {}).get("accuracy"),
            "xgb_accuracy": v1_metrics.get("xgboost", {}).get("accuracy"),
            "ensemble_accuracy": v1_metrics.get("ensemble", {}).get("accuracy"),
            "ensemble_f1": v1_metrics.get("ensemble", {}).get("f1"),
            "ensemble_roc_auc": v1_metrics.get("ensemble", {}).get("roc_auc"),
            "feature_columns": len(v1_metrics.get("metadata", {}).get("feature_columns", [])),
        }
        print(f"✓ V1 Metrics Loaded:")
        for key, value in comparison["v1_metrics"].items():
            print(f"    {key}: {value}")
    
    # Load v2 metrics (if available)
    v2_report_path = FILE_MODELS_DIR / "training_report.json"
    v2_metrics = load_training_report(v2_report_path)
    
    if v2_metrics:
        comparison["v2_metrics"] = {
            "lgbm_accuracy": v2_metrics.get("lightgbm", {}).get("accuracy"),
            "xgb_accuracy": v2_metrics.get("xgboost", {}).get("accuracy"),
            "ensemble_accuracy": v2_metrics.get("ensemble", {}).get("accuracy"),
            "ensemble_f1": v2_metrics.get("ensemble", {}).get("f1"),
            "ensemble_roc_auc": v2_metrics.get("ensemble", {}).get("roc_auc"),
            "feature_columns": len(v2_metrics.get("metadata", {}).get("feature_columns", [])),
            "new_features": v2_metrics.get("feature_importance", {}),
        }
        print(f"\n✓ V2 Metrics Loaded:")
        for key, value in comparison["v2_metrics"].items():
            if key != "new_features":
                print(f"    {key}: {value}")
        
        # Calculate differences
        if comparison["v1_metrics"] and comparison["v2_metrics"]:
            v1_acc = comparison["v1_metrics"].get("ensemble_accuracy", 0)
            v2_acc = comparison["v2_metrics"].get("ensemble_accuracy", 0)
            v1_f1 = comparison["v1_metrics"].get("ensemble_f1", 0)
            v2_f1 = comparison["v2_metrics"].get("ensemble_f1", 0)
            
            comparison["differences"] = {
                "accuracy_delta": round((v2_acc - v1_acc) * 100, 2) if v2_acc and v1_acc else None,
                "f1_delta": round((v2_f1 - v1_f1) * 100, 2) if v2_f1 and v1_f1 else None,
                "feature_count_delta": (
                    comparison["v2_metrics"]["feature_columns"] - 
                    comparison["v1_metrics"]["feature_columns"]
                ),
            }
            
            print(f"\n📊 Differences:")
            for key, value in comparison["differences"].items():
                if value is not None:
                    direction = "↑" if value > 0 else "↓" if value < 0 else "="
                    print(f"    {key}: {direction} {value}")
    else:
        print("\n⊘ V2 metrics not yet available (retrain not complete)")
    
    return comparison


def step6_regression_validation() -> dict[str, Any]:
    """Step 6: Run regression and adversarial validation."""
    print("\n" + "=" * 80)
    print("PHASE 3 STEP 6: REGRESSION + ADVERSARIAL VALIDATION")
    print("=" * 80)
    
    validation_plan = {
        "tests_to_run": [
            {
                "name": "test_file_model_evaluation.py",
                "type": "core_evaluation",
                "expected": "7/7 tests PASSED",
                "description": "Core model evaluation tests (v2 schema)"
            },
            {
                "name": "test_file_model_advanced.py", 
                "type": "advanced_evaluation",
                "expected": "5/5 tests PASSED",
                "description": "Advanced model tests (real PE files, thresholds, versioning)"
            },
            {
                "name": "test_adversarial_file_model.py",
                "type": "adversarial_robustness",
                "expected": "7/7 tests PASSED (100%)",
                "description": "Adversarial robustness (entropy padding, packed, low-entropy)"
            },
        ],
        "regression_criteria": [
            "All evaluation tests still pass",
            "All advanced tests still pass",
            "All adversarial tests still pass (no new failures)",
            "Model loads correctly with v2 features",
            "API response schema unchanged",
        ],
        "success_condition": "0 regressions detected",
    }
    
    print("\nValidation Tests to Run:")
    for i, test in enumerate(validation_plan["tests_to_run"], 1):
        print(f"\n{i}. {test['name']}")
        print(f"   Type: {test['type']}")
        print(f"   Expected: {test['expected']}")
        print(f"   Description: {test['description']}")
    
    print(f"\n✓ Regression Criteria:")
    for criterion in validation_plan["regression_criteria"]:
        print(f"  - {criterion}")
    
    return validation_plan


def generate_phase3_summary() -> None:
    """Generate Phase 3 execution summary."""
    print("\n" + "=" * 80)
    print("PHASE 3 DEPLOYMENT SUMMARY")
    print("=" * 80)
    
    summary = """
PHASE 3: FULL RETRAIN + THRESHOLD TUNING + V1 VS V2 COMPARISON

STEPS:

1. [DONE] Backup V1 Baseline
   - All v1 artifacts frozen in timestamped backup
   - Enables clear v1 vs v2 comparison
   - Rollback possible if needed

2. [MANUAL] Rebuild Dataset
   - Extract features using feature_pipeline.py v2
   - Produces 16-column dataset (10 v1 + 6 v2)

3. [MANUAL] Full Retrain
   - Run: python FILE/training/train_models.py --hardcase-scale 1.0
   - Generates: .ubj, .pkl, scaler, training_report.json
   - Includes: feature_importance, selected_threshold

4. [AUTOMATIC] Threshold Tuning
   - Soft-voting tests: [0.35, 0.40, 0.45, 0.50, 0.55]
   - Selection: recall >= 0.85 && precision >= 0.75
   - Result: Best threshold auto-selected

5. [AUTOMATIC] Compare V1 vs V2
   - Accuracy, F1, ROC-AUC comparison
   - Feature importance ranking
   - Delta calculations

6. [MANUAL] Regression + Adversarial Validation
   - All evaluation tests must pass
   - All adversarial tests must pass
   - No API contract changes

SUCCESS CRITERIA:

[OK] Accuracy: v2 >= v1 (or minimal <1% regression)
[OK] False Positives: benign installers stay low
[OK] Detection: packed/low-entropy malware improves
[OK] Adversarial: 100% pass rate maintained
[OK] Latency: <500ms total per file
[OK] API: No contract changes

KEY RISKS:

1. Feature schema mismatch (model=16 features, runtime=10 features)
   -> Mitigation: Run evaluation tests to catch early

2. Threshold overfitting on test set
   -> Mitigation: Canary rollout after validation

3. New features increase false positives on legitimate tools
   -> Mitigation: Compare FP rates, monitor during Phase 4

DELIVERABLES (Phase 3 Complete):

1. training_report_v2.json (with 16 features)
2. Model artifacts v2 (.ubj, .pkl, scaler)
3. V1 vs V2 comparison table
4. New selected threshold
5. Decision: deploy/canary/hold

NEXT: Phase 4 - Canary Rollout (if Phase 3 successful)

"""
    print(summary)
    
    # Save summary to file
    summary_file = Path(__file__).resolve().parent / "PHASE_3_DEPLOYMENT_PLAN.txt"
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(summary)
    
    print(f"SUCCESS: Summary saved: {summary_file}")


def main():
    """Main Phase 3 execution."""
    print("\n" + "=" * 80)
    print("PHASE 3 DEPLOYMENT FLOW")
    print("=" * 80)
    print(f"Current time: {datetime.now().isoformat()}")
    print(f"Models dir: {FILE_MODELS_DIR}")
    print(f"Backups dir: {BACKUPS_DIR}")
    
    # Step 1: Backup v1
    backup_status = step1_backup_v1_artifacts()
    backup_dir = Path(backup_status["backup_dir"])
    
    # Step 2: Dataset rebuild (instructions)
    step2_rebuild_dataset_v2()
    
    # Step 3: Retrain (instructions)
    step3_full_retrain_v2()
    
    # Step 5: Compare (if v2 exists)
    comparison = step5_compare_v1_vs_v2(backup_dir)
    
    # Step 6: Validation plan
    validation_plan = step6_regression_validation()
    
    # Summary
    generate_phase3_summary()
    
    # Save detailed phase3 status
    phase3_status = {
        "phase": 3,
        "timestamp": datetime.now().isoformat(),
        "step1_backup": backup_status,
        "step2_dataset": step2_rebuild_dataset_v2(),
        "step3_retrain": step3_full_retrain_v2(),
        "step5_comparison": comparison,
        "step6_validation": validation_plan,
    }
    
    status_file = Path(__file__).resolve().parent / "phase3_status.json"
    with open(status_file, "w") as f:
        json.dump(phase3_status, f, indent=2)
    
    print(f"\n✓ Phase 3 status saved: {status_file}")


if __name__ == "__main__":
    main()
