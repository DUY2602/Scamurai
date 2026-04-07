# FILE Model Enhancement Roadmap

**Date**: 2026-04-07  
**Status**: PLANNING  
**Priority**: HIGH (Production quality improvements)

---

## Overview

5-step enhancement to improve FILE model production readiness:

1. Model format modernization (.ubj for XGBoost)
2. Feature importance explainability
3. Feature set expansion
4. Adversarial robustness testing
5. Retrain + threshold tuning

---

## Step 1: XGBoost Format Upgrade (.ubj with .pkl fallback)

### Goal

Migrate XGBoost from pickle (.pkl) to universal binary format (.ubj) for:

- Better compatibility
- Smaller file size
- Version independence
- Keep .pkl as fallback during transition

### Files to Modify

- `FILE/training/train_models.py` - Save as .ubj
- `FILE/models/` - Add .ubj format support
- `backend/services/file_service.py` - Load .ubj with .pkl fallback

### Implementation

```python
# In train_models.py
xgb_model.save_model(models_dir / "xgboost_malware_model.ubj")
xgb_model.save_model(models_dir / "xgboost_malware_model.pkl")  # Fallback

# In file_service.py
try:
    xgb = xgb.Booster(model_file=MODEL_DIR / "xgboost_malware_model.ubj")
except:
    xgb = joblib.load(MODEL_DIR / "xgboost_malware_model.pkl")
```

### Benefits

✓ Modern format
✓ No backward compatibility breaks
✓ Gradual migration path

---

## Step 2: Feature Importance & SHAP Values

### Goal

Export feature importance/SHAP into modeling metadata for transparency

### What to Extract

```python
{
  "feature_importance": {
    "lgbm": {
      "Entropy": 0.23,
      "DLLs": 0.19,
      "Imports": 0.18,
      ...
    },
    "xgboost": {
      "AvgEntropy": 0.25,
      "SuspiciousSections": 0.20,
      ...
    },
    "ensemble_avg": {
      "Entropy": 0.24,
      "Imports": 0.19,
      ...
    }
  },
  "shap_samples": [
    {
      "filename": "calc.exe",
      "prediction": 0.05,
      "shap_values": {...}
    },
    ...
  ]
}
```

### Files to Modify

- `FILE/training/train_models.py` - Compute and save
- `backend/config/model_metadata_registry.py` - Load and expose

### Implementation

```python
# In train_models.py
import shap

feature_importance = {
    "lgbm": dict(zip(FEATURE_COLUMNS, lgbm.feature_importances_)),
    "xgboost": dict(zip(FEATURE_COLUMNS, xgb.feature_importances_)),
}

report["feature_importance"] = feature_importance
report["training_report.json"]  # Save

# In metadata_registry.py
metadata.feature_importance = report.get("feature_importance", {})
```

### Benefits

✓ Model interpretability
✓ No more guessing which features matter
✓ Better debugging of misclassifications

---

## Step 3: Expand Feature Set

### Current Features (10)

```
Sections, AvgEntropy, MaxEntropy, SuspiciousSections,
DLLs, Imports, HasSensitiveAPI, ImageBase, SizeOfImage, HasVersionInfo
```

### New Features to Add

1. **is_packed** (binary)
   - Detected entropy > 7.5 or packing indicators
   - Strong signal for potential malware

2. **import_category_score** (0-1)
   - Categorize imports: suspicious (network, file I/O), benign (display), etc.
   - Score = % suspicious APIs

3. **has_tls** (binary)
   - TLS/section encryption presence
   - Malware often use encryption

4. **api_category_distribution** (categorical)
   - Groups of APIs: networking, process, registry, file
   - Better than just HasSensitiveAPI

5. **export_table_size** (numeric)
   - Number of exports (usually 0 for regular files)
   - Malware often exports functions

6. **resource_entropy** (0-8)
   - Entropy of .rsrc section
   - High = compressed/encrypted resources

### Implementation Location

```python
# FILE/training/train_models.py
# After extract_training_features_from_pe()

def compute_new_features(pe):
    return {
        "is_packed": detect_packing(pe),
        "import_category_score": categorize_imports(pe),
        "has_tls": has_tls_section(pe),
        "api_category_dist": get_api_categories(pe),
        "export_table_size": get_export_count(pe),
        "resource_entropy": get_resource_entropy(pe),
    }
```

### Benefits

✓ Better feature coverage
✓ Detect packed/obfuscated malware
✓ More discriminative signals

---

## Step 4: Adversarial Test Dataset

### Test Cases

#### Type A: Entropy Padding (False Positives Risk)

```python
# Benign file + random padding to increase entropy
original_entropy = 5.2  # Normal file
padded_entropy = 7.8    # Looks like packed malware
```

#### Type B: Packed Benign Installers

```python
# Real legitimate installers (7-Zip, Inno Setup, etc.)
# with high entropy but completely benign
```

#### Type C: Malware with Low Entropy

```python
# Malware that mimics benign profiles
# Deliberate deception patterns
```

### Dataset Structure

```
FILE/data/adversarial_test_set/
  ├── entropy_padding/
  │   ├── benign_padded_1.exe
  │   ├── benign_padded_2.exe
  │   └── ...
  ├── packed_installers/
  │   ├── 7zip_installer.exe
  │   ├── inno_installer.exe
  │   └── ...
  └── low_entropy_malware/
      ├── malware_disguised_1.exe
      ├── malware_disguised_2.exe
      └── ...
```

### Implementation

```python
# test_adversarial.py
def test_entropy_padding():
    """Verify model doesn't flag benign + padding as malware"""

def test_packed_installers():
    """Verify legitimate packed installers detected as safe"""

def test_low_entropy_malware():
    """Verify low-entropy malware still detected"""
```

### Benefits

✓ Real-world robustness testing
✓ Catch adversarial evasion attempts
✓ Validate feature engineering

---

## Step 5: Retrain & Threshold Tuning

### Retraining Flow

```
1. Add new features to training pipeline
2. Rebuild feature DataFrame with new columns
3. Re-extract features from all training PE files
4. Retrain LGBM + XGB with new feature set
5. Evaluate on test set
6. Run soft-voting threshold selection
7. Compare with old model (regression testing)
```

### Threshold Tuning

```python
# Using existing soft-voting logic from train_models.py

# Test thresholds: 0.35, 0.40, 0.45, 0.50, 0.55
# Select threshold that maximizes:
#   - Recall >= 0.85 (catch malware)
#   - Precision >= 0.75 (minimize false positives)
#   - F1-score

# Update report with:
# ensemble_soft_voting.selected_threshold = new_value
```

### Files to Run

```bash
# 1. Extract new features
python FILE/training/train_models.py --feature-config v2

# 2. Retrain
python FILE/training/train_models.py \
  --data-path FILE/data/malware_data_final.csv \
  --models-dir FILE/models \
  --test-size 0.2 \
  --hardcase-scale 1.0

# 3. Test adversarial set
python test_adversarial_file_model.py

# 4. Deploy
# Update FILE/models/ with new .ubj/.pkl
# ThresholdRegistry auto-loads new thresholds
```

### Success Criteria

- [ ] New features improve accuracy
- [ ] Adversarial tests pass
- [ ] Threshold selected correctly
- [ ] No regression on old test set
- [ ] Runtime performance acceptable

---

## Step-by-Step Execution Plan

### Phase 1: Foundation (.ubj + Metadata)

**Estimated**: 2-3 hours

1. Add .ubj save logic to train_models.py
2. Add .ubj load logic to file_service.py
3. Extract feature importance + save to training_report.json
4. Update ModelMetadataRegistry to expose feature_importance
5. Test: Load model, verify feature importance accessible

**Outcome**: Model format modernized, feature importance visible

---

### Phase 2: Feature Expansion

**Estimated**: 3-4 hours

1. Implement new feature extractors (is_packed, import_category_score, etc.)
2. Update train_models.py to compute new features
3. Add new features to FEATURES list
4. Run feature extraction on training data
5. Test: Generate features for sample PE files

**Outcome**: 10 → 16 features in production

---

### Phase 3: Adversarial Testing

**Estimated**: 2-3 hours

1. Create test dataset directory structure
2. Implement adversarial test cases
3. Create test_adversarial_file_model.py script
4. Run tests against current model
5. Document results and edge cases

**Outcome**: Understand model robustness, identify weaknesses

---

### Phase 4: Retrain & Tune

**Estimated**: 2-4 hours

1. Run full retraining pipeline with new features
2. Generate new training_report.json with updated metrics
3. Select new thresholds via soft-voting
4. Compare with previous model metrics
5. Validate on adversarial test set
6. Update FILE/models/

**Outcome**: Production-ready model v2

---

### Phase 5: Validation & Deployment

**Estimated**: 1-2 hours

1. End-to-end pipeline test
2. Verify ThresholdRegistry loads new thresholds
3. Verify file_service uses new model
4. Run all evaluation tests
5. Documentation updates

**Outcome**: Ready for production deployment

---

## Total Effort: ~10-16 hours

**Timeline**: Can be done in 1-2 days

---

## Files to Create/Modify

### New Files (5)

```
FILE/training/feature_engineering_v2.py    # New feature functions
test_adversarial_file_model.py             # Adversarial tests
FILE/data/adversarial_test_set/            # Test dataset
docs/FILE_MODEL_V2_CHANGELOG.md            # What changed
docs/FEATURE_IMPORTANCE_GUIDE.md           # How to interpret
```

### Modified Files (5)

```
FILE/training/train_models.py              # Compute new features, .ubj save
FILE/models/                               # .ubj format added
backend/services/file_service.py           # Load .ubj with fallback
backend/config/model_metadata_registry.py  # Expose feature_importance
backend/services/upload_validator.py       # (No changes needed)
```

---

## Rollback Plan

If something goes wrong:

1. Keep old .pkl model as fallback
2. Old ThresholdConfig values still work
3. file_service.py can switch back by removing .ubj load
4. Gradual rollback possible per file detection

---

## Success Metrics

After completion:

- [ ] Model accuracy improved (or stable)
- [ ] False positive rate reduced
- [ ] Adversarial tests passing
- [ ] Feature importance transparent
- [ ] Threshold selected optimally
- [ ] Zero breaking changes to API
- [ ] All evaluation tests passing

---

## Next Steps

1. **Approve plan** - Confirm tasks and timeline
2. **Phase 1 Start** - XGBoost .ubj migration
3. Progress tracking via todo list
4. Weekly checkpoint review

---

**Status**: ✅ PLAN READY  
**Ready to execute**: YES  
**Estimated start**: Now  
**Estimated completion**: 1-2 days
