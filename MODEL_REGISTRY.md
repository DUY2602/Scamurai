# Model Registry

This file documents which artifacts are intended to be active, which ones are legacy, and which datasets/features they belong to.

## Active Deploy Artifacts

### URL
- Models: `URL/models/lgbm_model.pkl`, `URL/models/xgb_model.pkl` or `URL/models/xgb_model.ubj`
- Feature lists: `URL/models/feature_names.pkl`, `URL/models/feature_names_xgb.pkl`
- Label encoder: `URL/models/label_encoder.pkl`
- XGBoost scaler: `URL/models/scaler_xgb.pkl`
- Compatibility scaler: `URL/models/scaler.pkl`
- Dataset: `URL/data/processed_malicious_url.csv`

### Email
- Preferred single-model deploy: `Email/models/best_model.pkl`
- Metadata: `Email/models/best_model_metadata.json`
- Shared preprocessing artifacts: `Email/models/vectorizer.pkl`, `Email/models/scaler.pkl`, `Email/models/label_encoder.pkl`
- Datasets: `Email/data/email_train.csv`, `Email/data/email_val.csv`, `Email/data/email_test.csv`, `Email/data/email_hardcase_test.csv`

### FILE
- Models: `FILE/models/lightgbm_malware_model.pkl`, `FILE/models/xgboost_malware_model.pkl` or `FILE/models/xgboost_malware_model.ubj`
- Auxiliary anomaly model: `FILE/models/kmeans_malware_model.pkl`
- Feature scaler: `FILE/models/feature_scaler.pkl`
- Dataset: restored CSV under `FILE/data/`

## Legacy / Archive Candidates
- `Email/models/archive/*`
- `Email/models/backup/*`
- `URL/models/backup/*`
- Notebook-only experiment outputs under `URL/scripts`, `Email/scripts`, `FILE/scripts`
- Legacy evaluation JSON/CSV that are not referenced by deploy code

<!-- REGISTRY_JSON_START -->
```json
{
  "active": [
    "URL/models/lgbm_model.pkl",
    "URL/models/xgb_model.pkl",
    "URL/models/xgb_model.ubj",
    "URL/models/feature_names.pkl",
    "URL/models/feature_names_xgb.pkl",
    "URL/models/label_encoder.pkl",
    "URL/models/scaler_xgb.pkl",
    "URL/models/scaler.pkl",
    "URL/models/model_metadata.json",
    "Email/models/best_model.pkl",
    "Email/models/best_model_metadata.json",
    "Email/models/vectorizer.pkl",
    "Email/models/scaler.pkl",
    "Email/models/label_encoder.pkl",
    "FILE/models/lightgbm_malware_model.pkl",
    "FILE/models/xgboost_malware_model.pkl",
    "FILE/models/xgboost_malware_model.ubj",
    "FILE/models/kmeans_malware_model.pkl",
    "FILE/models/feature_scaler.pkl"
  ],
  "legacy_prefixes": [
    "URL/models/backup/",
    "Email/models/archive/",
    "Email/models/backup/"
  ]
}
```
<!-- REGISTRY_JSON_END -->
