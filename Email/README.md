## Email Prediction Module

- Model source: `Email/models/lgb_model.pkl` + `Email/models/xgb_model.pkl`
- Supporting artifacts: `Email/models/vectorizer.pkl`, `Email/models/scaler.pkl`, `Email/models/label_encoder.pkl`
- Entry point: `Email/predict.py`
- Functions: `predict_from_file(eml_path)`, `predict_from_text(subject, body)`
- Live inference no longer depends on `WEB/backend/spam_model.joblib`
