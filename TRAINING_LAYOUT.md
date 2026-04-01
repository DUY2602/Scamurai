# Training Layout

This repo now separates runtime code from training and dataset-preparation scripts.

## Runtime entry points

- `Email/predict.py`
- `FILE/main.py`
- `URL/main.py`

## Topic script layout

- `Email/training/`
  - model training and evaluation scripts
- `Email/data_prep/`
  - dataset parsing, deduplication, and merge helpers
- `FILE/training/`
  - retraining, audit, and experiment scripts
- `URL/training/`
  - training and feature-engineering scripts

## Example commands

```powershell
python Email/training/train.py
python Email/training/email_retrain.py
python Email/data_prep/email_dedup_split.py
python FILE/training/train_models.py
python URL/training/train.py
python URL/training/url_train_v2.py
```
