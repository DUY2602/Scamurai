from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from ml_artifact_utils import print_done


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
DATASET_CANDIDATES = [
    DATA_DIR / "malware_data_final.csv",
    DATA_DIR / "file_dataset.csv",
    DATA_DIR / "malware_dataset.csv",
]


def detect_dataset() -> Path | None:
    for candidate in DATASET_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def main() -> None:
    dataset_path = detect_dataset()
    if dataset_path is None:
        print("WARNING: FILE training dataset is missing.")
        print("Expected one of:")
        for candidate in DATASET_CANDIDATES:
            print(f"  - {candidate}")
        print("Recovery steps:")
        print("  1. Restore the original CSV from backup or version control.")
        print("  2. If unavailable, rebuild the CSV from malware/benign PE folders using FILE/utils/preprocess.py.")
        print("  3. Re-run python FILE/training/file_retrain_template.py once the dataset is restored.")
        print_done("file_data_audit.py")
        return

    df = pd.read_csv(dataset_path)
    label_column = next((column for column in df.columns if column.lower() in {"label", "target", "class"}), None)
    print(f"Dataset: {dataset_path}")
    print(f"Shape: {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    if label_column:
        print("\nClass distribution:")
        print(df[label_column].value_counts(dropna=False))
    else:
        print("\nWARNING: No label column detected.")
    print("\nMissing values by column:")
    print(df.isna().sum())
    print_done("file_data_audit.py")


if __name__ == "__main__":
    main()
