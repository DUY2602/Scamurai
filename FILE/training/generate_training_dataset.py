"""Generate synthetic malware training dataset for Phase 3 retrain."""

from __future__ import annotations

import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
from ml_artifact_utils import print_done


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"


def generate_synthetic_dataset(benign_samples: int = 300, malware_samples: int = 300) -> pd.DataFrame:
    """Generate realistic synthetic malware/benign dataset for training.
    
    Args:
        benign_samples: Number of benign samples
        malware_samples: Number of malware samples
        
    Returns:
        DataFrame with features and labels
    """
    rng = random.Random(42)
    records = []
    
    # Benign samples - typical system files/libraries
    for idx in range(benign_samples):
        records.append({
            "MD5": f"benign_{idx:05d}",
            "Sections": rng.randint(4, 9),
            "AvgEntropy": round(rng.uniform(3.0, 5.8), 4),
            "MaxEntropy": round(rng.uniform(4.5, 6.8), 4),
            "SuspiciousSections": rng.randint(0, 1),
            "DLLs": rng.randint(10, 80),
            "Imports": rng.randint(50, 500),
            "HasSensitiveAPI": rng.randint(0, 1),
            "ImageBase": rng.choice([4194304, 5368709120]),
            "SizeOfImage": rng.randint(32768, 1048576),
            "HasVersionInfo": 1,
            # v2 features
            "is_packed": 0,
            "import_category_score": round(rng.uniform(0.01, 0.3), 4),
            "has_tls": rng.randint(0, 1),
            "export_table_size": 0,
            "resource_entropy": round(rng.uniform(2.0, 5.0), 4),
            "api_category_score": round(rng.uniform(0.1, 0.5), 4),
            "Label": 0,
        })
    
    # Malware samples - packed, suspicious, high entropy
    for idx in range(malware_samples):
        records.append({
            "MD5": f"malware_{idx:05d}",
            "Sections": rng.randint(2, 7),
            "AvgEntropy": round(rng.uniform(6.5, 7.9), 4),
            "MaxEntropy": round(rng.uniform(7.2, 8.0), 4),
            "SuspiciousSections": rng.randint(1, 4),
            "DLLs": rng.randint(0, 20),
            "Imports": rng.randint(5, 150),
            "HasSensitiveAPI": 1,
            "ImageBase": rng.choice([4194304, 5368709120]),
            "SizeOfImage": rng.randint(8192, 262144),
            "HasVersionInfo": rng.randint(0, 1),
            # v2 features
            "is_packed": rng.randint(0, 1),
            "import_category_score": round(rng.uniform(0.5, 1.0), 4),
            "has_tls": rng.randint(0, 1),
            "export_table_size": rng.randint(0, 50),
            "resource_entropy": round(rng.uniform(5.5, 8.0), 4),
            "api_category_score": round(rng.uniform(0.6, 1.0), 4),
            "Label": 1,
        })
    
    df = pd.DataFrame(records)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df


def main() -> None:
    """Generate and save training dataset."""
    print("Generating synthetic malware training dataset...")
    print("-" * 60)
    
    # Create data directory if it doesn't exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate dataset
    df = generate_synthetic_dataset(benign_samples=300, malware_samples=300)
    
    # Save
    output_path = DATA_DIR / "malware_data_final.csv"
    df.to_csv(output_path, index=False)
    
    print(f"Dataset saved: {output_path}")
    print(f"Shape: {df.shape}")
    print(f"Columns: {len(df.columns)}")
    print(f"\nClass distribution:")
    print(df["Label"].value_counts())
    print(f"\nV1 Features (10): Sections, AvgEntropy, MaxEntropy, SuspiciousSections, DLLs, Imports, HasSensitiveAPI, ImageBase, SizeOfImage, HasVersionInfo")
    print(f"V2 New Features (6): is_packed, import_category_score, has_tls, export_table_size, resource_entropy, api_category_score")
    print(f"Total Features (16): ✓")
    
    print_done("generate_training_dataset.py")


if __name__ == "__main__":
    main()
