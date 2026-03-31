from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Email.email_dedup_split import deduplicate_dataset, normalize_records, print_class_distribution, save_split, split_dataset
from ml_artifact_utils import print_done


ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
TRAIN_PATH = DATA_DIR / "email_train.csv"
VAL_PATH = DATA_DIR / "email_val.csv"
TEST_PATH = DATA_DIR / "email_test.csv"


def load_existing_splits() -> pd.DataFrame:
    frames = []
    for path in [TRAIN_PATH, VAL_PATH, TEST_PATH]:
        if not path.is_file():
            raise FileNotFoundError(f"Missing existing split file: {path}")
        frame = pd.read_csv(path)
        frame["source"] = frame.get("source", "existing_split")
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def load_spamassassin_csv(path: Path) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"SpamAssassin parsed CSV not found: {path}")

    df = pd.read_csv(path)
    if not {"text", "label", "source"}.issubset(df.columns):
        raise ValueError("spamassassin_parsed.csv must contain columns: text, label, source")

    output = df.copy()
    output["label"] = output["label"].map({0: "ham", 1: "spam"}).fillna(output["label"]).astype(str).str.lower()
    output["source"] = output["source"].fillna("spamassassin").astype(str).str.lower()
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge existing Email splits with parsed SpamAssassin data, then deduplicate and resplit.")
    parser.add_argument("--spamassassin-csv", required=True, type=str, help="Path to spamassassin_parsed.csv.")
    parser.add_argument("--threshold", default=0.85, type=float, help="Near-dedup similarity threshold.")
    parser.add_argument("--num-perm", default=128, type=int, help="MinHash permutation count when datasketch is available.")
    parser.add_argument("--random-state", default=42, type=int)
    args = parser.parse_args()

    existing_df = load_existing_splits()
    spamassassin_df = load_spamassassin_csv(Path(args.spamassassin_csv).expanduser().resolve())
    merged_df = pd.concat([existing_df, spamassassin_df], ignore_index=True)
    total_before = len(merged_df)

    normalized_df = normalize_records(merged_df)
    dedup_df, stats = deduplicate_dataset(normalized_df, threshold=args.threshold, num_perm=args.num_perm)
    train_df, val_df, test_df = split_dataset(dedup_df, random_state=args.random_state)

    save_split(train_df, TRAIN_PATH)
    save_split(val_df, VAL_PATH)
    save_split(test_df, TEST_PATH)

    print(f"Total rows before dedup: {total_before}")
    print(f"Total rows after dedup:  {len(dedup_df)}")
    print(f"Dropped exact dups:      {stats.dropped_exact}")
    print(f"Dropped near dups:       {stats.dropped_near}")
    print(f"Dropped label clashes:   {stats.dropped_conflicts}")
    print_class_distribution("Post-dedup", dedup_df["label"])
    print(f"\nSplit sizes: train={len(train_df)} val={len(val_df)} test={len(test_df)}")
    print_done("merge_and_dedup.py")


if __name__ == "__main__":
    main()
