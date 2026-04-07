from __future__ import annotations

import argparse
import hashlib
import itertools
import sys
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
from sklearn.model_selection import train_test_split

from Email.pipeline import build_training_record, normalize_email_text_for_hash
from ml_artifact_utils import print_done

try:
    from datasketch import MinHash, MinHashLSH
except Exception:  # pragma: no cover - optional dependency
    MinHash = None
    MinHashLSH = None


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
DEFAULT_INPUT = DATA_DIR / "email_classification_dataset.csv"
if not DEFAULT_INPUT.exists():
    DEFAULT_INPUT = ROOT_DIR / "spamassassin_parsed.csv"
TRAIN_OUTPUT = DATA_DIR / "email_train.csv"
VAL_OUTPUT = DATA_DIR / "email_val.csv"
TEST_OUTPUT = DATA_DIR / "email_test.csv"


@dataclass
class DedupStats:
    raw_rows: int
    after_exact_dedup: int
    after_near_dedup: int
    dropped_exact: int
    dropped_near: int
    dropped_conflicts: int


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left == root_right:
            return
        if self.rank[root_left] < self.rank[root_right]:
            self.parent[root_left] = root_right
        elif self.rank[root_left] > self.rank[root_right]:
            self.parent[root_right] = root_left
        else:
            self.parent[root_right] = root_left
            self.rank[root_left] += 1


def detect_input_path(candidate: str | None) -> Path:
    if candidate:
        return Path(candidate).expanduser().resolve()
    return DEFAULT_INPUT.resolve()


def build_mock_dataset() -> pd.DataFrame:
    samples = [
        {
            "email": "From: support@company.com\nSubject: Your order has shipped\n\nYour package is on its way and will arrive Thursday.",
            "label": "ham",
        },
        {
            "email": "From: noreply@store.com\nSubject: Shipment confirmation\n\nTracking number 1Z999AA10123456784 is active.",
            "label": "ham",
        },
        {
            "email": "From: promo@winner.net\nSubject: Congratulations winner\n\nClaim your free gift card before midnight.",
            "label": "spam",
        },
        {
            "email": "From: promo@winner.net\nSubject: Congratulations winner\n\nClaim your free gift card before midnight!",
            "label": "spam",
        },
    ]
    return pd.DataFrame(samples)


def load_dataset(input_path: Path) -> pd.DataFrame:
    if input_path.is_file():
        print(f"Loading dataset: {input_path}")
        return pd.read_csv(input_path)

    warnings.warn(
        f"Input dataset not found at {input_path}. Falling back to mock email data so the script can still run.",
        RuntimeWarning,
        stacklevel=2,
    )
    return build_mock_dataset()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_records(df: pd.DataFrame) -> pd.DataFrame:
    label_col = "label" if "label" in df.columns else "target"
    normalized_rows: list[dict[str, str]] = []
    for row in df.to_dict(orient="records"):
        record = build_training_record(pd.Series(row))
        normalized_text = normalize_email_text_for_hash(record["text"])
        normalized_rows.append(
            {
                "subject": record["subject"],
                "body": record["body"],
                "sender": record["sender"],
                "text": record["text"],
                "normalized_text": normalized_text,
                "exact_hash": sha256_text(normalized_text),
                "label": "spam" if str(row.get(label_col, "ham")).strip().lower() in ["1", "spam", "true", "malicious"] else "ham",
                "source": str(row.get("source", "unknown") or "unknown").strip().lower(),
            }
        )
    output = pd.DataFrame(normalized_rows)
    output = output[output["normalized_text"].astype(bool)].reset_index(drop=True)
    return output


def make_shingles(text: str, shingle_size: int = 5) -> set[str]:
    tokens = text.split()
    if len(tokens) <= shingle_size:
        return {text}
    return {" ".join(tokens[index : index + shingle_size]) for index in range(len(tokens) - shingle_size + 1)}


def jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _cluster_with_datasketch(df: pd.DataFrame, threshold: float, num_perm: int) -> list[int]:
    shingles = [make_shingles(text) for text in df["normalized_text"]]
    union_find = UnionFind(len(df))
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    minhashes: list[MinHash] = []

    for index, shingle_set in enumerate(shingles):
        minhash = MinHash(num_perm=num_perm)
        for token in shingle_set:
            minhash.update(token.encode("utf-8"))
        key = f"row-{index}"
        minhashes.append(minhash)
        lsh.insert(key, minhash)

    for index, minhash in enumerate(minhashes):
        key = f"row-{index}"
        for candidate in lsh.query(minhash):
            candidate_index = int(candidate.split("-")[-1])
            if candidate_index <= index:
                continue
            if df.iloc[index]["label"] != df.iloc[candidate_index]["label"]:
                continue
            union_find.union(index, candidate_index)

    return [union_find.find(index) for index in range(len(df))]


def _cluster_with_fallback(df: pd.DataFrame, threshold: float) -> list[int]:
    print("WARNING: datasketch is not installed; using conservative near-dedup fallback.")
    shingles = [make_shingles(text) for text in df["normalized_text"]]
    candidate_blocks: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    for index, row in enumerate(df.itertuples(index=False)):
        tokens = row.normalized_text.split()
        prefix = " ".join(tokens[:10])
        bucket = len(tokens) // 10
        candidate_blocks[(row.label, prefix, bucket)].append(index)

    union_find = UnionFind(len(df))
    for indices in candidate_blocks.values():
        if len(indices) < 2:
            continue
        for left, right in itertools.combinations(indices, 2):
            if jaccard_similarity(shingles[left], shingles[right]) >= threshold:
                union_find.union(left, right)

    return [union_find.find(index) for index in range(len(df))]


def deduplicate_dataset(df: pd.DataFrame, threshold: float, num_perm: int) -> tuple[pd.DataFrame, DedupStats]:
    raw_rows = len(df)
    exact_dedup = df.drop_duplicates(subset=["exact_hash", "label"]).reset_index(drop=True)
    dropped_exact = raw_rows - len(exact_dedup)

    if len(exact_dedup) == 0:
        stats = DedupStats(raw_rows, 0, 0, dropped_exact, 0, 0)
        return exact_dedup, stats

    if MinHash is not None and MinHashLSH is not None:
        cluster_ids = _cluster_with_datasketch(exact_dedup, threshold=threshold, num_perm=num_perm)
        print(f"Near-dedup mode: MinHashLSH threshold={threshold} num_perm={num_perm}")
    else:
        cluster_ids = _cluster_with_fallback(exact_dedup, threshold=threshold)
        print(f"Near-dedup mode: fallback Jaccard threshold={threshold}")

    clustered = exact_dedup.copy()
    clustered["near_group"] = cluster_ids

    cluster_rows: list[dict[str, str]] = []
    dropped_conflicts = 0
    for cluster_id, group in clustered.groupby("near_group", sort=False):
        label_counts = group["label"].value_counts()
        if len(label_counts) > 1:
            dropped_conflicts += len(group)
            continue
        chosen = group.sort_values(["normalized_text", "exact_hash"]).iloc[0].to_dict()
        chosen["near_group"] = f"group_{cluster_id}"
        cluster_rows.append(chosen)

    dedup_df = pd.DataFrame(cluster_rows).reset_index(drop=True)
    dropped_near = len(exact_dedup) - len(dedup_df) - dropped_conflicts
    stats = DedupStats(
        raw_rows=raw_rows,
        after_exact_dedup=len(exact_dedup),
        after_near_dedup=len(dedup_df),
        dropped_exact=dropped_exact,
        dropped_near=max(dropped_near, 0),
        dropped_conflicts=dropped_conflicts,
    )
    return dedup_df, stats


def print_class_distribution(name: str, labels: Iterable[str]) -> None:
    counter = Counter(labels)
    total = sum(counter.values()) or 1
    print(f"\n{name} class distribution:")
    for label, count in sorted(counter.items()):
        print(f"  {label:<6} {count:>6} ({(count / total) * 100:6.2f}%)")


def split_dataset(df: pd.DataFrame, random_state: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        stratify=df["label"],
        random_state=random_state,
    )
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        stratify=temp_df["label"],
        random_state=random_state,
    )
    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def save_split(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False, encoding="utf-8")
    print(f"Saved: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deduplicate email data and create leak-resistant train/val/test splits.")
    parser.add_argument("--input", type=str, default=None, help="Input CSV path. Defaults to Email/data/email_classification_dataset.csv.")
    parser.add_argument("--threshold", type=float, default=0.85, help="Near-dedup similarity threshold.")
    parser.add_argument("--num-perm", type=int, default=128, help="MinHash permutation count when datasketch is installed.")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    input_path = detect_input_path(args.input)
    raw_df = load_dataset(input_path)
    normalized_df = normalize_records(raw_df)
    dedup_df, stats = deduplicate_dataset(normalized_df, threshold=args.threshold, num_perm=args.num_perm)

    print(f"\nRaw rows:              {stats.raw_rows}")
    print(f"After exact dedup:     {stats.after_exact_dedup}")
    print(f"After near dedup:      {stats.after_near_dedup}")
    print(f"Dropped exact dups:    {stats.dropped_exact}")
    print(f"Dropped near dups:     {stats.dropped_near}")
    print(f"Dropped label clashes: {stats.dropped_conflicts}")
    print_class_distribution("Post-dedup", dedup_df["label"])

    train_df, val_df, test_df = split_dataset(dedup_df, random_state=args.random_state)
    print(f"\nSplit sizes: train={len(train_df)} val={len(val_df)} test={len(test_df)}")
    print_class_distribution("Train", train_df["label"])
    print_class_distribution("Validation", val_df["label"])
    print_class_distribution("Test", test_df["label"])

    save_split(train_df, TRAIN_OUTPUT)
    save_split(val_df, VAL_OUTPUT)
    save_split(test_df, TEST_OUTPUT)
    print_done("email_dedup_split.py")


if __name__ == "__main__":
    main()
