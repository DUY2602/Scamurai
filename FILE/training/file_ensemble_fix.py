from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml_artifact_utils import print_done


KNOWN_CLEAN_SYSTEM_FILES = ("notepad.exe", "calc.exe", "cmd.exe", "mspaint.exe", "taskmgr.exe")


def compute_sha256_from_path(file_path: str | Path) -> str:
    path = Path(file_path).expanduser().resolve()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_sha256_from_bytes(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def build_known_clean_whitelist() -> set[str]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    whitelist: set[str] = set()
    for filename in KNOWN_CLEAN_SYSTEM_FILES:
        candidate = system_root / "System32" / filename
        if candidate.is_file():
            whitelist.add(compute_sha256_from_path(candidate))
    return whitelist


def summarize_supervised_confidence(supervised_results: list[dict[str, Any]]) -> tuple[str, float]:
    if not supervised_results:
        return "BENIGN", 0.0

    malware_votes = sum(1 for result in supervised_results if bool(result.get("is_malicious")))
    benign_votes = len(supervised_results) - malware_votes
    positive_confidences = [float(result.get("confidence", 0.0) or 0.0) for result in supervised_results]
    avg_positive_confidence = sum(positive_confidences) / len(positive_confidences)

    if malware_votes > benign_votes:
        return "MALWARE", avg_positive_confidence
    return "BENIGN", 1.0 - avg_positive_confidence


def finalize_file_ensemble(
    *,
    supervised_results: list[dict[str, Any]],
    kmeans_result: dict[str, Any] | None,
    known_clean_sha256: set[str] | None,
    file_sha256: str | None,
) -> dict[str, Any]:
    whitelist = known_clean_sha256 or set()
    if file_sha256 and file_sha256 in whitelist:
        return {
            "label": "BENIGN",
            "verdict": "BENIGN",
            "confidence": 0.9999,
            "risk_flag": "Known-clean SHA256 whitelist hit",
        }

    supervised_label, supervised_confidence = summarize_supervised_confidence(supervised_results)
    kmeans_is_malware = bool(kmeans_result and kmeans_result.get("is_malicious"))

    if supervised_confidence >= 0.6:
        if supervised_label == "BENIGN":
            return {
                "label": "BENIGN",
                "verdict": "BENIGN",
                "confidence": float(supervised_confidence),
                "risk_flag": None,
            }
        verdict = "MALICIOUS" if supervised_confidence >= 0.7 else "SUSPICIOUS"
        return {
            "label": "MALWARE",
            "verdict": verdict,
            "confidence": float(supervised_confidence),
            "risk_flag": None,
        }

    if supervised_label == "BENIGN" and not kmeans_is_malware:
        return {
            "label": "BENIGN",
            "verdict": "BENIGN",
            "confidence": float(max(0.55, supervised_confidence)),
            "risk_flag": "Low-confidence benign consensus",
        }

    if supervised_label == "BENIGN" and kmeans_is_malware:
        return {
            "label": "BENIGN",
            "verdict": "SUSPICIOUS",
            "confidence": float(max(0.45, supervised_confidence)),
            "risk_flag": "KMeans anomaly flag raised a low-confidence benign case",
        }

    return {
        "label": "MALWARE",
        "verdict": "SUSPICIOUS",
        "confidence": float(max(0.5, supervised_confidence)),
        "risk_flag": "Low-confidence supervised malware signal",
    }


def main() -> None:
    whitelist = build_known_clean_whitelist()
    print(f"Known-clean whitelist entries: {len(whitelist)}")
    for digest in sorted(list(whitelist))[:5]:
        print(f"  {digest}")
    print_done("file_ensemble_fix.py")


if __name__ == "__main__":
    main()
