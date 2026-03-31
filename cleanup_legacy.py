from __future__ import annotations

import json
from pathlib import Path

from ml_artifact_utils import print_done


ROOT_DIR = Path(__file__).resolve().parent
REGISTRY_PATH = ROOT_DIR / "MODEL_REGISTRY.md"
TARGET_SUFFIXES = {".pkl", ".ubj", ".json", ".csv"}
IGNORE_PARTS = {"node_modules", ".git", "__pycache__", ".vite"}


def load_registry() -> dict[str, list[str]]:
    text = REGISTRY_PATH.read_text(encoding="utf-8")
    start_marker = "<!-- REGISTRY_JSON_START -->"
    end_marker = "<!-- REGISTRY_JSON_END -->"
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start)
    payload = text[start:end].strip()
    payload = payload.replace("```json", "").replace("```", "").strip()
    return json.loads(payload)


def main() -> None:
    registry = load_registry()
    active = {str((ROOT_DIR / path).resolve()) for path in registry.get("active", [])}
    legacy_prefixes = [str((ROOT_DIR / prefix).resolve()) for prefix in registry.get("legacy_prefixes", [])]

    all_candidates = [
        path.resolve()
        for path in ROOT_DIR.rglob("*")
        if path.is_file()
        and path.suffix.lower() in TARGET_SUFFIXES
        and not any(part in IGNORE_PARTS for part in path.parts)
    ]

    active_files: list[str] = []
    legacy_files: list[str] = []
    review_files: list[str] = []

    for file_path in all_candidates:
        resolved = str(file_path)
        if resolved in active:
            active_files.append(resolved)
            continue
        if any(resolved.startswith(prefix) for prefix in legacy_prefixes):
            legacy_files.append(resolved)
            continue
        review_files.append(resolved)

    print("Active files:")
    for path in sorted(active_files):
        print(f"  ACTIVE  {path}")

    print("\nLegacy candidates (safe to review/archive manually):")
    for path in sorted(legacy_files):
        print(f"  LEGACY  {path}")

    print("\nNeeds manual review:")
    for path in sorted(review_files):
        print(f"  REVIEW  {path}")

    print_done("cleanup_legacy.py")


if __name__ == "__main__":
    main()
