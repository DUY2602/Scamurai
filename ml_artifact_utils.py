from __future__ import annotations

import hashlib
import json
import sys
import warnings
from pathlib import Path
from typing import Any

import joblib


def ensure_parent_dir(path: str | Path) -> Path:
    resolved = Path(path).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def compute_file_md5(path: str | Path) -> str:
    file_path = Path(path).resolve()
    digest = hashlib.md5()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path: str | Path, payload: dict[str, Any]) -> Path:
    target = ensure_parent_dir(path)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return target


def save_joblib(path: str | Path, payload: Any) -> Path:
    target = ensure_parent_dir(path)
    joblib.dump(payload, target)
    return target


def save_xgboost_model(model: Any, path: str | Path, *, legacy_pickle_path: str | Path | None = None) -> Path:
    target = ensure_parent_dir(path)
    model.save_model(str(target))
    if legacy_pickle_path is not None:
        save_joblib(legacy_pickle_path, model)
    return target


def load_xgboost_model(
    *,
    ubj_path: str | Path | None = None,
    pickle_path: str | Path | None = None,
    model_factory: Any = None,
) -> Any:
    ubj_file = Path(ubj_path).resolve() if ubj_path is not None else None
    pickle_file = Path(pickle_path).resolve() if pickle_path is not None else None

    if ubj_file is not None and ubj_file.is_file():
        if model_factory is None:
            from xgboost import XGBClassifier

            model_factory = XGBClassifier
        model = model_factory()
        model.load_model(str(ubj_file))
        return model

    if pickle_file is not None and pickle_file.is_file():
        warnings.warn(
            f"Loading XGBoost artifact from pickle fallback: {pickle_file}. "
            "Consider migrating this artifact to .ubj for version-safe loading.",
            RuntimeWarning,
            stacklevel=2,
        )
        return joblib.load(pickle_file)

    tried_paths = [str(path) for path in [ubj_file, pickle_file] if path is not None]
    raise FileNotFoundError(f"Could not locate XGBoost artifact. Tried: {tried_paths}")


def print_done(script_name: str) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    try:
        print(f"\n\u2713 Done: {script_name}")
    except UnicodeEncodeError:
        pass
    print(f"Done: {script_name}")
