from pathlib import Path
from threading import Lock
import json

import joblib
import pandas as pd

from backend.services.asset_paths import maybe_find_asset_path

_dataset_cache_lock = Lock()
_dataset_cache_signature: tuple | None = None
_dataset_cache_payload: dict | None = None


def _safe_float(value) -> float:
    try:
        return round(float(value), 4)
    except Exception:
        return 0.0


def _count_urls(text: str) -> int:
    lowered = text.lower()
    return lowered.count("http://") + lowered.count("https://") + lowered.count("www.")


def _uppercase_ratio(text: str) -> float:
    if not text:
        return 0.0

    letters = [char for char in text if char.isalpha()]
    if not letters:
        return 0.0

    uppercase = sum(1 for char in letters if char.isupper())
    return uppercase / len(letters)


def _label_distribution(series: pd.Series, positive_values: set[str]) -> dict:
    normalized = series.astype(str).str.strip().str.lower()
    positive_count = int(normalized.isin(positive_values).sum())
    negative_count = int(len(normalized) - positive_count)

    return {
        "positive": positive_count,
        "negative": negative_count,
        "total": int(len(normalized)),
    }


def _build_topic_payload(
    topic_id: str,
    title: str,
    source_path: Path | None,
    distribution: dict,
    distribution_labels: dict | None,
    feature_rows: list[dict],
    top_features: list[dict],
) -> dict:
    return {
        "id": topic_id,
        "title": title,
        "source_path": str(source_path) if source_path else None,
        "distribution": distribution,
        "distribution_labels": distribution_labels or {},
        "feature_rows": feature_rows,
        "top_features": top_features,
    }


def _safe_feature_name(value: object) -> str:
    return str(value or "").replace("_", " ").strip().title()


def _normalize_importances(names: list[str], values: list[float], limit: int = 10) -> list[dict]:
    pairs = []
    for name, value in zip(names, values):
        try:
            numeric_value = abs(float(value))
        except Exception:
            numeric_value = 0.0

        if numeric_value <= 0:
            continue

        pairs.append((str(name), numeric_value))

    if not pairs:
        return []

    pairs.sort(key=lambda item: item[1], reverse=True)
    top_pairs = pairs[:limit]
    max_value = top_pairs[0][1] if top_pairs else 1.0

    return [
        {
            "id": feature_name,
            "label": _safe_feature_name(feature_name),
            "importance": round((importance / max_value) * 100, 2),
            "raw_importance": round(importance, 6),
        }
        for feature_name, importance in top_pairs
    ]


def _load_joblib_if_exists(path: Path | None):
    if path is None or not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None


def _find_email_dataset_path() -> Path | None:
    candidates = [
        ("Email", "data", "email_classification_dataset.csv"),
        ("Email", "data", "processed_email_data.csv"),
        ("Email", "data", "email_split_data.csv"),
    ]

    for parts in candidates:
        path = maybe_find_asset_path(Path(__file__), *parts)
        if path is not None:
            return path

    return None


def _get_url_top_features() -> list[dict]:
    models_dir = maybe_find_asset_path(Path(__file__), "URL", "models")
    if models_dir is None:
        return []

    feature_names = _load_joblib_if_exists(models_dir / "feature_names.pkl") or []
    lgbm_model = _load_joblib_if_exists(models_dir / "lgbm_model.pkl")
    xgb_model = _load_joblib_if_exists(models_dir / "xgb_model.pkl")

    if not feature_names:
        return []

    scores = [0.0] * len(feature_names)

    if hasattr(lgbm_model, "feature_importances_"):
        for index, value in enumerate(lgbm_model.feature_importances_[: len(feature_names)]):
            scores[index] += float(value)

    if hasattr(xgb_model, "feature_importances_"):
        for index, value in enumerate(xgb_model.feature_importances_[: len(feature_names)]):
            scores[index] += float(value)

    return _normalize_importances(list(feature_names), scores)


def _get_file_top_features() -> list[dict]:
    models_dir = maybe_find_asset_path(Path(__file__), "FILE", "models")
    if models_dir is None:
        return []

    feature_names = [
        "Sections",
        "AvgEntropy",
        "MaxEntropy",
        "SuspiciousSections",
        "DLLs",
        "Imports",
        "HasSensitiveAPI",
        "ImageBase",
        "SizeOfImage",
        "HasVersionInfo",
    ]
    lgbm_model = _load_joblib_if_exists(models_dir / "lightgbm_malware_model.pkl")
    xgb_model = _load_joblib_if_exists(models_dir / "xgboost_malware_model.pkl")
    scores = [0.0] * len(feature_names)

    if hasattr(lgbm_model, "feature_importances_"):
        for index, value in enumerate(lgbm_model.feature_importances_[: len(feature_names)]):
            scores[index] += float(value)

    if hasattr(xgb_model, "feature_importances_"):
        for index, value in enumerate(xgb_model.feature_importances_[: len(feature_names)]):
            scores[index] += float(value)

    return _normalize_importances(feature_names, scores)


def _get_email_top_features() -> list[dict]:
    models_dir = maybe_find_asset_path(Path(__file__), "Email", "models")
    if models_dir is None:
        return []

    metadata = {}
    metadata_path = models_dir / "best_model_metadata.json"
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            metadata = {}
    model = _load_joblib_if_exists(models_dir / "best_model.pkl")
    vectorizer = _load_joblib_if_exists(models_dir / "vectorizer.pkl")
    numeric_features = []

    if isinstance(metadata, dict):
        numeric_features = list(metadata.get("numeric_features") or [])

    feature_names = []
    if hasattr(vectorizer, "get_feature_names_out"):
        try:
            feature_names.extend(vectorizer.get_feature_names_out().tolist())
        except Exception:
            feature_names.extend([])

    feature_names.extend(numeric_features)

    if not feature_names:
        return []

    if hasattr(model, "coef_"):
        coefficients = model.coef_[0] if getattr(model.coef_, "ndim", 1) > 1 else model.coef_
        return _normalize_importances(feature_names[: len(coefficients)], list(coefficients))

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_[: len(feature_names)]
        return _normalize_importances(feature_names[: len(importances)], list(importances))

    return []


def _load_url_dataset() -> dict:
    source_path = maybe_find_asset_path(Path(__file__), "URL", "data", "processed_malicious_url.csv")
    if source_path is None:
        return _build_topic_payload(
            "url",
            "URL",
            None,
            {"positive": 0, "negative": 0, "total": 0},
            {"positive": "Malicious", "negative": "Benign"},
            [],
            [],
        )

    df = pd.read_csv(
        source_path,
        usecols=["target", "url_len", "entropy", "keyword_count", "subdomain_count"],
    )
    distribution = _label_distribution(df["target"], {"malicious", "phishing", "harm", "1", "true"})
    harmful_mask = df["target"].astype(str).str.lower().isin({"malicious", "phishing", "harm", "1", "true"})

    feature_rows = [
        {
            "id": "url_len",
            "label": "URL length",
            "positive": _safe_float(df.loc[harmful_mask, "url_len"].mean()),
            "negative": _safe_float(df.loc[~harmful_mask, "url_len"].mean()),
        },
        {
            "id": "entropy",
            "label": "Entropy",
            "positive": _safe_float(df.loc[harmful_mask, "entropy"].mean()),
            "negative": _safe_float(df.loc[~harmful_mask, "entropy"].mean()),
        },
        {
            "id": "keyword_count",
            "label": "Keyword count",
            "positive": _safe_float(df.loc[harmful_mask, "keyword_count"].mean()),
            "negative": _safe_float(df.loc[~harmful_mask, "keyword_count"].mean()),
        },
        {
            "id": "subdomain_count",
            "label": "Subdomain count",
            "positive": _safe_float(df.loc[harmful_mask, "subdomain_count"].mean()),
            "negative": _safe_float(df.loc[~harmful_mask, "subdomain_count"].mean()),
        },
    ]

    return _build_topic_payload(
        "url",
        "URL",
        source_path,
        distribution,
        {"positive": "Malicious", "negative": "Benign"},
        feature_rows,
        _get_url_top_features(),
    )


def _load_file_dataset() -> dict:
    source_path = maybe_find_asset_path(Path(__file__), "FILE", "data", "malware_data_final.csv")
    if source_path is None:
        return _build_topic_payload(
            "file",
            "File",
            None,
            {"positive": 0, "negative": 0, "total": 0},
            {"positive": "Malware", "negative": "Benign"},
            [],
            [],
        )

    df = pd.read_csv(
        source_path,
        usecols=["Label", "Sections", "AvgEntropy", "Imports", "DLLs"],
    )
    labels = df["Label"].astype(str).str.strip().str.lower()
    malicious_mask = labels.isin({"1", "malware", "true"})
    benign_mask = ~malicious_mask
    distribution = {
        "positive": int(malicious_mask.sum()),
        "negative": int(benign_mask.sum()),
        "total": int(len(df)),
    }

    feature_rows = [
        {
            "id": "sections",
            "label": "Sections",
            "positive": _safe_float(df.loc[malicious_mask, "Sections"].mean()),
            "negative": _safe_float(df.loc[benign_mask, "Sections"].mean()),
        },
        {
            "id": "avg_entropy",
            "label": "Avg entropy",
            "positive": _safe_float(df.loc[malicious_mask, "AvgEntropy"].mean()),
            "negative": _safe_float(df.loc[benign_mask, "AvgEntropy"].mean()),
        },
        {
            "id": "imports",
            "label": "Imports",
            "positive": _safe_float(df.loc[malicious_mask, "Imports"].mean()),
            "negative": _safe_float(df.loc[benign_mask, "Imports"].mean()),
        },
        {
            "id": "dlls",
            "label": "DLLs",
            "positive": _safe_float(df.loc[malicious_mask, "DLLs"].mean()),
            "negative": _safe_float(df.loc[benign_mask, "DLLs"].mean()),
        },
    ]

    return _build_topic_payload(
        "file",
        "File",
        source_path,
        distribution,
        {"positive": "Malware", "negative": "Benign"},
        feature_rows,
        _get_file_top_features(),
    )


def _load_email_dataset() -> dict:
    source_path = _find_email_dataset_path()
    if source_path is None:
        return _build_topic_payload(
            "email",
            "Email",
            None,
            {"positive": 0, "negative": 0, "total": 0},
            {"positive": "Spam", "negative": "Ham"},
            [],
            [],
        )

    df = pd.read_csv(source_path)
    label_column = "label" if "label" in df.columns else None
    text_column = next(
        (column for column in ["email", "text", "normalized_text", "full_clean_text", "body"] if column in df.columns),
        None,
    )

    if label_column is None or text_column is None:
        return _build_topic_payload(
            "email",
            "Email",
            source_path,
            {"positive": 0, "negative": 0, "total": 0},
            {"positive": "Spam", "negative": "Ham"},
            [],
            _get_email_top_features(),
        )

    labels = df[label_column].astype(str).str.strip().str.lower()
    spam_mask = labels.isin({"spam", "phishing", "1", "true"})
    ham_mask = ~spam_mask
    texts = df[text_column].fillna("").astype(str)

    feature_frame = pd.DataFrame(
        {
            "text_length": texts.str.len(),
            "word_count": texts.str.split().str.len(),
            "link_count": texts.map(_count_urls),
            "exclamation_count": texts.str.count("!"),
            "uppercase_ratio": texts.map(_uppercase_ratio),
        }
    )

    distribution = {
        "positive": int(spam_mask.sum()),
        "negative": int(ham_mask.sum()),
        "total": int(len(df)),
    }

    feature_rows = [
        {
            "id": "text_length",
            "label": "Text length",
            "positive": _safe_float(feature_frame.loc[spam_mask, "text_length"].mean()),
            "negative": _safe_float(feature_frame.loc[ham_mask, "text_length"].mean()),
        },
        {
            "id": "word_count",
            "label": "Word count",
            "positive": _safe_float(feature_frame.loc[spam_mask, "word_count"].mean()),
            "negative": _safe_float(feature_frame.loc[ham_mask, "word_count"].mean()),
        },
        {
            "id": "link_count",
            "label": "Link count",
            "positive": _safe_float(feature_frame.loc[spam_mask, "link_count"].mean()),
            "negative": _safe_float(feature_frame.loc[ham_mask, "link_count"].mean()),
        },
        {
            "id": "exclamation_count",
            "label": "Exclamation count",
            "positive": _safe_float(feature_frame.loc[spam_mask, "exclamation_count"].mean()),
            "negative": _safe_float(feature_frame.loc[ham_mask, "exclamation_count"].mean()),
        },
    ]

    return _build_topic_payload(
        "email",
        "Email",
        source_path,
        distribution,
        {"positive": "Spam", "negative": "Ham"},
        feature_rows,
        _get_email_top_features(),
    )


def get_dataset_insights() -> dict:
    global _dataset_cache_signature, _dataset_cache_payload

    source_paths = [
        maybe_find_asset_path(Path(__file__), "URL", "data", "processed_malicious_url.csv"),
        maybe_find_asset_path(Path(__file__), "FILE", "data", "malware_data_final.csv"),
        _find_email_dataset_path(),
    ]
    signature = tuple(
        (str(path), path.stat().st_mtime_ns, path.stat().st_size) if path else None
        for path in source_paths
    )

    with _dataset_cache_lock:
        if _dataset_cache_signature == signature and _dataset_cache_payload is not None:
            return _dataset_cache_payload

    topics = {
        "url": _load_url_dataset(),
        "file": _load_file_dataset(),
        "email": _load_email_dataset(),
    }

    payload = {"topics": topics}

    with _dataset_cache_lock:
        _dataset_cache_signature = signature
        _dataset_cache_payload = payload

    return payload
