import json
from pathlib import Path
from threading import Lock

from backend.services.asset_paths import maybe_find_asset_path
from backend.services.db_service import get_connection

_stats_lock = Lock()
_stats = {
    "summary": {
        "total_scans": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "safe_count": 0,
    },
    "by_type": {
        "url": {
            "total_scans": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
        },
        "file": {
            "total_scans": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
        },
        "email": {
            "total_scans": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
        },
    },
}


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _build_model_section(report: dict, model_keys: list[str]) -> dict:
    section = {}

    for model_key in model_keys:
        model_metrics = report.get(model_key)

        if not isinstance(model_metrics, dict):
            continue

        section[model_key] = {
            key: value
            for key, value in model_metrics.items()
            if isinstance(value, (int, float))
        }

    return section


def _memory_dashboard_stats() -> dict:
    with _stats_lock:
        return {
            "summary": dict(_stats["summary"]),
            "by_type": {
                key: dict(values) for key, values in _stats["by_type"].items()
            },
            "trend": [],
            "top_countries": [],
            "map_points": [],
            "recent_detections": [],
            "data_source": "memory",
        }


def _fetch_one(cursor, query: str, params: tuple = ()) -> dict:
    cursor.execute(query, params)
    row = cursor.fetchone()
    return row or {}


def _fetch_all(cursor, query: str, params: tuple = ()) -> list[dict]:
    cursor.execute(query, params)
    return cursor.fetchall() or []


def get_dashboard_stats() -> dict:
    try:
        with get_connection() as connection:
            if connection is None:
                return _memory_dashboard_stats()

            with connection.cursor() as cursor:
                summary = _fetch_one(
                    cursor,
                    """
                    SELECT
                        COUNT(*) AS total_scans,
                        SUM(CASE WHEN status = 'threat' THEN 1 ELSE 0 END) AS malicious_count,
                        SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
                        SUM(CASE WHEN status = 'safe' THEN 1 ELSE 0 END) AS safe_count
                    FROM detection_results
                    """,
                )

                by_type_rows = _fetch_all(
                    cursor,
                    """
                    SELECT
                        detection_type,
                        COUNT(*) AS total_scans,
                        SUM(CASE WHEN status = 'threat' THEN 1 ELSE 0 END) AS malicious_count,
                        SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
                        SUM(CASE WHEN status = 'safe' THEN 1 ELSE 0 END) AS safe_count,
                        ROUND(AVG(risk_score), 2) AS avg_risk_score
                    FROM detection_results
                    GROUP BY detection_type
                    """,
                )

                trend_rows = _fetch_all(
                    cursor,
                    """
                    SELECT
                        DATE(created_at) AS day,
                        COUNT(*) AS total_scans,
                        SUM(CASE WHEN status = 'threat' THEN 1 ELSE 0 END) AS threat_count
                    FROM detection_results
                    WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
                    GROUP BY DATE(created_at)
                    ORDER BY day ASC
                    """,
                )

                country_rows = _fetch_all(
                    cursor,
                    """
                    SELECT
                        country_name,
                        country_code,
                        COUNT(*) AS total_scans,
                        SUM(CASE WHEN status = 'threat' THEN 1 ELSE 0 END) AS threat_count
                    FROM detection_results
                    WHERE country_name IS NOT NULL AND country_name <> ''
                    GROUP BY country_name, country_code
                    ORDER BY total_scans DESC
                    LIMIT 6
                    """,
                )

                map_rows = _fetch_all(
                    cursor,
                    """
                    SELECT
                        latitude,
                        longitude,
                        detection_type,
                        status,
                        COUNT(*) AS total_scans
                    FROM detection_results
                    WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                    GROUP BY latitude, longitude, detection_type, status
                    ORDER BY MAX(created_at) DESC
                    LIMIT 150
                    """,
                )

                recent_rows = _fetch_all(
                    cursor,
                    """
                    SELECT
                        id,
                        detection_type,
                        source_value,
                        status,
                        verdict,
                        risk_score,
                        country_name,
                        created_at
                    FROM detection_results
                    ORDER BY created_at DESC
                    LIMIT 8
                    """,
                )

            by_type = {
                "url": {
                    "total_scans": 0,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "safe_count": 0,
                    "avg_risk_score": 0,
                },
                "file": {
                    "total_scans": 0,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "safe_count": 0,
                    "avg_risk_score": 0,
                },
                "email": {
                    "total_scans": 0,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "safe_count": 0,
                    "avg_risk_score": 0,
                },
            }

            for row in by_type_rows:
                detection_type = row.get("detection_type")
                if detection_type in by_type:
                    by_type[detection_type] = {
                        "total_scans": int(row.get("total_scans") or 0),
                        "malicious_count": int(row.get("malicious_count") or 0),
                        "suspicious_count": int(row.get("suspicious_count") or 0),
                        "safe_count": int(row.get("safe_count") or 0),
                        "avg_risk_score": float(row.get("avg_risk_score") or 0),
                    }

            return {
                "summary": {
                    "total_scans": int(summary.get("total_scans") or 0),
                    "malicious_count": int(summary.get("malicious_count") or 0),
                    "suspicious_count": int(summary.get("suspicious_count") or 0),
                    "safe_count": int(summary.get("safe_count") or 0),
                },
                "by_type": by_type,
                "trend": [
                    {
                        "day": str(row.get("day")),
                        "total_scans": int(row.get("total_scans") or 0),
                        "threat_count": int(row.get("threat_count") or 0),
                    }
                    for row in trend_rows
                ],
                "top_countries": [
                    {
                        "country_name": row.get("country_name"),
                        "country_code": row.get("country_code"),
                        "total_scans": int(row.get("total_scans") or 0),
                        "threat_count": int(row.get("threat_count") or 0),
                    }
                    for row in country_rows
                ],
                "map_points": [
                    {
                        "latitude": float(row.get("latitude")),
                        "longitude": float(row.get("longitude")),
                        "detection_type": row.get("detection_type"),
                        "status": row.get("status"),
                        "total_scans": int(row.get("total_scans") or 0),
                    }
                    for row in map_rows
                    if row.get("latitude") is not None and row.get("longitude") is not None
                ],
                "recent_detections": [
                    {
                        "id": row.get("id"),
                        "detection_type": row.get("detection_type"),
                        "source_value": row.get("source_value"),
                        "status": row.get("status"),
                        "verdict": row.get("verdict"),
                        "risk_score": int(row.get("risk_score") or 0),
                        "country_name": row.get("country_name"),
                        "created_at": str(row.get("created_at")),
                    }
                    for row in recent_rows
                ],
                "data_source": "database",
            }
    except Exception:
        return _memory_dashboard_stats()


def get_dashboard_metrics() -> dict:
    url_report = _load_json(
        maybe_find_asset_path(Path(__file__), "URL", "models", "training_report.json")
        or Path("__missing__")
    )
    file_report = _load_json(
        maybe_find_asset_path(Path(__file__), "FILE", "models", "training_report.json")
        or Path("__missing__")
    )
    email_report = _load_json(
        maybe_find_asset_path(Path(__file__), "Email", "models", "training_report.json")
        or Path("__missing__")
    )

    email_selected = email_report.get("selected_model", {})
    email_metrics = email_selected.get("metrics", {}) if isinstance(email_selected, dict) else {}

    return {
        "url": _build_model_section(url_report, ["lightgbm", "xgboost", "ensemble"]),
        "file": _build_model_section(file_report, ["lightgbm", "xgboost", "ensemble"]),
        "email": {
            "selected_model": {
                key: value
                for key, value in email_metrics.items()
                if isinstance(value, (int, float))
            }
        },
    }


def record_scan(scan_type: str, result: dict) -> None:
    if scan_type not in _stats["by_type"]:
        return

    status = str(result.get("status", "")).lower()
    is_malicious = status == "threat" or bool(result.get("is_malicious") or result.get("is_spam"))
    is_suspicious = status == "suspicious"

    summary_key = "safe_count"
    if is_malicious:
        summary_key = "malicious_count"
    elif is_suspicious:
        summary_key = "suspicious_count"

    with _stats_lock:
        _stats["summary"]["total_scans"] += 1
        _stats["summary"][summary_key] += 1
        _stats["by_type"][scan_type]["total_scans"] += 1
        _stats["by_type"][scan_type][summary_key] += 1
