import logging
import math
import os
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def _supabase_config() -> dict | None:
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv(
        "SUPABASE_ANON_KEY", ""
    ).strip()
    table = os.getenv("SUPABASE_TABLE", "detection_results").strip() or "detection_results"

    if not url or not key:
        return None

    return {
        "url": url.rstrip("/"),
        "key": key,
        "table": table,
        "timeout": int(os.getenv("SUPABASE_TIMEOUT", "8")),
        "page_size": int(os.getenv("SUPABASE_PAGE_SIZE", "1000")),
    }


def is_supabase_enabled() -> bool:
    return _supabase_config() is not None


def _headers(config: dict, *, prefer: str | None = None) -> dict:
    headers = {
        "apikey": config["key"],
        "Authorization": f"Bearer {config['key']}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


def _table_url(config: dict) -> str:
    return f"{config['url']}/rest/v1/{config['table']}"


def build_detection_payload(
    detection_type: str,
    result: dict,
    location: dict | None = None,
    session_id: str | None = None,
) -> dict:
    location = location or {}

    return {
        "session_id": session_id,
        "detection_type": detection_type,
        "source_value": result.get("source_value"),
        "status": result.get("status"),
        "verdict": result.get("verdict"),
        "is_malicious": bool(result.get("is_malicious") or result.get("is_spam")),
        "is_suspicious": bool(result.get("is_suspicious")),
        "risk_score": int(float(result.get("risk_score", 0) or 0)),
        "confidence": float(result.get("confidence", 0) or 0),
        "country_code": location.get("country_code"),
        "country_name": location.get("country_name"),
        "city": location.get("city"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
    }


def insert_detection_result(payload: dict) -> bool:
    config = _supabase_config()
    if not config:
        return False

    try:
        request = Request(
            _table_url(config),
            data=json.dumps(payload).encode("utf-8"),
            headers=_headers(config, prefer="return=minimal"),
            method="POST",
        )
        with urlopen(request, timeout=config["timeout"]):
            pass
        return True
    except Exception as exc:
        logger.warning("Supabase insert failed: %s", exc)
        return False


def fetch_detection_rows() -> list[dict]:
    config = _supabase_config()
    if not config:
        return []

    rows: list[dict] = []
    offset = 0
    page_size = max(1, config["page_size"])
    select_fields = ",".join(
        [
            "id",
            "detection_type",
            "source_value",
            "status",
            "verdict",
            "risk_score",
            "confidence",
            "country_name",
            "country_code",
            "city",
            "latitude",
            "longitude",
            "created_at",
        ]
    )

    try:
        while True:
            query = urlencode(
                {
                    "select": select_fields,
                    "order": "created_at.desc",
                }
            )
            request = Request(
                f"{_table_url(config)}?{query}",
                headers={
                    **_headers(config),
                    "Range-Unit": "items",
                    "Range": f"{offset}-{offset + page_size - 1}",
                },
                method="GET",
            )
            with urlopen(request, timeout=config["timeout"]) as response:
                batch = json.loads(response.read().decode("utf-8") or "[]")
            if not isinstance(batch, list):
                return rows

            rows.extend(batch)
            if len(batch) < page_size:
                break

            offset += page_size
    except Exception as exc:
        logger.warning("Supabase read failed: %s", exc)
        return []

    return rows


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _parse_timestamp(value) -> datetime | None:
    if not value:
        return None

    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _normalize_dashboard_range(range_name: str | None) -> int:
    return 30 if str(range_name or "").lower() == "month" else 7


def _build_tick_step(max_value: int) -> int:
    if max_value <= 5:
        return 1

    rough_step = max_value / 4
    magnitude = 10 ** math.floor(math.log10(max(rough_step, 1)))
    normalized = rough_step / magnitude

    if normalized <= 1:
        nice = 1
    elif normalized <= 2:
        nice = 2
    elif normalized <= 5:
        nice = 5
    else:
        nice = 10

    return max(1, int(nice * magnitude))


def _build_y_ticks(max_value: int) -> list[int]:
    step = _build_tick_step(max_value)
    ceiling = max(step, int(math.ceil(max_value / step) * step))
    ticks = list(range(0, ceiling + step, step))

    if len(ticks) < 3:
        ticks = [0, step, step * 2]

    return ticks


def build_dashboard_stats(rows: list[dict], range_name: str = "week") -> dict:
    range_days = _normalize_dashboard_range(range_name)
    summary = {
        "total_scans": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "safe_count": 0,
    }
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
    risk_sums = defaultdict(float)
    trend_buckets: dict[str, dict] = {}
    country_buckets: dict[tuple[str, str], dict] = {}
    map_buckets: dict[tuple[float, float, str, str, str], dict] = {}
    recent_detections = []
    now_utc = datetime.now(timezone.utc)
    trend_dates = [
        (now_utc - timedelta(days=offset)).date()
        for offset in range(range_days - 1, -1, -1)
    ]
    trend_date_set = set(trend_dates)

    sorted_rows = sorted(
        rows,
        key=lambda row: _parse_timestamp(row.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    for index, row in enumerate(sorted_rows):
        status = str(row.get("status") or "").lower()
        detection_type = str(row.get("detection_type") or "").lower()
        risk_score = _safe_float(row.get("risk_score"), 0)
        created_at = _parse_timestamp(row.get("created_at"))

        summary["total_scans"] += 1
        summary_key = "safe_count"
        if status == "threat":
            summary_key = "malicious_count"
        elif status == "suspicious":
            summary_key = "suspicious_count"
        summary[summary_key] += 1

        if detection_type in by_type:
            by_type[detection_type]["total_scans"] += 1
            by_type[detection_type][summary_key] += 1
            risk_sums[detection_type] += risk_score

        if created_at and created_at.date() in trend_date_set:
            day_key = created_at.date().isoformat()
            bucket = trend_buckets.setdefault(
                day_key,
                {"day": day_key, "total_scans": 0, "threat_count": 0},
            )
            bucket["total_scans"] += 1
            if status == "threat":
                bucket["threat_count"] += 1

        country_name = row.get("country_name")
        country_code = row.get("country_code")
        if country_name:
            country_key = (str(country_name), str(country_code or ""))
            bucket = country_buckets.setdefault(
                country_key,
                {
                    "country_name": country_name,
                    "country_code": country_code,
                    "total_scans": 0,
                    "threat_count": 0,
                    "by_type": {
                        "url": {"total_scans": 0, "threat_count": 0},
                        "file": {"total_scans": 0, "threat_count": 0},
                        "email": {"total_scans": 0, "threat_count": 0},
                    },
                },
            )
            bucket["total_scans"] += 1
            if status == "threat":
                bucket["threat_count"] += 1
            if detection_type in bucket["by_type"]:
                bucket["by_type"][detection_type]["total_scans"] += 1
                if status == "threat":
                    bucket["by_type"][detection_type]["threat_count"] += 1

        latitude = row.get("latitude")
        longitude = row.get("longitude")
        if latitude is not None and longitude is not None:
            lat = _safe_float(latitude, None)
            lng = _safe_float(longitude, None)
            if lat is not None and lng is not None:
                map_key = (
                    lat,
                    lng,
                    str(country_name or ""),
                    str(country_code or ""),
                    f"{detection_type}:{status}",
                )
                bucket = map_buckets.setdefault(
                    map_key,
                    {
                        "latitude": lat,
                        "longitude": lng,
                        "country_name": country_name,
                        "country_code": country_code,
                        "detection_type": detection_type,
                        "status": status,
                        "total_scans": 0,
                    },
                )
                bucket["total_scans"] += 1

        if index < 8:
            recent_detections.append(
                {
                    "id": row.get("id"),
                    "detection_type": row.get("detection_type"),
                    "source_value": row.get("source_value"),
                    "status": row.get("status"),
                    "verdict": row.get("verdict"),
                    "risk_score": _safe_int(row.get("risk_score"), 0),
                    "country_name": row.get("country_name"),
                    "created_at": str(row.get("created_at")),
                }
            )

    for detection_type, values in by_type.items():
        total = values["total_scans"]
        values["avg_risk_score"] = round(risk_sums[detection_type] / total, 2) if total else 0

    trend = []
    max_trend_value = 0
    for trend_date in trend_dates:
        day_key = trend_date.isoformat()
        bucket = trend_buckets.get(
            day_key,
            {"day": day_key, "total_scans": 0, "threat_count": 0},
        )
        max_trend_value = max(
            max_trend_value,
            _safe_int(bucket.get("total_scans"), 0),
            _safe_int(bucket.get("threat_count"), 0),
        )
        trend.append(bucket)

    country_stats = sorted(
        country_buckets.values(),
        key=lambda item: item["total_scans"],
        reverse=True,
    )
    top_countries = country_stats[:6]
    map_points = sorted(
        map_buckets.values(),
        key=lambda item: item["total_scans"],
        reverse=True,
    )[:150]

    return {
        "summary": summary,
        "by_type": by_type,
        "trend": trend,
        "country_stats": country_stats,
        "top_countries": top_countries,
        "map_points": map_points,
        "recent_detections": recent_detections,
        "trend_range": "month" if range_days == 30 else "week",
        "trend_days": range_days,
        "trend_meta": {
            "max_value": max_trend_value,
            "y_ticks": _build_y_ticks(max_trend_value),
        },
        "data_source": "supabase",
    }
