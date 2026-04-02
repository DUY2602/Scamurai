from backend.services.db_service import get_connection


def save_detection_result(
    detection_type: str,
    result: dict,
    location: dict | None = None,
    session_id: str | None = None,
) -> None:
    location = location or {}

    query = """
        INSERT INTO detection_results (
            session_id,
            detection_type,
            source_value,
            status,
            verdict,
            is_malicious,
            is_suspicious,
            risk_score,
            confidence,
            country_code,
            country_name,
            city,
            latitude,
            longitude
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
    """

    values = (
        session_id,
        detection_type,
        result.get("source_value"),
        result.get("status"),
        result.get("verdict"),
        bool(result.get("is_malicious") or result.get("is_spam")),
        bool(result.get("is_suspicious")),
        int(float(result.get("risk_score", 0) or 0)),
        float(result.get("confidence", 0) or 0),
        location.get("country_code"),
        location.get("country_name"),
        location.get("city"),
        location.get("latitude"),
        location.get("longitude"),
    )

    try:
        with get_connection() as connection:
            if connection is None:
                return

            with connection.cursor() as cursor:
                cursor.execute(query, values)
    except Exception:
        return
