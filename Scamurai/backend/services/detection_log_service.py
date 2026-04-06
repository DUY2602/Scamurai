import logging

from backend.services.supabase_service import (
    build_detection_payload,
    insert_detection_result as insert_supabase_detection_result,
    is_supabase_enabled,
)

logger = logging.getLogger(__name__)


def save_detection_result(
    detection_type: str,
    result: dict,
    location: dict | None = None,
    session_id: str | None = None,
) -> None:
    location = location or {}
    payload = build_detection_payload(
        detection_type=detection_type,
        result=result,
        location=location,
        session_id=session_id,
    )

    if is_supabase_enabled():
        if insert_supabase_detection_result(payload):
            return
        logger.warning("Skipping detection log write for %s after Supabase insert failure.", detection_type)
        return

    logger.info("Skipping detection log write for %s because Supabase is not configured.", detection_type)
