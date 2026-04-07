from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from backend.services.dashboard_service import record_scan
from backend.services.detection_log_service import save_detection_result
from backend.services.geo_service import get_client_ip, lookup_ip_location
from backend.services.url_service import predict_url, submit_url_feedback

router = APIRouter()


class UrlRequest(BaseModel):
    url: str


class UrlFeedbackRequest(BaseModel):
    url: str
    verdict: str


@router.post("")
def analyze_url(payload: UrlRequest, request: Request):
    if not payload.url:
        raise HTTPException(400, "Please provide a URL before starting the scan.")

    result = predict_url(payload.url)
    record_scan("url", result)
    save_detection_result(
        detection_type="url",
        result=result,
        location=lookup_ip_location(get_client_ip(request)),
        session_id=request.headers.get("x-session-id"),
    )
    return result


@router.post("/feedback")
def submit_feedback(payload: UrlFeedbackRequest):
    if not payload.url:
        raise HTTPException(400, "Please provide a URL before sending feedback.")

    try:
        result = submit_url_feedback(payload.url, payload.verdict)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    return {
        "status": "ok",
        "message": "URL feedback saved successfully.",
        **result,
    }
