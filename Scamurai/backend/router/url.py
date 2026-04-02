from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from backend.services.dashboard_service import record_scan
from backend.services.detection_log_service import save_detection_result
from backend.services.geo_service import get_client_ip, lookup_ip_location
from backend.services.url_service import predict_url

router = APIRouter()


class UrlRequest(BaseModel):
    url: str


@router.post("")
def analyze_url(payload: UrlRequest, request: Request):
    if not payload.url:
        raise HTTPException(400, "URL khong duoc de trong")

    result = predict_url(payload.url)
    record_scan("url", result)
    save_detection_result(
        detection_type="url",
        result=result,
        location=lookup_ip_location(get_client_ip(request)),
        session_id=request.headers.get("x-session-id"),
    )
    return result
