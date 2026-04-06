from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

from backend.services.dashboard_service import record_scan
from backend.services.detection_log_service import save_detection_result
from backend.services.email_service import predict_from_file, predict_from_text
from backend.services.geo_service import get_client_ip, lookup_ip_location

router = APIRouter()


class TextRequest(BaseModel):
    subject: str = ""
    body: str = ""


@router.post("/file")
async def analyze_email_file(request: Request, file: UploadFile = File(...)):
    raw = await file.read()
    try:
        result = predict_from_file(file.filename or "upload.eml", raw)
    except FileNotFoundError as exc:
        raise HTTPException(
            503,
            "Email detection model is unavailable on the server. Verify the Email/models deployment bundle.",
        ) from exc
    record_scan("email", result)
    save_detection_result(
        detection_type="email",
        result=result,
        location=lookup_ip_location(get_client_ip(request)),
        session_id=request.headers.get("x-session-id"),
    )
    return result


@router.post("/text")
def analyze_email_text(payload: TextRequest, request: Request):
    if not payload.subject and not payload.body:
        raise HTTPException(400, "Please provide an email subject or body before starting the scan.")

    try:
        result = predict_from_text(payload.subject, payload.body)
    except FileNotFoundError as exc:
        raise HTTPException(
            503,
            "Email detection model is unavailable on the server. Verify the Email/models deployment bundle.",
        ) from exc
    record_scan("email", result)
    save_detection_result(
        detection_type="email",
        result=result,
        location=lookup_ip_location(get_client_ip(request)),
        session_id=request.headers.get("x-session-id"),
    )
    return result
