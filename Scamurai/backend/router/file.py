from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from backend.services.dashboard_service import record_scan
from backend.services.detection_log_service import save_detection_result
from backend.services.file_service import FileScanError, predict_file
from backend.services.geo_service import get_client_ip, lookup_ip_location

router = APIRouter()


@router.post("")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, "The uploaded file is missing a filename.")

    raw = await file.read()
    if not raw:
        raise HTTPException(400, "The uploaded file is empty.")

    try:
        result = predict_file(file.filename, raw)
    except FileScanError as exc:
        raise HTTPException(400, str(exc)) from exc

    record_scan("file", result)
    save_detection_result(
        detection_type="file",
        result=result,
        location=lookup_ip_location(get_client_ip(request)),
        session_id=request.headers.get("x-session-id"),
    )
    return result
