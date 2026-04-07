from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from backend.services.dashboard_service import record_scan
from backend.services.detection_log_service import save_detection_result
from backend.services.file_service import FileScanError, predict_file
from backend.services.geo_service import get_client_ip, lookup_ip_location
from backend.services.upload_validator import (
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    MAX_FILE_SIZE_BYTES,
    UploadValidationError,
    validate_upload_file,
)

router = APIRouter()


@router.post("")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    """
    Analyze uploaded file for malware detection.
    
    Validates file before processing:
    - Checks filename
    - Enforces file size limit (100 MB)
    - Validates file extension and MIME type
    """
    # Read file bytes
    raw = await file.read()
    
    # Validate upload
    try:
        validate_upload_file(
            file,
            raw,
            max_size_bytes=MAX_FILE_SIZE_BYTES,
            allowed_extensions=ALLOWED_EXTENSIONS,
            allowed_mime_types=ALLOWED_MIME_TYPES,
        )
    except UploadValidationError as exc:
        raise HTTPException(400, f"Upload validation failed: {str(exc)}") from exc

    # Perform malware detection
    try:
        result = predict_file(file.filename, raw)
    except FileScanError as exc:
        raise HTTPException(400, str(exc)) from exc

    # Record and persist detection results
    record_scan("file", result)
    save_detection_result(
        detection_type="file",
        result=result,
        location=lookup_ip_location(get_client_ip(request)),
        session_id=request.headers.get("x-session-id"),
    )
    return result
