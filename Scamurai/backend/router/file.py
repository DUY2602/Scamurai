from fastapi import APIRouter, UploadFile, File, HTTPException
from backend.services.dashboard_service import record_scan
from backend.services.file_service import predict_file

router = APIRouter()

@router.post("/")
async def analyze_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, "File không có tên")
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "File rỗng")
    result = predict_file(file.filename, raw)
    record_scan("file", result)
    return result
