from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from backend.services.dashboard_service import record_scan
from backend.services.email_service import predict_from_file, predict_from_text

router = APIRouter()

class TextRequest(BaseModel):
    subject: str = ""
    body: str    = ""

@router.post("/file")
async def analyze_email_file(file: UploadFile = File(...)):
    raw = await file.read()
    result = predict_from_file(file.filename or "upload.eml", raw)
    record_scan("email", result)
    return result

@router.post("/text")
def analyze_email_text(payload: TextRequest):
    if not payload.subject and not payload.body:
        raise HTTPException(400, "Cần có subject hoặc body")
    result = predict_from_text(payload.subject, payload.body)
    record_scan("email", result)
    return result
