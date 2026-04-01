from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.services.dashboard_service import record_scan
from backend.services.url_service import predict_url

router = APIRouter()


class UrlRequest(BaseModel):
    url: str
    
@router.post("")
def analyze_url(payload: UrlRequest):
    if not payload.url:
        raise HTTPException(400, "URL không được để trống")
    result = predict_url(payload.url)
    record_scan("url", result)
    return result
