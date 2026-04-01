from fastapi import APIRouter
from backend.services.dashboard_service import (
    get_dashboard_metrics,
    get_dashboard_stats,
)


router = APIRouter()


@router.get("/stats")
def dashboard_stats():
    return get_dashboard_stats()


@router.get("/model-metrics")
def dashboard_model_metrics():
    return get_dashboard_metrics()
