from typing import Literal

from fastapi import APIRouter, Query
from backend.services.dashboard_service import (
    get_dashboard_metrics,
    get_dashboard_stats,
)
from backend.services.dataset_insights_service import get_dataset_insights


router = APIRouter()


@router.get("/stats")
def dashboard_stats(range: Literal["week", "month"] = Query(default="week")):
    return get_dashboard_stats(range_name=range)


@router.get("/model-metrics")
def dashboard_model_metrics():
    return get_dashboard_metrics()


@router.get("/dataset-insights")
def dashboard_dataset_insights():
    return get_dataset_insights()
