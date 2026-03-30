"""Pydantic schema models for API requests."""

from __future__ import annotations

from pydantic import BaseModel


class AnalyzeTextRequest(BaseModel):
    """Request body for manual subject/body analysis."""

    subject: str = ""
    body: str = ""
