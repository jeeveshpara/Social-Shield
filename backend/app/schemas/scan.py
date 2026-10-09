from datetime import datetime

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=50)


class ScanResponse(BaseModel):
    id: int
    target: str
    platform: str
    risk_score: int
    risk_level: str
    findings: list
    evidence: dict = {}
    created_at: datetime