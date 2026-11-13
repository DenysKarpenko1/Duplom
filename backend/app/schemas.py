"""Схеми запитів і відповідей API (валідація вхідних даних)."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskCreate(BaseModel):
    """Дані, які надсилає форма «Введення даних»."""

    asset: str = Field(min_length=1, max_length=200)
    threat: str = Field(min_length=1, max_length=200)
    vulnerability: str = Field(min_length=1, max_length=300)
    probability: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)


class RiskOut(RiskCreate):
    """Ризик разом із результатами розрахунку."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    score: int
    level: str
    created_at: datetime
