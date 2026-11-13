"""Модель бази даних."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class Risk(Base):
    """Сценарій ризику: актив + загроза + вразливість та їхні оцінки."""

    __tablename__ = "risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset: Mapped[str] = mapped_column(String(200))
    threat: Mapped[str] = mapped_column(String(200))
    vulnerability: Mapped[str] = mapped_column(String(300))
    probability: Mapped[int] = mapped_column(Integer)  # імовірність, 1..5
    impact: Mapped[int] = mapped_column(Integer)  # вплив (збиток), 1..5
    score: Mapped[int] = mapped_column(Integer)  # бал ризику, 1..25
    level: Mapped[str] = mapped_column(String(20))  # якісний рівень
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
