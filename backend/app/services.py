"""Допоміжні операції над БД, спільні для кількох ендпоінтів."""
from decimal import Decimal

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .risk_core import risk_score


def get_or_404(db: Session, model, obj_id: int, what: str = "Запис"):
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{what} не знайдено (id={obj_id})")
    return obj


def load_many(db: Session, model, ids: list[int], what: str) -> list:
    """Завантажує записи за списком id; 422, якщо якогось немає."""
    ids = list(dict.fromkeys(ids))
    if not ids:
        return []
    found = db.scalars(select(model).where(model.id.in_(ids))).all()
    missing = set(ids) - {o.id for o in found}
    if missing:
        raise HTTPException(status_code=422, detail=f"{what}: не існують id {sorted(missing)}")
    return list(found)


def level_for_score(db: Session, score: Decimal | float | int) -> models.RiskLevel:
    """Рівень ризику з довідника risk_levels, у діапазон якого потрапляє бал."""
    levels = db.scalars(select(models.RiskLevel).order_by(models.RiskLevel.max_score)).all()
    if not levels:
        raise HTTPException(status_code=500, detail="Довідник risk_levels порожній")
    for level in levels:
        if score <= level.max_score:
            return level
    return levels[-1]


def matrix_assessment(db: Session, scenario: models.RiskScenario, probability: int,
                      impact: int, notes: str | None = None) -> models.RiskAssessment:
    """Оцінювання базовим матричним методом (Risk = P × I)."""
    score = Decimal(risk_score(probability, impact))
    assessment = models.RiskAssessment(
        method="matrix", probability=probability, impact=impact, score=score,
        level=level_for_score(db, score), notes=notes)
    scenario.assessments.append(assessment)
    return assessment


def get_or_create_by_name(db: Session, model, name: str):
    obj = db.scalar(select(model).where(model.name == name))
    if obj is None:
        obj = model(name=name)
        db.add(obj)
        db.flush()
    return obj
