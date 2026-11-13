"""Сумісний з MVP плаский API /api/risks поверх нормалізованої схеми.

Один «ризик» = сценарій + його остання оцінка. Залишено, щоб фронтенд MVP
працював без змін до оновлення в Етапі 3.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from .. import models, schemas
from ..database import get_db
from ..services import get_or_404, get_or_create_by_name, matrix_assessment

router = APIRouter(prefix="/api/risks")


def _flatten(scenario: models.RiskScenario, a: models.RiskAssessment) -> schemas.RiskOut:
    return schemas.RiskOut(
        id=scenario.id, asset=scenario.asset.name, threat=scenario.threat.name,
        vulnerability=scenario.vulnerability.name, probability=a.probability,
        impact=a.impact, score=float(a.score), level=a.level.name, created_at=a.assessed_at)


@router.get("", response_model=list[schemas.RiskOut])
def list_risks(db: Session = Depends(get_db)):
    """Усі сценарії з останньою оцінкою, від найнебезпечнішого до найменш небезпечного."""
    latest = (select(models.RiskAssessment.scenario_id,
                     func.max(models.RiskAssessment.id).label("aid"))
              .group_by(models.RiskAssessment.scenario_id).subquery())
    rows = db.execute(
        select(models.RiskScenario, models.RiskAssessment)
        .join(latest, latest.c.scenario_id == models.RiskScenario.id)
        .join(models.RiskAssessment, models.RiskAssessment.id == latest.c.aid)
        .options(joinedload(models.RiskScenario.asset), joinedload(models.RiskScenario.threat),
                 joinedload(models.RiskScenario.vulnerability),
                 joinedload(models.RiskAssessment.level))
        .order_by(models.RiskAssessment.score.desc(), models.RiskScenario.id)
    ).all()
    return [_flatten(s, a) for s, a in rows]


@router.post("", response_model=schemas.RiskOut, status_code=201)
def create_risk(payload: schemas.RiskCreate, db: Session = Depends(get_db)):
    """Додає оцінку; відсутні актив/загроза/вразливість створюються в довідниках."""
    asset = get_or_create_by_name(db, models.Asset, payload.asset)
    threat = get_or_create_by_name(db, models.Threat, payload.threat)
    vuln = get_or_create_by_name(db, models.Vulnerability, payload.vulnerability)
    if vuln not in threat.vulnerabilities:
        threat.vulnerabilities.append(vuln)
    if vuln not in asset.vulnerabilities:
        asset.vulnerabilities.append(vuln)
    scenario = db.scalar(select(models.RiskScenario).where(
        models.RiskScenario.asset_id == asset.id, models.RiskScenario.threat_id == threat.id,
        models.RiskScenario.vulnerability_id == vuln.id))
    if scenario is None:
        scenario = models.RiskScenario(asset=asset, threat=threat, vulnerability=vuln)
        db.add(scenario)
    assessment = matrix_assessment(db, scenario, payload.probability, payload.impact)
    db.commit()
    return _flatten(scenario, assessment)


@router.delete("/{risk_id}", status_code=204)
def delete_risk(risk_id: int, db: Session = Depends(get_db)):
    """Видаляє сценарій разом з історією його оцінювань."""
    db.delete(get_or_404(db, models.RiskScenario, risk_id, "Ризик"))
    db.commit()
