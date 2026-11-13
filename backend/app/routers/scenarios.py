"""Сценарії ризику, застосовані заходи захисту та історія оцінювань."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..services import get_or_404, load_many, matrix_assessment

router = APIRouter(prefix="/api/scenarios")


def _set_measures(db: Session, scenario: models.RiskScenario,
                  items: list[schemas.ScenarioMeasureIn]) -> None:
    measures = {m.id: m for m in load_many(db, models.ProtectiveMeasure,
                                           [i.measure_id for i in items], "Заходи захисту")}
    scenario.measure_links = [
        models.ScenarioMeasure(measure=measures[i.measure_id], status=i.status) for i in items]


@router.get("", response_model=list[schemas.ScenarioOut])
def list_scenarios(db: Session = Depends(get_db)):
    return db.scalars(select(models.RiskScenario).order_by(models.RiskScenario.id)).all()


@router.get("/{scenario_id}", response_model=schemas.ScenarioOut)
def get_scenario(scenario_id: int, db: Session = Depends(get_db)):
    return get_or_404(db, models.RiskScenario, scenario_id, "Сценарій")


@router.post("", response_model=schemas.ScenarioOut, status_code=201)
def create_scenario(payload: schemas.ScenarioIn, db: Session = Depends(get_db)):
    key = (payload.asset_id, payload.threat_id, payload.vulnerability_id)
    get_or_404(db, models.Asset, key[0], "ІТ-актив")
    get_or_404(db, models.Threat, key[1], "Загрозу")
    get_or_404(db, models.Vulnerability, key[2], "Вразливість")
    exists = db.scalar(select(models.RiskScenario).where(
        models.RiskScenario.asset_id == key[0], models.RiskScenario.threat_id == key[1],
        models.RiskScenario.vulnerability_id == key[2]))
    if exists:
        raise HTTPException(status_code=409, detail=f"Такий сценарій уже існує (id={exists.id})")
    scenario = models.RiskScenario(asset_id=key[0], threat_id=key[1], vulnerability_id=key[2],
                                   description=payload.description)
    _set_measures(db, scenario, payload.measures)
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@router.put("/{scenario_id}/measures", response_model=schemas.ScenarioOut)
def replace_measures(scenario_id: int, items: list[schemas.ScenarioMeasureIn],
                     db: Session = Depends(get_db)):
    scenario = get_or_404(db, models.RiskScenario, scenario_id, "Сценарій")
    _set_measures(db, scenario, items)
    db.commit()
    db.refresh(scenario)
    return scenario


@router.delete("/{scenario_id}", status_code=204)
def delete_scenario(scenario_id: int, db: Session = Depends(get_db)):
    db.delete(get_or_404(db, models.RiskScenario, scenario_id, "Сценарій"))
    db.commit()


@router.get("/{scenario_id}/assessments", response_model=list[schemas.AssessmentOut])
def list_assessments(scenario_id: int, db: Session = Depends(get_db)):
    return get_or_404(db, models.RiskScenario, scenario_id, "Сценарій").assessments


@router.post("/{scenario_id}/assessments", response_model=schemas.AssessmentOut,
             status_code=201)
def create_assessment(scenario_id: int, payload: schemas.AssessmentIn,
                      db: Session = Depends(get_db)):
    scenario = get_or_404(db, models.RiskScenario, scenario_id, "Сценарій")
    assessment = matrix_assessment(db, scenario, payload.probability, payload.impact,
                                   payload.notes)
    db.commit()
    db.refresh(assessment)
    return assessment
