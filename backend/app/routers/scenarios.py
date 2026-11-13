"""Сценарії ризику, застосовані заходи захисту та історія оцінювань."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..assessment import (combined_assessment, evaluate_combined, matrix_assessment, save_tree,
                          tree_from_db)
from ..core import attack_tree as at
from ..database import get_db
from ..services import get_or_404, load_many

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
    if payload.method == "combined":
        assessment = combined_assessment(db, scenario, payload.impact, payload.notes)
    else:
        assessment = matrix_assessment(db, scenario, payload.probability, int(payload.impact),
                                       payload.notes)
    db.commit()
    db.refresh(assessment)
    return assessment


# ------------------------------------------------------------------ дерево атак
def _to_core(node: schemas.AttackNodeIn) -> at.AttackNode:
    return at.AttackNode(name=node.name, gate=at.Gate(node.gate), probability=node.probability,
                         vulnerability_id=node.vulnerability_id,
                         children=[_to_core(c) for c in node.children])


def _collect_vuln_ids(node: schemas.AttackNodeIn) -> list[int]:
    ids = [node.vulnerability_id] if node.vulnerability_id is not None else []
    for c in node.children:
        ids += _collect_vuln_ids(c)
    return ids


def _tree_out(scenario: models.RiskScenario) -> schemas.AttackTreeOut:
    _, custom = tree_from_db(scenario)
    r = evaluate_combined(scenario)
    g, res_g = r.tree.graph, r.residual_tree.graph
    cut_sets = at.minimal_cut_sets(g, r.tree.root)
    critical = r.tree.critical_nodes()

    def node_out(nid: int) -> schemas.AttackNodeOut:
        d = g.nodes[nid]
        return schemas.AttackNodeOut(
            name=d["name"], gate=d["gate"].value, probability=d["probability"],
            vulnerability_id=d["vulnerability_id"], computed=round(d["computed"], 6),
            residual=round(res_g.nodes[nid]["computed"], 6), on_critical_path=nid in critical,
            children=[node_out(c) for c in g.successors(nid)])

    def fuzzy_out(f) -> schemas.FuzzyOut:
        return schemas.FuzzyOut(score=f.score, nist_level=f.nist_level.label,
                                activations={k.label: round(v, 4) for k, v in f.activations.items()})

    return schemas.AttackTreeOut(
        scenario_id=scenario.id, custom=custom, root=node_out(r.tree.root),
        likelihood=round(r.likelihood, 6), likelihood_level=r.likelihood_level.label,
        residual_likelihood=round(r.residual_likelihood, 6), impact=r.impact,
        inherent=fuzzy_out(r.inherent), residual=fuzzy_out(r.residual),
        risk_reduction=round(r.risk_reduction, 4), most_likely_path=r.most_likely_path,
        minimal_cut_sets=sorted([sorted(g.nodes[n]["name"] for n in s) for s in cut_sets]))


@router.get("/{scenario_id}/attack-tree", response_model=schemas.AttackTreeOut)
def get_attack_tree(scenario_id: int, db: Session = Depends(get_db)):
    """Дерево атак сценарію з обчисленими ймовірностями та нечіткою оцінкою ризику."""
    return _tree_out(get_or_404(db, models.RiskScenario, scenario_id, "Сценарій"))


@router.put("/{scenario_id}/attack-tree", response_model=schemas.AttackTreeOut)
def put_attack_tree(scenario_id: int, root: schemas.AttackNodeIn, db: Session = Depends(get_db)):
    """Замінює дерево атак сценарію."""
    scenario = get_or_404(db, models.RiskScenario, scenario_id, "Сценарій")
    load_many(db, models.Vulnerability, _collect_vuln_ids(root), "Вразливості")
    try:
        core = _to_core(root)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    save_tree(db, scenario, core)
    db.commit()
    db.refresh(scenario)
    return _tree_out(scenario)


@router.delete("/{scenario_id}/attack-tree", response_model=schemas.AttackTreeOut)
def reset_attack_tree(scenario_id: int, db: Session = Depends(get_db)):
    """Видаляє власне дерево — сценарій оцінюється типовим деревом."""
    scenario = get_or_404(db, models.RiskScenario, scenario_id, "Сценарій")
    save_tree(db, scenario, None)
    db.commit()
    db.refresh(scenario)
    return _tree_out(scenario)
