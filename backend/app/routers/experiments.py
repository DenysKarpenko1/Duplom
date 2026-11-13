"""Експериментальне порівняння: базова матрична модель vs комбінований метод.

Обидві моделі обчислюються «наживо» за поточним станом БД (нічого не записується),
тож експеримент можна повторювати після зміни довідників, дерев чи заходів.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..assessment import evaluate_combined, scenario_impact, scenario_measures, tree_from_db
from ..core import attack_tree as at
from ..core.combined import Measure, assess, matrix_residual
from ..core.comparison import LEVEL_ORDER, ModelScores, compare
from ..database import get_db
from ..risk_core import matrix_probability, risk_level, risk_score

router = APIRouter(prefix="/api/experiments")


def _matrix_inputs(s: models.RiskScenario) -> tuple[int, int, str]:
    """P та I матричної моделі: остання експертна оцінка або правило з вихідних даних."""
    last = next((a for a in reversed(s.assessments) if a.method == "matrix"), None)
    if last:
        return last.probability, last.impact, "експертна оцінка"
    impact = round(scenario_impact(s))
    return matrix_probability(s.threat.base_likelihood, s.vulnerability.severity), impact, \
        "правило ⌈(L+S)/2⌉"


def _matrix(p: int, i: int, measures: list[Measure]) -> tuple[float, float]:
    _, residual = matrix_residual(p, i, [m.effectiveness for m in measures if m.implemented])
    return float(risk_score(p, i)), float(residual)


def _level(score: float) -> str:
    # межі рівнів системи (risk_levels): <=4, <=9, <=14, інакше критичний
    return risk_level(round(score, 2)) if score >= 1 else LEVEL_ORDER[0]


@router.get("/comparison")
def comparison(top_n: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    scenarios = db.scalars(select(models.RiskScenario).order_by(models.RiskScenario.id)).all()
    rows = []
    a_scores, a_levels, a_res, a_res_levels = [], [], [], []
    b_scores, b_levels, b_res, b_res_levels = [], [], [], []
    trees = {}

    for s in scenarios:
        p, i, source = _matrix_inputs(s)
        measures = scenario_measures(s)
        m_score, m_res = _matrix(p, i, measures)
        c = evaluate_combined(s)
        tree, custom = tree_from_db(s)
        graph, root = at.build_graph(tree)
        trees[s.id] = (tree, c.impact, p, i, measures)
        cut_sets = at.minimal_cut_sets(graph, root)
        row = {
            "id": s.id, "asset": s.asset.name, "threat": s.threat.name,
            "vulnerability": s.vulnerability.name,
            "matrix": {"probability": p, "impact": i, "source": source, "score": m_score,
                       "level": _level(m_score), "residual": m_res, "residual_level": _level(m_res)},
            "combined": {"likelihood": round(c.likelihood, 4),
                         "likelihood_level": c.likelihood_level.label,
                         "residual_likelihood": round(c.residual_likelihood, 4),
                         "impact": c.impact, "score": c.inherent.score,
                         "nist_level": c.inherent.nist_level.label,
                         "level": _level(c.inherent.score), "residual": c.residual.score,
                         "residual_level": _level(c.residual.score)},
            "tree": {"custom": custom, "nodes": graph.number_of_nodes(),
                     "leaves": sum(1 for n in graph if graph.out_degree(n) == 0),
                     "attack_paths": len(cut_sets), "most_likely_path": c.most_likely_path},
            "measures": {"implemented": sum(m.implemented for m in measures),
                         "planned": sum(not m.implemented for m in measures)},
        }
        rows.append(row)
        for target, value in ((a_scores, m_score), (a_levels, row["matrix"]["level"]),
                              (a_res, m_res), (a_res_levels, row["matrix"]["residual_level"]),
                              (b_scores, c.inherent.score), (b_levels, row["combined"]["level"]),
                              (b_res, c.residual.score),
                              (b_res_levels, row["combined"]["residual_level"])):
            target.append(value)

    result = compare(ModelScores(a_scores, a_levels, a_res, a_res_levels),
                     ModelScores(b_scores, b_levels, b_res, b_res_levels), top_n=top_n)
    return {
        "scenarios": rows,
        "summary": {"matrix": result["a"], "combined": result["b"]},
        "agreement": result["agreement"],
        "levels": list(LEVEL_ORDER),
        "measures": _measure_effects(db, trees),
    }


def _measure_effects(db: Session, trees: dict) -> list[dict]:
    """Індивідуальний ефект кожного заходу: сумарне зниження ризику, якщо впровадити лише його.

    Застосовність заходу до сценарію — за прив'язкою scenario_measures.
    """
    effects = []
    for measure in db.scalars(select(models.ProtectiveMeasure).order_by(models.ProtectiveMeasure.id)):
        only = Measure(measure.name, float(measure.effectiveness),
                       {v.id for v in measure.vulnerabilities})
        d_matrix = d_combined = 0.0
        scenarios = 0
        for tree, impact, p, i, measures in trees.values():
            if not any(m.name == measure.name for m in measures):
                continue
            scenarios += 1
            base_m, res_m = _matrix(p, i, [only])
            d_matrix += base_m - res_m
            r = assess(tree, impact, [only])
            d_combined += r.inherent.score - r.residual.score
        cost = float(measure.cost) if measure.cost is not None else None
        effects.append({
            "id": measure.id, "name": measure.name, "effectiveness": float(measure.effectiveness),
            "cost": cost, "scenarios": scenarios,
            "matrix_reduction": round(d_matrix, 2), "combined_reduction": round(d_combined, 2),
            "matrix_per_10k": round(d_matrix / cost * 10000, 3) if cost else None,
            "combined_per_10k": round(d_combined / cost * 10000, 3) if cost else None,
        })
    return effects
