"""Зв'язок між БД і математичним ядром: побудова входів і запис результатів оцінювання."""
from __future__ import annotations

from decimal import Decimal

from sqlalchemy.orm import Session

from . import models
from .core import attack_tree as at
from .core.combined import CombinedResult, Measure, asset_impact, assess, matrix_residual
from .core.scales import exploitability, level_to_probability
from .risk_core import risk_score
from .services import level_for_score


def tree_from_db(scenario: models.RiskScenario) -> tuple[at.AttackNode, bool]:
    """Дерево атак сценарію з БД; якщо його немає — типове. Повертає (дерево, is_custom)."""
    nodes = scenario.tree_nodes
    if not nodes:
        vuln, threat = scenario.vulnerability, scenario.threat
        cvss = float(vuln.cvss_score) if vuln.cvss_score is not None else None
        return at.default_tree(
            threat.name, level_to_probability(threat.base_likelihood), vuln.name, vuln.id,
            exploitability(cvss, vuln.severity)), False

    children: dict[int | None, list[models.AttackTreeNode]] = {}
    for n in nodes:
        children.setdefault(n.parent_id, []).append(n)
    roots = children.get(None, [])
    if len(roots) != 1:
        raise ValueError(f"Дерево сценарію {scenario.id} має {len(roots)} коренів")

    def build(n: models.AttackTreeNode) -> at.AttackNode:
        return at.AttackNode(
            name=n.name, gate=at.Gate(n.gate),
            probability=float(n.probability) if n.probability is not None else None,
            vulnerability_id=n.vulnerability_id,
            children=[build(c) for c in sorted(children.get(n.id, []), key=lambda c: c.position)])

    return build(roots[0]), True


def save_tree(db: Session, scenario: models.RiskScenario, root: at.AttackNode | None) -> None:
    """Замінює дерево сценарію (None — повернення до типового дерева)."""
    scenario.tree_nodes.clear()
    db.flush()
    if root is None:
        return

    def add(node: at.AttackNode, parent: models.AttackTreeNode | None, position: int):
        row = models.AttackTreeNode(
            name=node.name, gate=node.gate.value,
            parent_id=parent.id if parent is not None else None,
            probability=Decimal(f"{node.probability:.4f}") if node.probability is not None else None,
            vulnerability_id=node.vulnerability_id, position=position)
        scenario.tree_nodes.append(row)
        db.flush()
        for i, child in enumerate(node.children):
            add(child, row, i)

    add(root, None, 0)


def scenario_measures(scenario: models.RiskScenario) -> list[Measure]:
    return [Measure(name=link.measure.name, effectiveness=float(link.measure.effectiveness),
                    vulnerability_ids={v.id for v in link.measure.vulnerabilities},
                    implemented=link.status == "implemented")
            for link in scenario.measure_links]


def scenario_impact(scenario: models.RiskScenario) -> float:
    a = scenario.asset
    return asset_impact(a.confidentiality, a.integrity, a.availability)


def evaluate_combined(scenario: models.RiskScenario,
                      impact: float | None = None) -> CombinedResult:
    tree, _ = tree_from_db(scenario)
    return assess(tree, impact if impact is not None else scenario_impact(scenario),
                  scenario_measures(scenario))


def combined_assessment(db: Session, scenario: models.RiskScenario, impact: float | None = None,
                        notes: str | None = None) -> models.RiskAssessment:
    """Оцінювання комбінованим методом із записом в історію."""
    r = evaluate_combined(scenario, impact)
    auto = (f"NIST: ймовірність {r.likelihood_level.label}, ризик {r.inherent.nist_level.label}"
            f" -> залишковий {r.residual.nist_level.label}")
    assessment = models.RiskAssessment(
        method="combined", probability=int(r.likelihood_level), impact=round(r.impact),
        likelihood=Decimal(f"{r.likelihood:.4f}"),
        residual_likelihood=Decimal(f"{r.residual_likelihood:.4f}"),
        score=Decimal(f"{r.inherent.score:.2f}"), level=level_for_score(db, r.inherent.score),
        residual_score=Decimal(f"{r.residual.score:.2f}"),
        residual_level=level_for_score(db, max(r.residual.score, 0)),
        notes=notes or auto)
    scenario.assessments.append(assessment)
    return assessment


def matrix_assessment(db: Session, scenario: models.RiskScenario, probability: int, impact: int,
                      notes: str | None = None) -> models.RiskAssessment:
    """Оцінювання базовим матричним методом (Risk = P × I) із залишковим ризиком."""
    score = Decimal(risk_score(probability, impact))
    effs = [m.effectiveness for m in scenario_measures(scenario) if m.implemented]
    _, residual = matrix_residual(probability, impact, effs)
    assessment = models.RiskAssessment(
        method="matrix", probability=probability, impact=impact, score=score,
        level=level_for_score(db, score), residual_score=Decimal(residual),
        residual_level=level_for_score(db, residual), notes=notes)
    scenario.assessments.append(assessment)
    return assessment
