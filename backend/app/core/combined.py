"""Комбінований метод оцінювання ризику: дерево атак + нечіткий висновок.

Алгоритм для сценарію (актив, загроза, вразливість):
  1. Будується дерево атак (явно задане або типове: ініціювання загрози AND
     експлуатація вразливості) і обчислюється ймовірність досягнення мети P.
  2. Вплив I визначається цінністю активу за властивостями C/I/A (1..5).
  3. Нечіткий висновок Mamdani за правилами NIST SP 800-30 дає бал ризику R(P, I).
  4. Залишковий ризик: для впроваджених заходів захисту кожен листок, що
     експлуатує вразливість v, отримує множник П (1 - e_j) по заходах j,
     які закривають v; дерево перераховується -> P_res, і R_res = R(P_res, I).
     Ефективність заходу щодо ризику: (R - R_res) / R.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from . import attack_tree as at
from .fuzzy import FuzzyResult, infer
from .scales import NistLevel, probability_to_level


@dataclass
class Measure:
    """Захід захисту: ефективність 0..1 та вразливості, які він закриває."""

    name: str
    effectiveness: float
    vulnerability_ids: set[int]
    implemented: bool = True


@dataclass
class CombinedResult:
    likelihood: float
    likelihood_level: NistLevel
    impact: float
    inherent: FuzzyResult
    residual_likelihood: float
    residual: FuzzyResult
    most_likely_path: list[str]
    tree: at.TreeEvaluation
    residual_tree: at.TreeEvaluation

    @property
    def risk_reduction(self) -> float:
        """Відносне зниження ризику завдяки заходам, 0..1."""
        if self.inherent.score == 0:
            return 0.0
        return max(0.0, (self.inherent.score - self.residual.score) / self.inherent.score)


def combined_effectiveness(effectiveness: list[float]) -> float:
    """Сумарна ефективність незалежних заходів: E = 1 - П (1 - e_j)."""
    for e in effectiveness:
        if not 0.0 <= e <= 1.0:
            raise ValueError("Ефективність заходу має лежати в [0, 1]")
    return 1.0 - math.prod(1.0 - e for e in effectiveness)


def leaf_reduction(measures: list[Measure]) -> dict[int, float]:
    """vulnerability_id -> множник (1 - E) за впровадженими заходами."""
    by_vuln: dict[int, list[float]] = {}
    for m in measures:
        if not m.implemented:
            continue
        for vid in m.vulnerability_ids:
            by_vuln.setdefault(vid, []).append(m.effectiveness)
    return {vid: 1.0 - combined_effectiveness(es) for vid, es in by_vuln.items()}


def asset_impact(confidentiality: int, integrity: int, availability: int) -> float:
    """Вплив за цінністю активу: максимум за властивостями безпеки (принцип найгіршого випадку)."""
    for v in (confidentiality, integrity, availability):
        if not 1 <= v <= 5:
            raise ValueError("Оцінки C/I/A мають лежати в [1, 5]")
    return float(max(confidentiality, integrity, availability))


def assess(tree: at.AttackNode, impact: float,
           measures: list[Measure] | None = None) -> CombinedResult:
    """Повне оцінювання сценарію комбінованим методом."""
    graph, root = at.build_graph(tree)
    inherent_tree = at.evaluate((graph.copy(), root))
    residual_tree = at.evaluate((graph.copy(), root), leaf_reduction(measures or []))
    path, _ = inherent_tree.most_likely_path()
    return CombinedResult(
        likelihood=inherent_tree.probability,
        likelihood_level=probability_to_level(inherent_tree.probability),
        impact=impact,
        inherent=infer(inherent_tree.probability, impact),
        residual_likelihood=residual_tree.probability,
        residual=infer(residual_tree.probability, impact),
        most_likely_path=path,
        tree=inherent_tree,
        residual_tree=residual_tree,
    )


def matrix_residual(probability: int, impact: int,
                    effectiveness: list[float]) -> tuple[int, int]:
    """Залишковий ризик базової матричної моделі: P_res = max(1, round(P * (1 - E)))."""
    e = combined_effectiveness(effectiveness)
    p_res = max(1, round(probability * (1.0 - e)))
    return p_res, p_res * impact
