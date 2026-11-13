"""Комбінований метод і залишковий ризик."""
import pytest

from app.core.attack_tree import AttackNode, Gate
from app.core.combined import (Measure, asset_impact, assess, combined_effectiveness,
                               leaf_reduction, matrix_residual)


def tree():
    return AttackNode("goal", Gate.OR, children=[
        AttackNode("web", Gate.AND, children=[
            AttackNode("scan", probability=0.9),
            AttackNode("exploit", probability=0.98, vulnerability_id=1)]),
        AttackNode("phish", probability=0.3, vulnerability_id=2)])


def test_combined_effectiveness():
    assert combined_effectiveness([]) == 0
    assert combined_effectiveness([0.5, 0.5]) == pytest.approx(0.75)
    with pytest.raises(ValueError):
        combined_effectiveness([1.5])


def test_leaf_reduction_ignores_planned():
    measures = [Measure("patch", 0.8, {1}), Measure("waf", 0.5, {1}),
                Measure("training", 0.5, {2}, implemented=False)]
    assert leaf_reduction(measures) == {1: pytest.approx(0.1)}


def test_residual_not_greater_than_inherent():
    r = assess(tree(), 5, [Measure("patch", 0.8, {1})])
    assert r.residual_likelihood < r.likelihood
    assert r.residual.score <= r.inherent.score
    assert 0 <= r.risk_reduction <= 1


def test_no_measures_means_residual_equals_inherent():
    r = assess(tree(), 4, [])
    assert r.residual.score == r.inherent.score
    assert r.risk_reduction == 0


def test_measure_on_unrelated_vulnerability_has_no_effect():
    r = assess(tree(), 4, [Measure("other", 0.9, {99})])
    assert r.residual_likelihood == r.likelihood


def test_more_effective_measures_reduce_more():
    scores = [assess(tree(), 5, [Measure("m", e, {1, 2})]).residual.score
              for e in (0.0, 0.3, 0.6, 0.9)]
    assert all(b <= a for a, b in zip(scores, scores[1:]))
    assert scores[-1] < scores[0]


def test_most_likely_path():
    assert assess(tree(), 3).most_likely_path == ["scan", "exploit"]


def test_asset_impact():
    assert asset_impact(5, 2, 3) == 5
    with pytest.raises(ValueError):
        asset_impact(0, 3, 3)


def test_matrix_residual():
    assert matrix_residual(4, 5, []) == (4, 20)
    assert matrix_residual(4, 5, [0.5]) == (2, 10)
    assert matrix_residual(4, 5, [0.99]) == (1, 5)  # ймовірність не нижче 1
