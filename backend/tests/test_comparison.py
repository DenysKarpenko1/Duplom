"""Метрики порівняння моделей."""
import pytest

from app.core.comparison import (ModelScores, compare, confusion, normalized_entropy,
                                 tie_ratio, top_overlap, weighted_kappa)
from app.risk_core import matrix_probability

L, M, H, C = "Низький", "Середній", "Високий", "Критичний"


def test_tie_ratio():
    assert tie_ratio([1, 2, 3]) == 0
    assert tie_ratio([5, 5, 5]) == 1
    assert tie_ratio([5, 5, 1]) == pytest.approx(1 / 3)


def test_entropy_bounds():
    assert normalized_entropy([C] * 10) == 0
    assert normalized_entropy([L, M, H, C]) == pytest.approx(1.0)


def test_confusion_and_kappa():
    a = [L, M, H, C]
    assert confusion(a, a) == [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]
    assert weighted_kappa(a, a) == 1.0
    assert weighted_kappa(a, list(reversed(a))) < 0


def test_top_overlap():
    assert top_overlap([5, 4, 3, 2], [5, 4, 1, 0], 2) == 1.0
    assert top_overlap([5, 4, 3, 2], [0, 1, 4, 5], 2) == 0.0


def test_compare_identical_models():
    m = ModelScores([20, 12, 6, 2], [C, H, M, L], [10, 6, 3, 1], [H, M, L, L])
    r = compare(m, m, top_n=2)
    assert r["agreement"]["exact"] == 1.0
    assert r["agreement"]["spearman"]["coef"] == pytest.approx(1.0)
    assert r["a"]["levels"] == {L: 1, M: 1, H: 1, C: 1}
    assert r["a"]["mean_reduction"] == pytest.approx((0.5 + 0.5 + 0.5 + 0.5) / 4)


def test_matrix_probability_rule():
    assert matrix_probability(4, 5) == 5
    assert matrix_probability(4, 4) == 4
    assert matrix_probability(1, 2) == 2
