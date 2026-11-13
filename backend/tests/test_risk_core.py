"""Модульні тести математичного ядра: pytest"""
import pytest

from app.risk_core import calculate_risk, risk_level, risk_score


def test_score_is_product():
    for p in range(1, 6):
        for i in range(1, 6):
            assert risk_score(p, i) == p * i


@pytest.mark.parametrize(
    "score, level",
    [(1, "Низький"), (4, "Низький"), (5, "Середній"), (9, "Середній"),
     (10, "Високий"), (12, "Високий"), (15, "Критичний"), (25, "Критичний")],
)
def test_level_boundaries(score, level):
    assert risk_level(score) == level


def test_score_is_monotonic():
    # Ризик не зменшується зі зростанням імовірності або впливу
    for p in range(1, 5):
        for i in range(1, 6):
            assert risk_score(p + 1, i) >= risk_score(p, i)
            assert risk_score(i, p + 1) >= risk_score(i, p)


def test_calculate_risk_returns_score_and_level():
    assert calculate_risk(4, 5) == (20, "Критичний")
    assert calculate_risk(1, 1) == (1, "Низький")
