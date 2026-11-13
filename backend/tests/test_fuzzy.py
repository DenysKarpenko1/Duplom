"""Нечіткий висновок: функції належності, узгодженість з NIST Table I-2, монотонність."""
import numpy as np
import pytest

from app.core import fuzzy
from app.core.scales import (LEVEL_PROBABILITY, NistLevel, exploitability, level_to_probability,
                             probability_to_level)

LEVELS = list(NistLevel)


@pytest.mark.parametrize("p", np.linspace(0, 1, 41))
def test_likelihood_partition_of_unity(p):
    assert sum(fuzzy.likelihood_membership(p).values()) == pytest.approx(1.0, abs=1e-6)


@pytest.mark.parametrize("i", np.linspace(1, 5, 41))
def test_impact_partition_of_unity(i):
    assert sum(fuzzy.impact_membership(i).values()) == pytest.approx(1.0, abs=1e-6)


def test_representative_points_are_in_cores():
    for level, p in LEVEL_PROBABILITY.items():
        assert fuzzy.likelihood_membership(p)[level] == pytest.approx(1.0)
        assert fuzzy.impact_membership(int(level))[level] == pytest.approx(1.0)


@pytest.mark.parametrize("l_level", LEVELS)
@pytest.mark.parametrize("i_level", LEVELS)
def test_crisp_inputs_reproduce_nist_matrix(l_level, i_level):
    result = fuzzy.infer(LEVEL_PROBABILITY[l_level], int(i_level))
    assert result.nist_level == fuzzy.NIST_RISK_MATRIX[l_level][LEVELS.index(i_level)]
    assert len(result.fired_rules) == 1


def test_output_centroids_fall_into_system_levels():
    # VL, L -> «Низький» (<=4), M -> «Середній» (<=9), H -> «Високий» (<=14), VH -> «Критичний»
    expected = {NistLevel.VERY_LOW: (0, 4), NistLevel.LOW: (0, 4), NistLevel.MODERATE: (5, 9),
                NistLevel.HIGH: (10, 14), NistLevel.VERY_HIGH: (15, 25)}
    for l_level in LEVELS:
        for j, i_level in enumerate(LEVELS):
            r = fuzzy.infer(LEVEL_PROBABILITY[l_level], int(i_level))
            lo, hi = expected[r.nist_level]
            assert lo <= r.score <= hi


def test_monotonic_in_both_inputs():
    ps = np.linspace(0, 1, 81)
    impacts = np.linspace(1, 5, 33)
    s = np.array([[fuzzy.infer(p, i).score for i in impacts] for p in ps])
    assert (np.diff(s, axis=0) >= -0.011).all()  # допуск — округлення до 0,01
    assert (np.diff(s, axis=1) >= -0.011).all()


def test_extremes_and_bounds():
    assert fuzzy.infer(0.0, 1.0).score < 2
    assert fuzzy.infer(1.0, 5.0).score > 19
    with pytest.raises(ValueError):
        fuzzy.infer(1.2, 3)
    with pytest.raises(ValueError):
        fuzzy.infer(0.5, 0)


def test_interpolates_between_rules():
    # На межі Moderate/High за впливом бал лежить між центроїдами M (7) і H (12)
    r = fuzzy.infer(0.875, 3.5)
    assert 7 < r.score < 12
    assert r.activations[NistLevel.MODERATE] == pytest.approx(0.5)
    assert r.activations[NistLevel.HIGH] == pytest.approx(0.5)


def test_scales():
    assert level_to_probability(3) == 0.5
    assert probability_to_level(0.02) is NistLevel.VERY_LOW
    assert probability_to_level(0.5) is NistLevel.MODERATE
    assert probability_to_level(0.97) is NistLevel.VERY_HIGH
    assert exploitability(9.8, 1) == pytest.approx(0.98)
    assert exploitability(None, 4) == 0.875
    with pytest.raises(ValueError):
        probability_to_level(-0.1)


def test_membership_functions_export():
    data = fuzzy.membership_functions()
    assert len(data["rules"]) == 25
    assert set(data["likelihood"]) == {"Very Low", "Low", "Moderate", "High", "Very High"}
