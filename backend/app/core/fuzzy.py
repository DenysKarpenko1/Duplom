"""Нечіткий логічний висновок рівня ризику (Mamdani), узгоджений з NIST SP 800-30.

Лінгвістичні змінні (терми VL, L, M, H, VH — п'ять рівнів NIST):
    Likelihood — імовірність реалізації сценарію, універсум [0, 1]
                 (результат дерева атак); трикутні функції належності з
                 вершинами в представницьких значеннях рівнів NIST
                 (0.02, 0.125, 0.5, 0.875, 0.98 — середини діапазонів Table G-2),
                 що утворюють розбиття одиниці; крайні терми мають «плечі»;
    Impact     — рівень впливу, універсум [1, 5]; трикутні функції з вершинами 1..5
                 (Table H-3);
    Risk       — рівень ризику, універсум [0, 25] (сумісний з балом матричної
                 моделі P x I); терми підібрано так, щоб центроїд кожного терму
                 потрапляв у відповідний рівень шкали системи.

База правил — 25 правил «ЯКЩО Likelihood = A І Impact = B, ТО Risk = C»,
де C береться з матриці NIST SP 800-30 Table I-2.

Висновок (Mamdani-type, імплікація Ларсена): добуток як t-норма для «І»,
імплікація-добуток (масштабування вихідного терму), агрегація max,
дефазифікація методом центру ваги (centroid).

Чому трикутники, а не трапеції з ядрами в діапазонах NIST: широке ядро терму
Moderate (21–79 %) дає «плато», на якому зміна ймовірності (зокрема через
впровадження заходів) не змінює бал ризику. Трикутне розбиття зберігає збіг
з матрицею NIST у представницьких точках і дає неперервну реакцію на P.

Чому добуток, а не min: при min-t-нормі й відсіканні центроїд «стрибає» в зонах
перекриття термів, і бал ризику може зменшуватися зі зростанням ймовірності або
впливу (немонотонність до 0,4 бала). Варіант з добутком монотонний, що
перевіряється в unit-тестах.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import skfuzzy as fuzz

from .scales import NistLevel

VL, L, M, H, VH = (NistLevel.VERY_LOW, NistLevel.LOW, NistLevel.MODERATE, NistLevel.HIGH,
                   NistLevel.VERY_HIGH)
LEVELS = (VL, L, M, H, VH)

# NIST SP 800-30 Rev.1, Table I-2: рядки — ймовірність, стовпці — вплив (VL..VH)
NIST_RISK_MATRIX: dict[NistLevel, tuple[NistLevel, ...]] = {
    VH: (VL, L, M, H, VH),
    H: (VL, L, M, H, VH),
    M: (VL, L, M, M, H),
    L: (VL, L, L, L, M),
    VL: (VL, VL, VL, L, L),
}

# Параметри функцій належності
LIKELIHOOD_MF = {  # [a, b, c, d]: крайні терми — трапеції-«плечі», решта — трикутники (b = c)
    VL: [0.00, 0.00, 0.02, 0.125],
    L: [0.02, 0.125, 0.125, 0.50],
    M: [0.125, 0.50, 0.50, 0.875],
    H: [0.50, 0.875, 0.875, 0.98],
    VH: [0.875, 0.98, 1.00, 1.00],
}
IMPACT_MF = {  # трикутники [a, b, c]
    VL: [1, 1, 2],
    L: [1, 2, 3],
    M: [2, 3, 4],
    H: [3, 4, 5],
    VH: [4, 5, 5],
}
RISK_MF = {  # VL і VH — трапеції, решта — трикутники
    VL: ("trap", [0.0, 0.0, 1.0, 3.0]),
    L: ("tri", [1.5, 3.5, 5.5]),
    M: ("tri", [4.5, 7.0, 9.5]),
    H: ("tri", [9.0, 12.0, 15.0]),
    VH: ("trap", [14.0, 18.0, 25.0, 25.0]),
}

X_LIKELIHOOD = np.linspace(0.0, 1.0, 1001)
X_IMPACT = np.linspace(1.0, 5.0, 401)
X_RISK = np.linspace(0.0, 25.0, 2501)


def _risk_curve(level: NistLevel) -> np.ndarray:
    kind, params = RISK_MF[level]
    return fuzz.trapmf(X_RISK, params) if kind == "trap" else fuzz.trimf(X_RISK, params)


RISK_CURVES = {lvl: _risk_curve(lvl) for lvl in LEVELS}


def likelihood_membership(p: float) -> dict[NistLevel, float]:
    """Ступені належності ймовірності p до термів VL..VH."""
    if not 0.0 <= p <= 1.0:
        raise ValueError("Ймовірність має лежати в [0, 1]")
    return {lvl: float(fuzz.interp_membership(X_LIKELIHOOD, fuzz.trapmf(X_LIKELIHOOD, prm), p))
            for lvl, prm in LIKELIHOOD_MF.items()}


def impact_membership(impact: float) -> dict[NistLevel, float]:
    """Ступені належності рівня впливу (1..5, можна дробовий) до термів VL..VH."""
    if not 1.0 <= impact <= 5.0:
        raise ValueError("Вплив має лежати в [1, 5]")
    return {lvl: float(fuzz.interp_membership(X_IMPACT, fuzz.trimf(X_IMPACT, prm), impact))
            for lvl, prm in IMPACT_MF.items()}


@dataclass
class FuzzyResult:
    score: float  # дефазифікований бал ризику 0..25
    nist_level: NistLevel  # терм з найбільшою активацією
    activations: dict[NistLevel, float]  # активація кожного вихідного терму
    likelihood_memberships: dict[NistLevel, float]
    impact_memberships: dict[NistLevel, float]
    fired_rules: list[tuple[NistLevel, NistLevel, NistLevel, float]]  # (L, I, Risk, сила)


def infer(likelihood: float, impact: float) -> FuzzyResult:
    """Нечіткий висновок рівня ризику для пари (ймовірність, вплив)."""
    mu_l = likelihood_membership(likelihood)
    mu_i = impact_membership(impact)

    activations = {lvl: 0.0 for lvl in LEVELS}
    fired = []
    for l_term, row in NIST_RISK_MATRIX.items():
        for i_term, r_term in zip(LEVELS, row):
            strength = mu_l[l_term] * mu_i[i_term]  # «І» = добуток
            if strength > 0:
                fired.append((l_term, i_term, r_term, strength))
                activations[r_term] = max(activations[r_term], strength)  # агрегація max

    aggregated = np.zeros_like(X_RISK)
    for lvl, act in activations.items():
        if act > 0:
            aggregated = np.fmax(aggregated, act * RISK_CURVES[lvl])  # імплікація Ларсена
    score = float(fuzz.defuzz(X_RISK, aggregated, "centroid"))
    dominant = max(LEVELS, key=lambda lvl: (activations[lvl], lvl))
    return FuzzyResult(score=round(score, 2), nist_level=dominant, activations=activations,
                       likelihood_memberships=mu_l, impact_memberships=mu_i, fired_rules=fired)


def membership_functions() -> dict:
    """Параметри функцій належності — для візуалізації на фронтенді та в тексті."""
    return {
        "likelihood": {lvl.label: prm for lvl, prm in LIKELIHOOD_MF.items()},
        "impact": {lvl.label: prm for lvl, prm in IMPACT_MF.items()},
        "risk": {lvl.label: {"type": kind, "params": prm} for lvl, (kind, prm) in RISK_MF.items()},
        "rules": [{"likelihood": l_t.label, "impact": i_t.label, "risk": r_t.label}
                  for l_t, row in NIST_RISK_MATRIX.items() for i_t, r_t in zip(LEVELS, row)],
    }
