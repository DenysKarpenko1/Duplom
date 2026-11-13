"""Шкали оцінювання, узгоджені з NIST SP 800-30 Rev. 1 (Appendix G, H, I).

NIST використовує п'ять якісних рівнів (Very Low ... Very High) і відповідні
напівкількісні діапазони 0..100. Тут вони переведені в імовірнісну шкалу [0, 1]:

    рівень        діапазон NIST   представницьке значення p
    Very Low      0–4             0.02
    Low           5–20            0.125
    Moderate      21–79           0.50
    High          80–95           0.875
    Very High     96–100          0.98
"""
from enum import IntEnum


class NistLevel(IntEnum):
    VERY_LOW = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    VERY_HIGH = 5

    @property
    def label(self) -> str:
        return NIST_LABELS[self]

    @property
    def label_uk(self) -> str:
        return NIST_LABELS_UK[self]


NIST_LABELS = {
    NistLevel.VERY_LOW: "Very Low",
    NistLevel.LOW: "Low",
    NistLevel.MODERATE: "Moderate",
    NistLevel.HIGH: "High",
    NistLevel.VERY_HIGH: "Very High",
}

NIST_LABELS_UK = {
    NistLevel.VERY_LOW: "Дуже низький",
    NistLevel.LOW: "Низький",
    NistLevel.MODERATE: "Помірний",
    NistLevel.HIGH: "Високий",
    NistLevel.VERY_HIGH: "Дуже високий",
}

# Напівкількісні діапазони NIST (Table G-2 / H-2 / I-3), частка від 100
NIST_RANGES = {
    NistLevel.VERY_LOW: (0.00, 0.04),
    NistLevel.LOW: (0.05, 0.20),
    NistLevel.MODERATE: (0.21, 0.79),
    NistLevel.HIGH: (0.80, 0.95),
    NistLevel.VERY_HIGH: (0.96, 1.00),
}

# Представницька ймовірність для оцінки за шкалою 1..5 (середина діапазону NIST)
LEVEL_PROBABILITY = {
    NistLevel.VERY_LOW: 0.02,
    NistLevel.LOW: 0.125,
    NistLevel.MODERATE: 0.50,
    NistLevel.HIGH: 0.875,
    NistLevel.VERY_HIGH: 0.98,
}


def level_to_probability(level: int) -> float:
    """Оцінку 1..5 переводить у ймовірність за шкалою NIST."""
    return LEVEL_PROBABILITY[NistLevel(level)]


def probability_to_level(p: float) -> NistLevel:
    """Ймовірність [0, 1] -> якісний рівень NIST (межі — середини проміжків між діапазонами)."""
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"Ймовірність має лежати в [0, 1], отримано {p}")
    bounds = ((0.045, NistLevel.VERY_LOW), (0.205, NistLevel.LOW),
              (0.795, NistLevel.MODERATE), (0.955, NistLevel.HIGH))
    for upper, level in bounds:
        if p < upper:
            return level
    return NistLevel.VERY_HIGH


def exploitability(cvss_score: float | None, severity: int) -> float:
    """Ймовірність успішної експлуатації вразливості.

    Якщо відомий бал CVSS (0..10), береться cvss/10; інакше — оцінка
    критичності 1..5 за шкалою NIST.
    """
    if cvss_score is not None:
        if not 0 <= cvss_score <= 10:
            raise ValueError("CVSS має лежати в [0, 10]")
        return float(cvss_score) / 10.0
    return level_to_probability(severity)
