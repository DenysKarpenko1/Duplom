"""Математичне ядро: розрахунок рівня ризику.

У MVP реалізовано класичну матричну модель (ISO/IEC 27005, NIST SP 800-30):
    Risk = Probability * Impact,
де обидві оцінки задаються за шкалою від 1 до 5, а результат лежить у межах 1..25.

Модуль не залежить ні від FastAPI, ні від БД, тому складнішу модель
(дерева атак, нечіткий висновок) можна буде додати сюди, не змінюючи решту системи.
"""

# Верхня межа балу (включно) -> назва рівня ризику
LEVELS = (
    (4, "Низький"),
    (9, "Середній"),
    (14, "Високий"),
    (25, "Критичний"),
)


def risk_score(probability: int, impact: int) -> int:
    """Бал ризику за формулою Risk = Probability * Impact."""
    return probability * impact


def risk_level(score: int) -> str:
    """Якісний рівень ризику за балом."""
    for upper_bound, name in LEVELS:
        if score <= upper_bound:
            return name
    return LEVELS[-1][1]


def calculate_risk(probability: int, impact: int) -> tuple[int, str]:
    """Повертає пару (бал, рівень) для заданих оцінок."""
    score = risk_score(probability, impact)
    return score, risk_level(score)


def matrix_probability(threat_likelihood: int, severity: int) -> int:
    """Ймовірність для матричної моделі з тих самих вихідних даних, що й у комбінованого методу:
    P = ⌈(базова ймовірність загрози + критичність вразливості) / 2⌉, обидві за шкалою 1..5."""
    return -(-(threat_likelihood + severity) // 2)
