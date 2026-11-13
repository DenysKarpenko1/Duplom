"""Статистичне порівняння двох моделей оцінювання ризику на одному наборі сценаріїв.

Метрики:
  * описова статистика балів (середнє, медіана, стандартне відхилення, діапазон);
  * роздільна здатність: кількість різних значень балу, частка пар сценаріїв
    з однаковим балом (ties), нормована ентропія Шеннона розподілу за рівнями;
  * узгодженість: матриця відповідності рівнів, частка повного збігу, збігу
    з точністю до одного рівня, коефіцієнт каппа Коена (лінійно зважений),
    рангові кореляції Спірмена та Кендалла, перетин топ-N;
  * чутливість до заходів: середнє відносне зниження ризику.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from statistics import mean, median, pstdev

from scipy import stats

LEVEL_ORDER = ("Низький", "Середній", "Високий", "Критичний")


@dataclass
class ModelScores:
    scores: list[float]
    levels: list[str]
    residual_scores: list[float]
    residual_levels: list[str]


def describe(values: list[float]) -> dict:
    if not values:
        return {"mean": 0, "median": 0, "std": 0, "min": 0, "max": 0}
    return {"mean": round(mean(values), 3), "median": round(median(values), 3),
            "std": round(pstdev(values), 3), "min": round(min(values), 3),
            "max": round(max(values), 3)}


def tie_ratio(values: list[float]) -> float:
    """Частка пар сценаріїв, які модель не розрізняє (однаковий бал)."""
    pairs = list(combinations(values, 2))
    if not pairs:
        return 0.0
    return sum(1 for a, b in pairs if math.isclose(a, b, abs_tol=1e-9)) / len(pairs)


def normalized_entropy(levels: list[str]) -> float:
    """Ентропія розподілу за рівнями, нормована на log(кількість рівнів): 0..1."""
    n = len(levels)
    if n == 0:
        return 0.0
    probs = [c / n for c in Counter(levels).values()]
    return -sum(p * math.log(p) for p in probs) / math.log(len(LEVEL_ORDER))


def distribution(levels: list[str]) -> dict[str, int]:
    counts = Counter(levels)
    return {lvl: counts.get(lvl, 0) for lvl in LEVEL_ORDER}


def confusion(levels_a: list[str], levels_b: list[str]) -> list[list[int]]:
    """matrix[i][j] — кількість сценаріїв з рівнем i за моделлю A та j за моделлю B."""
    idx = {lvl: i for i, lvl in enumerate(LEVEL_ORDER)}
    m = [[0] * len(LEVEL_ORDER) for _ in LEVEL_ORDER]
    for a, b in zip(levels_a, levels_b):
        m[idx[a]][idx[b]] += 1
    return m


def weighted_kappa(levels_a: list[str], levels_b: list[str]) -> float:
    """Каппа Коена з лінійними вагами для порядкових рівнів."""
    k = len(LEVEL_ORDER)
    n = len(levels_a)
    if n == 0:
        return 0.0
    obs = confusion(levels_a, levels_b)
    row = [sum(r) for r in obs]
    col = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    w = [[abs(i - j) / (k - 1) for j in range(k)] for i in range(k)]
    observed = sum(w[i][j] * obs[i][j] for i in range(k) for j in range(k)) / n
    expected = sum(w[i][j] * row[i] * col[j] for i in range(k) for j in range(k)) / n ** 2
    return 1.0 if expected == 0 else round(1 - observed / expected, 4)


def top_overlap(a: list[float], b: list[float], n: int) -> float:
    """Частка спільних сценаріїв серед n найризикованіших за кожною моделлю."""
    n = min(n, len(a))
    if n == 0:
        return 0.0
    top = lambda xs: set(sorted(range(len(xs)), key=lambda i: (-xs[i], i))[:n])  # noqa: E731
    return len(top(a) & top(b)) / n


def _corr(fn, a, b) -> dict:
    if len(a) < 3 or len(set(a)) < 2 or len(set(b)) < 2:
        return {"coef": None, "p_value": None}
    res = fn(a, b)
    return {"coef": round(float(res.statistic), 4), "p_value": float(res.pvalue)}


def model_summary(m: ModelScores) -> dict:
    reductions = [(s - r) / s for s, r in zip(m.scores, m.residual_scores) if s > 0]
    return {
        "score": describe(m.scores),
        "residual": describe(m.residual_scores),
        "distinct_scores": len({round(s, 2) for s in m.scores}),
        "tie_ratio": round(tie_ratio(m.scores), 4),
        "entropy": round(normalized_entropy(m.levels), 4),
        "levels": distribution(m.levels),
        "residual_levels": distribution(m.residual_levels),
        "mean_reduction": round(mean(reductions), 4) if reductions else 0.0,
        "critical_share": round(m.levels.count("Критичний") / len(m.levels), 4) if m.levels else 0,
    }


def compare(a: ModelScores, b: ModelScores, top_n: int = 10) -> dict:
    """Порівняння моделі A (базової) і моделі B (запропонованої)."""
    idx = {lvl: i for i, lvl in enumerate(LEVEL_ORDER)}
    diffs = [abs(idx[x] - idx[y]) for x, y in zip(a.levels, b.levels)]
    n = len(diffs) or 1
    return {
        "a": model_summary(a),
        "b": model_summary(b),
        "agreement": {
            "confusion": confusion(a.levels, b.levels),
            "exact": round(sum(d == 0 for d in diffs) / n, 4),
            "within_one": round(sum(d <= 1 for d in diffs) / n, 4),
            "b_lower": round(sum(idx[y] < idx[x] for x, y in zip(a.levels, b.levels)) / n, 4),
            "b_higher": round(sum(idx[y] > idx[x] for x, y in zip(a.levels, b.levels)) / n, 4),
            "kappa_linear": weighted_kappa(a.levels, b.levels),
            "spearman": _corr(stats.spearmanr, a.scores, b.scores),
            "kendall": _corr(stats.kendalltau, a.scores, b.scores),
            "residual_spearman": _corr(stats.spearmanr, a.residual_scores, b.residual_scores),
            "top_n": top_n,
            "top_overlap": round(top_overlap(a.scores, b.scores, top_n), 4),
        },
    }
