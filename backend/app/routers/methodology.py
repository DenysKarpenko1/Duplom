"""Параметри комбінованого методу — для візуалізації та пояснень у UI."""
from fastapi import APIRouter, Query

from ..core import fuzzy
from ..core.scales import LEVEL_PROBABILITY, NIST_RANGES

router = APIRouter(prefix="/api/methodology")


@router.get("/fuzzy")
def fuzzy_model():
    """Функції належності, база правил (NIST SP 800-30 Table I-2) і шкали."""
    return {
        **fuzzy.membership_functions(),
        "nist_ranges": {lvl.label: rng for lvl, rng in NIST_RANGES.items()},
        "level_probability": {lvl.label: p for lvl, p in LEVEL_PROBABILITY.items()},
    }


@router.get("/fuzzy/infer")
def fuzzy_infer(likelihood: float = Query(ge=0, le=1), impact: float = Query(ge=1, le=5)):
    """Нечіткий висновок для довільної пари (ймовірність, вплив) — для «пісочниці» в UI."""
    r = fuzzy.infer(likelihood, impact)
    return {
        "score": r.score, "nist_level": r.nist_level.label,
        "activations": {k.label: round(v, 4) for k, v in r.activations.items()},
        "fired_rules": [{"likelihood": a.label, "impact": b.label, "risk": c.label,
                         "strength": round(w, 4)} for a, b, c, w in r.fired_rules],
    }
