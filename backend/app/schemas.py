"""Схеми запитів і відповідей API (валідація вхідних даних)."""
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

MeasureType = Literal["preventive", "detective", "corrective"]
MeasureStatus = Literal["implemented", "planned"]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    # Decimal у JSON віддаємо числом, а не рядком
    @field_serializer("*", when_used="json", check_fields=False)
    def _decimal_to_float(self, value):
        return float(value) if isinstance(value, Decimal) else value


class Ref(ORMModel):
    """Коротке посилання на запис довідника."""

    id: int
    name: str


# ---------------------------------------------------------------- класифікатори
class AssetCategoryIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None


class AssetCategoryOut(AssetCategoryIn, ORMModel):
    id: int


class ThreatCategoryIn(BaseModel):
    code: str = Field(min_length=1, max_length=30)
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None


class ThreatCategoryOut(ThreatCategoryIn, ORMModel):
    id: int


class RiskLevelOut(ORMModel):
    id: int
    name: str
    min_score: int
    max_score: int
    color: str


# ---------------------------------------------------------------- довідники
class AssetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    category_id: int | None = None
    owner: str | None = Field(default=None, max_length=200)
    description: str | None = None
    confidentiality: int = Field(default=3, ge=1, le=5)
    integrity: int = Field(default=3, ge=1, le=5)
    availability: int = Field(default=3, ge=1, le=5)
    vulnerability_ids: list[int] = []


class AssetOut(ORMModel):
    id: int
    name: str
    category: Ref | None
    owner: str | None
    description: str | None
    confidentiality: int
    integrity: int
    availability: int
    vulnerabilities: list[Ref]
    created_at: datetime


class ThreatIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    category_id: int | None = None
    description: str | None = None
    base_likelihood: int = Field(default=3, ge=1, le=5)
    vulnerability_ids: list[int] = []


class ThreatOut(ORMModel):
    id: int
    name: str
    category: Ref | None
    description: str | None
    base_likelihood: int
    vulnerabilities: list[Ref]


class VulnerabilityIn(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    description: str | None = None
    cve_id: str | None = Field(default=None, max_length=30)
    cvss_score: Decimal | None = Field(default=None, ge=0, le=10, decimal_places=1)
    severity: int = Field(default=3, ge=1, le=5)


class VulnerabilityOut(ORMModel):
    id: int
    name: str
    description: str | None
    cve_id: str | None
    cvss_score: Decimal | None
    severity: int
    threats: list[Ref]
    assets: list[Ref]
    measures: list[Ref]


class MeasureIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    control_ref: str | None = Field(default=None, max_length=50)
    measure_type: MeasureType = "preventive"
    effectiveness: Decimal = Field(default=Decimal("0.50"), ge=0, le=1, decimal_places=2)
    cost: Decimal | None = Field(default=None, ge=0)
    vulnerability_ids: list[int] = []


class MeasureOut(ORMModel):
    id: int
    name: str
    description: str | None
    control_ref: str | None
    measure_type: str
    effectiveness: Decimal
    cost: Decimal | None
    vulnerabilities: list[Ref]


# ---------------------------------------------------------------- сценарії та оцінки
class ScenarioMeasureIn(BaseModel):
    measure_id: int
    status: MeasureStatus = "planned"


class ScenarioMeasureOut(ORMModel):
    measure: Ref
    status: str


class AssessmentIn(BaseModel):
    """Нове оцінювання сценарію.

    matrix   — потрібні probability та impact (1..5);
    combined — ймовірність обчислюється деревом атак, impact (1..5, можна дробовий)
               необов'язковий: за замовчуванням — max(C, I, A) активу.
    """

    method: Literal["matrix", "combined"] = "matrix"
    probability: int | None = Field(default=None, ge=1, le=5)
    impact: float | None = Field(default=None, ge=1, le=5)
    notes: str | None = None

    @model_validator(mode="after")
    def _check_matrix_inputs(self):
        if self.method == "matrix":
            if self.probability is None or self.impact is None:
                raise ValueError("Для матричного методу потрібні probability та impact")
            if self.impact != int(self.impact):
                raise ValueError("Для матричного методу impact має бути цілим")
        return self


class AssessmentOut(ORMModel):
    id: int
    assessed_at: datetime
    method: str
    probability: int
    impact: int
    likelihood: Decimal | None
    residual_likelihood: Decimal | None
    score: Decimal
    level: Ref
    residual_score: Decimal | None
    residual_level: Ref | None
    notes: str | None


class ScenarioIn(BaseModel):
    asset_id: int
    threat_id: int
    vulnerability_id: int
    description: str | None = None
    measures: list[ScenarioMeasureIn] = []


class ScenarioOut(ORMModel):
    id: int
    asset: Ref
    threat: Ref
    vulnerability: Ref
    description: str | None
    created_at: datetime
    measure_links: list[ScenarioMeasureOut]
    assessments: list[AssessmentOut]


# ---------------------------------------------------------------- дерева атак
class AttackNodeIn(BaseModel):
    """Вузол дерева атак (вкладена структура)."""

    name: str = Field(min_length=1, max_length=300)
    gate: Literal["LEAF", "AND", "OR"] = "LEAF"
    probability: float | None = Field(default=None, ge=0, le=1)
    vulnerability_id: int | None = None
    children: list["AttackNodeIn"] = []


class AttackNodeOut(BaseModel):
    name: str
    gate: str
    probability: float | None  # задана ймовірність листка
    vulnerability_id: int | None
    computed: float  # обчислена ймовірність без заходів
    residual: float  # з урахуванням впроваджених заходів
    on_critical_path: bool
    children: list["AttackNodeOut"] = []


class FuzzyOut(BaseModel):
    score: float
    nist_level: str
    activations: dict[str, float]


class AttackTreeOut(BaseModel):
    scenario_id: int
    custom: bool  # False — типове дерево (загроза AND вразливість)
    root: AttackNodeOut
    likelihood: float
    likelihood_level: str
    residual_likelihood: float
    impact: float
    inherent: FuzzyOut
    residual: FuzzyOut
    risk_reduction: float
    most_likely_path: list[str]
    minimal_cut_sets: list[list[str]]


# ---------------------------------------------------------------- сумісність з MVP
class RiskCreate(BaseModel):
    """Дані форми «Введення даних» (плаский формат MVP)."""

    asset: str = Field(min_length=1, max_length=200)
    threat: str = Field(min_length=1, max_length=200)
    vulnerability: str = Field(min_length=1, max_length=300)
    probability: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)


class RiskOut(RiskCreate):
    """Сценарій разом з останньою оцінкою — у форматі, який очікує фронтенд MVP."""

    id: int
    score: float
    level: str
    created_at: datetime
