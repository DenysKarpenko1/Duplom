"""Нормалізована модель бази даних (3НФ).

Структура:
  * класифікатори: asset_categories, threat_categories, risk_levels;
  * довідники: assets, threats, vulnerabilities, protective_measures;
  * зв'язки M:N: threat_vulnerabilities, asset_vulnerabilities, measure_vulnerabilities;
  * ризики: risk_scenarios (актив + загроза + вразливість), scenario_measures
    (заходи, застосовані до сценарію), risk_assessments (історія оцінювань).

Зміни схеми вносяться лише через міграції Alembic (каталог migrations/).
"""
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Допустимі значення перелічуваних полів (контролюються CHECK-обмеженнями)
MEASURE_TYPES = ("preventive", "detective", "corrective")
MEASURE_STATUSES = ("implemented", "planned")
ASSESSMENT_METHODS = ("matrix", "combined")


# --------------------------------------------------------------------------
# Асоціативні таблиці M:N без власних атрибутів
# --------------------------------------------------------------------------
threat_vulnerabilities = Table(
    "threat_vulnerabilities",
    Base.metadata,
    Column("threat_id", ForeignKey("threats.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
           primary_key=True),
)

asset_vulnerabilities = Table(
    "asset_vulnerabilities",
    Base.metadata,
    Column("asset_id", ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
           primary_key=True),
)

measure_vulnerabilities = Table(
    "measure_vulnerabilities",
    Base.metadata,
    Column("measure_id", ForeignKey("protective_measures.id", ondelete="CASCADE"),
           primary_key=True),
    Column("vulnerability_id", ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
           primary_key=True),
)


# --------------------------------------------------------------------------
# Класифікатори
# --------------------------------------------------------------------------
class AssetCategory(Base):
    """Категорія ІТ-активу (інформація, ПЗ, апаратне забезпечення, сервіс...)."""

    __tablename__ = "asset_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str | None] = mapped_column(Text)

    assets: Mapped[list["Asset"]] = relationship(back_populates="category")


class ThreatCategory(Base):
    """Тип джерела загрози за NIST SP 800-30 (Table D-2)."""

    __tablename__ = "threat_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(30), unique=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str | None] = mapped_column(Text)

    threats: Mapped[list["Threat"]] = relationship(back_populates="category")


class RiskLevel(Base):
    """Якісний рівень ризику та діапазон балів, що йому відповідає."""

    __tablename__ = "risk_levels"
    __table_args__ = (
        CheckConstraint("min_score >= 1 AND max_score <= 25 AND min_score <= max_score",
                        name="ck_risk_levels_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(30), unique=True)
    min_score: Mapped[int] = mapped_column(Integer)
    max_score: Mapped[int] = mapped_column(Integer)
    color: Mapped[str] = mapped_column(String(7))  # HEX, напр. #dc2626


# --------------------------------------------------------------------------
# Довідники
# --------------------------------------------------------------------------
class Asset(Base):
    """ІТ-актив та його цінність за властивостями безпеки C/I/A (1..5)."""

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("confidentiality BETWEEN 1 AND 5", name="ck_assets_confidentiality"),
        CheckConstraint("integrity BETWEEN 1 AND 5", name="ck_assets_integrity"),
        CheckConstraint("availability BETWEEN 1 AND 5", name="ck_assets_availability"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_categories.id", ondelete="SET NULL"), index=True)
    owner: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    confidentiality: Mapped[int] = mapped_column(Integer, default=3)
    integrity: Mapped[int] = mapped_column(Integer, default=3)
    availability: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    category: Mapped[AssetCategory | None] = relationship(back_populates="assets")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        secondary=asset_vulnerabilities, back_populates="assets")


class Threat(Base):
    """Загроза ІБ; base_likelihood — апріорна ймовірність ініціювання (1..5)."""

    __tablename__ = "threats"
    __table_args__ = (
        CheckConstraint("base_likelihood BETWEEN 1 AND 5", name="ck_threats_likelihood"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    category_id: Mapped[int | None] = mapped_column(
        ForeignKey("threat_categories.id", ondelete="SET NULL"), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    base_likelihood: Mapped[int] = mapped_column(Integer, default=3)

    category: Mapped[ThreatCategory | None] = relationship(back_populates="threats")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        secondary=threat_vulnerabilities, back_populates="threats")


class Vulnerability(Base):
    """Вразливість; за наявності — ідентифікатор CVE і бал CVSS."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint("severity BETWEEN 1 AND 5", name="ck_vulnerabilities_severity"),
        CheckConstraint("cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
                        name="ck_vulnerabilities_cvss"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(300), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    cve_id: Mapped[str | None] = mapped_column(String(30), unique=True)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    severity: Mapped[int] = mapped_column(Integer, default=3)

    threats: Mapped[list[Threat]] = relationship(
        secondary=threat_vulnerabilities, back_populates="vulnerabilities")
    assets: Mapped[list[Asset]] = relationship(
        secondary=asset_vulnerabilities, back_populates="vulnerabilities")
    measures: Mapped[list["ProtectiveMeasure"]] = relationship(
        secondary=measure_vulnerabilities, back_populates="vulnerabilities")


class ProtectiveMeasure(Base):
    """Захід захисту (контроль) та його очікувана ефективність (0..1)."""

    __tablename__ = "protective_measures"
    __table_args__ = (
        CheckConstraint("effectiveness >= 0 AND effectiveness <= 1",
                        name="ck_measures_effectiveness"),
        CheckConstraint("measure_type IN ('preventive', 'detective', 'corrective')",
                        name="ck_measures_type"),
        CheckConstraint("cost IS NULL OR cost >= 0", name="ck_measures_cost"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    control_ref: Mapped[str | None] = mapped_column(String(50))  # ISO 27001 A.x / NIST 800-53
    measure_type: Mapped[str] = mapped_column(String(20), default="preventive")
    effectiveness: Mapped[Decimal] = mapped_column(Numeric(3, 2), default=Decimal("0.50"))
    cost: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))

    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        secondary=measure_vulnerabilities, back_populates="measures")


# --------------------------------------------------------------------------
# Ризики
# --------------------------------------------------------------------------
class ScenarioMeasure(Base):
    """Захід, застосований до конкретного сценарію (асоціація зі статусом)."""

    __tablename__ = "scenario_measures"
    __table_args__ = (
        CheckConstraint("status IN ('implemented', 'planned')", name="ck_scenario_measures_status"),
    )

    scenario_id: Mapped[int] = mapped_column(
        ForeignKey("risk_scenarios.id", ondelete="CASCADE"), primary_key=True)
    measure_id: Mapped[int] = mapped_column(
        ForeignKey("protective_measures.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="planned")

    scenario: Mapped["RiskScenario"] = relationship(back_populates="measure_links")
    measure: Mapped[ProtectiveMeasure] = relationship()


class RiskScenario(Base):
    """Сценарій ризику: загроза реалізується через вразливість щодо активу."""

    __tablename__ = "risk_scenarios"
    __table_args__ = (
        UniqueConstraint("asset_id", "threat_id", "vulnerability_id", name="uq_risk_scenario"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    threat_id: Mapped[int] = mapped_column(ForeignKey("threats.id", ondelete="RESTRICT"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped[Asset] = relationship()
    threat: Mapped[Threat] = relationship()
    vulnerability: Mapped[Vulnerability] = relationship()
    measure_links: Mapped[list[ScenarioMeasure]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan")
    assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan",
        order_by="RiskAssessment.assessed_at")


class RiskAssessment(Base):
    """Результат одного оцінювання сценарію певним методом (історія).

    score і level_id зберігаються як знімок результату методу на момент оцінки:
    правила розрахунку можуть змінюватися, а історія — ні.
    """

    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("probability BETWEEN 1 AND 5", name="ck_assessments_probability"),
        CheckConstraint("impact BETWEEN 1 AND 5", name="ck_assessments_impact"),
        CheckConstraint("score >= 0 AND score <= 25", name="ck_assessments_score"),
        CheckConstraint("residual_score IS NULL OR (residual_score >= 0 AND residual_score <= 25)",
                        name="ck_assessments_residual"),
        CheckConstraint("method IN ('matrix', 'combined')", name="ck_assessments_method"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario_id: Mapped[int] = mapped_column(
        ForeignKey("risk_scenarios.id", ondelete="CASCADE"), index=True)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow,
                                                  index=True)
    method: Mapped[str] = mapped_column(String(20), default="matrix")
    probability: Mapped[int] = mapped_column(Integer)
    impact: Mapped[int] = mapped_column(Integer)
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    level_id: Mapped[int] = mapped_column(ForeignKey("risk_levels.id", ondelete="RESTRICT"))
    residual_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 2))
    residual_level_id: Mapped[int | None] = mapped_column(
        ForeignKey("risk_levels.id", ondelete="RESTRICT"))
    notes: Mapped[str | None] = mapped_column(Text)

    scenario: Mapped[RiskScenario] = relationship(back_populates="assessments")
    level: Mapped[RiskLevel] = relationship(foreign_keys=[level_id])
    residual_level: Mapped[RiskLevel | None] = relationship(foreign_keys=[residual_level_id])
