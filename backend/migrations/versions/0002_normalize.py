"""Нормалізація БД: довідники, зв'язки M:N, сценарії та історія оцінювань.

Що робить upgrade:
  1. створює класифікатори (asset_categories, threat_categories, risk_levels)
     і заповнює їх базовими значеннями;
  2. створює довідники assets, threats, vulnerabilities, protective_measures;
  3. створює асоціативні таблиці M:N та таблиці ризиків;
  4. переносить дані з risks: унікальні назви -> довідники, кожен рядок ->
     сценарій (актив, загроза, вразливість) з однією матричною оцінкою;
  5. видаляє стару таблицю risks.

downgrade відновлює risks зі сценаріїв та їхніх останніх оцінок.

Revision ID: 0002_normalize
Revises: 0001_baseline
Create Date: 2026-11-13
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0002_normalize"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

# Базові значення класифікаторів (зафіксовані в міграції, а не імпортовані з коду)
RISK_LEVELS = [
    ("Низький", 1, 4, "#22c55e"),
    ("Середній", 5, 9, "#eab308"),
    ("Високий", 10, 14, "#f97316"),
    ("Критичний", 15, 25, "#dc2626"),
]
THREAT_CATEGORIES = [  # типи джерел загроз за NIST SP 800-30, Table D-2
    ("adversarial", "Навмисні", "Зовнішні та внутрішні порушники, організовані групи"),
    ("accidental", "Випадкові", "Помилкові дії користувачів та адміністраторів"),
    ("structural", "Структурні", "Відмови обладнання, ПЗ, систем життєзабезпечення"),
    ("environmental", "Природні та техногенні", "Пожежі, повені, перебої енергопостачання"),
]
ASSET_CATEGORIES = [
    ("Інформація", "Бази даних, документи, резервні копії"),
    ("Програмне забезпечення", "Прикладне та системне ПЗ, вебзастосунки"),
    ("Апаратне забезпечення", "Сервери, робочі станції, носії"),
    ("Мережа", "Мережеве обладнання та канали зв'язку"),
    ("Сервіси", "ІТ-сервіси, що надаються користувачам"),
    ("Персонал", "Працівники та їхні знання"),
]


def _cascade_fk(column: str, target: str) -> sa.Column:
    return sa.Column(column, sa.Integer(), sa.ForeignKey(target, ondelete="CASCADE"),
                     primary_key=True)


def upgrade() -> None:
    # ---------------------------------------------------------- класифікатори
    asset_categories = op.create_table(
        "asset_categories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
    )
    threat_categories = op.create_table(
        "threat_categories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(30), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
    )
    risk_levels = op.create_table(
        "risk_levels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(30), nullable=False, unique=True),
        sa.Column("min_score", sa.Integer(), nullable=False),
        sa.Column("max_score", sa.Integer(), nullable=False),
        sa.Column("color", sa.String(7), nullable=False),
        sa.CheckConstraint("min_score >= 1 AND max_score <= 25 AND min_score <= max_score",
                           name="ck_risk_levels_range"),
    )
    op.bulk_insert(asset_categories, [{"name": n, "description": d} for n, d in ASSET_CATEGORIES])
    op.bulk_insert(threat_categories,
                   [{"code": c, "name": n, "description": d} for c, n, d in THREAT_CATEGORIES])
    op.bulk_insert(risk_levels, [{"name": n, "min_score": lo, "max_score": hi, "color": c}
                                 for n, lo, hi, c in RISK_LEVELS])

    # ---------------------------------------------------------- довідники
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("category_id", sa.Integer(),
                  sa.ForeignKey("asset_categories.id", ondelete="SET NULL")),
        sa.Column("owner", sa.String(200)),
        sa.Column("description", sa.Text()),
        sa.Column("confidentiality", sa.Integer(), nullable=False),
        sa.Column("integrity", sa.Integer(), nullable=False),
        sa.Column("availability", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("confidentiality BETWEEN 1 AND 5", name="ck_assets_confidentiality"),
        sa.CheckConstraint("integrity BETWEEN 1 AND 5", name="ck_assets_integrity"),
        sa.CheckConstraint("availability BETWEEN 1 AND 5", name="ck_assets_availability"),
    )
    op.create_index("ix_assets_category_id", "assets", ["category_id"])

    op.create_table(
        "threats",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("category_id", sa.Integer(),
                  sa.ForeignKey("threat_categories.id", ondelete="SET NULL")),
        sa.Column("description", sa.Text()),
        sa.Column("base_likelihood", sa.Integer(), nullable=False),
        sa.CheckConstraint("base_likelihood BETWEEN 1 AND 5", name="ck_threats_likelihood"),
    )
    op.create_index("ix_threats_category_id", "threats", ["category_id"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("cve_id", sa.String(30), unique=True),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.CheckConstraint("severity BETWEEN 1 AND 5", name="ck_vulnerabilities_severity"),
        sa.CheckConstraint("cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
                           name="ck_vulnerabilities_cvss"),
    )

    op.create_table(
        "protective_measures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("control_ref", sa.String(50)),
        sa.Column("measure_type", sa.String(20), nullable=False),
        sa.Column("effectiveness", sa.Numeric(3, 2), nullable=False),
        sa.Column("cost", sa.Numeric(12, 2)),
        sa.CheckConstraint("effectiveness >= 0 AND effectiveness <= 1",
                           name="ck_measures_effectiveness"),
        sa.CheckConstraint("measure_type IN ('preventive', 'detective', 'corrective')",
                           name="ck_measures_type"),
        sa.CheckConstraint("cost IS NULL OR cost >= 0", name="ck_measures_cost"),
    )

    # ---------------------------------------------------------- зв'язки M:N
    op.create_table("threat_vulnerabilities",
                    _cascade_fk("threat_id", "threats.id"),
                    _cascade_fk("vulnerability_id", "vulnerabilities.id"))
    op.create_table("asset_vulnerabilities",
                    _cascade_fk("asset_id", "assets.id"),
                    _cascade_fk("vulnerability_id", "vulnerabilities.id"))
    op.create_table("measure_vulnerabilities",
                    _cascade_fk("measure_id", "protective_measures.id"),
                    _cascade_fk("vulnerability_id", "vulnerabilities.id"))

    # ---------------------------------------------------------- ризики
    op.create_table(
        "risk_scenarios",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("threat_id", sa.Integer(), sa.ForeignKey("threats.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("vulnerability_id", sa.Integer(),
                  sa.ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("asset_id", "threat_id", "vulnerability_id", name="uq_risk_scenario"),
    )
    for col in ("asset_id", "threat_id", "vulnerability_id"):
        op.create_index(f"ix_risk_scenarios_{col}", "risk_scenarios", [col])

    op.create_table(
        "scenario_measures",
        _cascade_fk("scenario_id", "risk_scenarios.id"),
        _cascade_fk("measure_id", "protective_measures.id"),
        sa.Column("status", sa.String(20), nullable=False),
        sa.CheckConstraint("status IN ('implemented', 'planned')",
                           name="ck_scenario_measures_status"),
    )

    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scenario_id", sa.Integer(),
                  sa.ForeignKey("risk_scenarios.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(20), nullable=False),
        sa.Column("probability", sa.Integer(), nullable=False),
        sa.Column("impact", sa.Integer(), nullable=False),
        sa.Column("score", sa.Numeric(5, 2), nullable=False),
        sa.Column("level_id", sa.Integer(), sa.ForeignKey("risk_levels.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("residual_score", sa.Numeric(5, 2)),
        sa.Column("residual_level_id", sa.Integer(),
                  sa.ForeignKey("risk_levels.id", ondelete="RESTRICT")),
        sa.Column("notes", sa.Text()),
        sa.CheckConstraint("probability BETWEEN 1 AND 5", name="ck_assessments_probability"),
        sa.CheckConstraint("impact BETWEEN 1 AND 5", name="ck_assessments_impact"),
        sa.CheckConstraint("score >= 0 AND score <= 25", name="ck_assessments_score"),
        sa.CheckConstraint(
            "residual_score IS NULL OR (residual_score >= 0 AND residual_score <= 25)",
            name="ck_assessments_residual"),
        sa.CheckConstraint("method IN ('matrix', 'combined')", name="ck_assessments_method"),
    )
    op.create_index("ix_risk_assessments_scenario_id", "risk_assessments", ["scenario_id"])
    op.create_index("ix_risk_assessments_assessed_at", "risk_assessments", ["assessed_at"])

    _migrate_risks_data()
    op.drop_table("risks")


def _migrate_risks_data() -> None:
    """Переносить рядки старої таблиці risks у нормалізовану схему."""
    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT asset, threat, vulnerability, probability, impact, score, created_at "
        "FROM risks ORDER BY id")).mappings().all()
    if not rows:
        return
    now = datetime.now(timezone.utc)

    def ensure(table: str, name: str, extra: dict) -> int:
        found = conn.execute(sa.text(f"SELECT id FROM {table} WHERE name = :n"),
                             {"n": name}).scalar()
        if found is not None:
            return found
        cols = {"name": name, **extra}
        conn.execute(sa.text(f"INSERT INTO {table} ({', '.join(cols)}) "
                             f"VALUES ({', '.join(':' + c for c in cols)})"), cols)
        return conn.execute(sa.text(f"SELECT id FROM {table} WHERE name = :n"),
                            {"n": name}).scalar()

    def link(table: str, a: str, b: str, ida: int, idb: int) -> None:
        exists = conn.execute(sa.text(f"SELECT 1 FROM {table} WHERE {a} = :x AND {b} = :y"),
                              {"x": ida, "y": idb}).scalar()
        if not exists:
            conn.execute(sa.text(f"INSERT INTO {table} ({a}, {b}) VALUES (:x, :y)"),
                         {"x": ida, "y": idb})

    levels = conn.execute(sa.text(
        "SELECT id, max_score FROM risk_levels ORDER BY max_score")).all()

    for r in rows:
        created = r["created_at"] or now
        asset_id = ensure("assets", r["asset"], {"confidentiality": 3, "integrity": 3,
                                                  "availability": 3, "created_at": created})
        threat_id = ensure("threats", r["threat"], {"base_likelihood": r["probability"]})
        vuln_id = ensure("vulnerabilities", r["vulnerability"], {"severity": 3})
        link("threat_vulnerabilities", "threat_id", "vulnerability_id", threat_id, vuln_id)
        link("asset_vulnerabilities", "asset_id", "vulnerability_id", asset_id, vuln_id)

        key = {"a": asset_id, "t": threat_id, "v": vuln_id}
        where = "asset_id = :a AND threat_id = :t AND vulnerability_id = :v"
        scenario_id = conn.execute(sa.text(f"SELECT id FROM risk_scenarios WHERE {where}"),
                                   key).scalar()
        if scenario_id is None:
            conn.execute(sa.text(
                "INSERT INTO risk_scenarios (asset_id, threat_id, vulnerability_id, created_at) "
                "VALUES (:a, :t, :v, :c)"), {**key, "c": created})
            scenario_id = conn.execute(sa.text(f"SELECT id FROM risk_scenarios WHERE {where}"),
                                       key).scalar()

        level_id = next((lid for lid, hi in levels if r["score"] <= hi), levels[-1][0])
        conn.execute(sa.text(
            "INSERT INTO risk_assessments "
            "(scenario_id, assessed_at, method, probability, impact, score, level_id, notes) "
            "VALUES (:s, :at, 'matrix', :p, :i, :score, :lvl, :notes)"),
            {"s": scenario_id, "at": created, "p": r["probability"], "i": r["impact"],
             "score": r["score"], "lvl": level_id, "notes": "Перенесено з таблиці risks (MVP)"})


def downgrade() -> None:
    op.create_table(
        "risks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset", sa.String(200), nullable=False),
        sa.Column("threat", sa.String(200), nullable=False),
        sa.Column("vulnerability", sa.String(300), nullable=False),
        sa.Column("probability", sa.Integer(), nullable=False),
        sa.Column("impact", sa.Integer(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    # Кожен сценарій -> один рядок з його останньою оцінкою
    op.execute(
        "INSERT INTO risks (asset, threat, vulnerability, probability, impact, score, level, "
        "created_at) "
        "SELECT a.name, t.name, v.name, ra.probability, ra.impact, "
        "CAST(ROUND(ra.score) AS INTEGER), rl.name, ra.assessed_at "
        "FROM risk_scenarios s "
        "JOIN assets a ON a.id = s.asset_id "
        "JOIN threats t ON t.id = s.threat_id "
        "JOIN vulnerabilities v ON v.id = s.vulnerability_id "
        "JOIN risk_assessments ra ON ra.id = "
        "  (SELECT MAX(id) FROM risk_assessments WHERE scenario_id = s.id) "
        "JOIN risk_levels rl ON rl.id = ra.level_id "
        "ORDER BY s.id")
    for table in ("risk_assessments", "scenario_measures", "risk_scenarios",
                  "measure_vulnerabilities", "asset_vulnerabilities", "threat_vulnerabilities",
                  "protective_measures", "vulnerabilities", "threats", "assets",
                  "risk_levels", "threat_categories", "asset_categories"):
        op.drop_table(table)
