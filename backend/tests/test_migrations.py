"""Міграції: перенесення даних MVP, відкат і відповідність моделям."""
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text

from app import models  # noqa: F401
from app.database import Base

LEGACY_ROWS = [
    ("БД клієнтів", "Несанкціонований доступ", "Невиправлена вразливість", 4, 5, 20, "Критичний"),
    ("БД клієнтів", "Втрата даних", "Немає контролю змін", 1, 4, 4, "Низький"),
    ("Вебпортал", "Несанкціонований доступ", "Невиправлена вразливість", 3, 3, 9, "Середній"),
]


def _insert_legacy(engine):
    with engine.begin() as conn:
        for row in LEGACY_ROWS:
            conn.execute(text(
                "INSERT INTO risks (asset, threat, vulnerability, probability, impact, score, "
                "level, created_at) VALUES (:a, :t, :v, :p, :i, :s, :l, CURRENT_TIMESTAMP)"),
                dict(zip("atvpisl", row)))


def test_upgrade_migrates_legacy_data(alembic_cfg, engine):
    command.upgrade(alembic_cfg, "0001_baseline")
    _insert_legacy(engine)
    command.upgrade(alembic_cfg, "head")

    assert not inspect(engine).has_table("risks")
    with engine.connect() as conn:
        count = lambda t: conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar()  # noqa: E731
        # дублікати назв злилися в один запис довідника
        assert count("assets") == 2
        assert count("threats") == 2
        assert count("vulnerabilities") == 2
        assert count("risk_scenarios") == 3
        assert count("risk_assessments") == 3
        assert count("threat_vulnerabilities") == 2
        assert count("asset_vulnerabilities") == 3
        assert count("risk_levels") == 4
        assert count("threat_categories") == 4
        levels = conn.execute(text(
            "SELECT ra.score, rl.name FROM risk_assessments ra "
            "JOIN risk_levels rl ON rl.id = ra.level_id ORDER BY ra.score")).all()
        assert [(float(s), n) for s, n in levels] == [
            (4.0, "Низький"), (9.0, "Середній"), (20.0, "Критичний")]


def test_downgrade_restores_risks(alembic_cfg, engine):
    command.upgrade(alembic_cfg, "0001_baseline")
    _insert_legacy(engine)
    command.upgrade(alembic_cfg, "head")
    command.downgrade(alembic_cfg, "0001_baseline")

    tables = set(inspect(engine).get_table_names())
    assert "risks" in tables and "assets" not in tables
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT asset, threat, vulnerability, probability, impact, score, level "
            "FROM risks ORDER BY id")).all()
    assert sorted(map(tuple, rows)) == sorted(LEGACY_ROWS)

    command.upgrade(alembic_cfg, "head")  # повторний upgrade теж працює


def test_models_match_migrations(alembic_cfg, engine):
    command.upgrade(alembic_cfg, "head")
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(ctx, Base.metadata) == []
