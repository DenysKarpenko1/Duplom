"""Спільні фікстури: окрема тестова БД, схема якої створюється міграціями Alembic.

За замовчуванням — тимчасовий файл SQLite. Для перевірки на PostgreSQL:
    TEST_DATABASE_URL=postgresql+psycopg://risk:risk@localhost:5432/risk_test pytest
(БД буде повністю очищено).
"""
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def db_url(tmp_path):
    url = os.getenv("TEST_DATABASE_URL")
    if url:
        engine = create_engine(url)
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
        engine.dispose()
        return url
    return f"sqlite:///{tmp_path / 'test.db'}"


@pytest.fixture
def alembic_cfg(db_url):
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture
def engine(db_url):
    eng = create_engine(db_url)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(alembic_cfg, engine):
    command.upgrade(alembic_cfg, "head")
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client(session_factory):
    from app.database import get_db
    from app.main import app

    def override():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
