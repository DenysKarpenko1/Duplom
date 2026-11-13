"""Підключення до бази даних.

За замовчуванням використовується локальний файл SQLite, щоб MVP запускався
без додаткового ПЗ. Для PostgreSQL достатньо задати змінну середовища, напр.:
DATABASE_URL=postgresql+psycopg://risk:risk@localhost:5432/risk
"""
import os

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./risk.db")

# check_same_thread потрібен лише для SQLite
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)


@event.listens_for(Engine, "connect")
def _sqlite_foreign_keys(dbapi_connection, _record):
    """SQLite за замовчуванням ігнорує зовнішні ключі та ON DELETE CASCADE."""
    if type(dbapi_connection).__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """Залежність FastAPI: видає сесію БД на час одного запиту."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
