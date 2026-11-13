"""Підключення до бази даних.

За замовчуванням використовується локальний файл SQLite, щоб MVP запускався
без додаткового ПЗ. Для PostgreSQL достатньо задати змінну середовища, напр.:
DATABASE_URL=postgresql+psycopg://risk:risk@localhost:5432/risk
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./risk.db")

# check_same_thread потрібен лише для SQLite
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
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
