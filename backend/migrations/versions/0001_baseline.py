"""Базовий стан MVP: одна денормалізована таблиця risks.

Для вже наявної БД MVP, створеної через create_all, достатньо виконати
`alembic upgrade head`: міграція пропускає створення, якщо таблиця вже є.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-13
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("risks"):
        return
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


def downgrade() -> None:
    op.drop_table("risks")
