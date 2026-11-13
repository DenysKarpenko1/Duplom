"""Дерева атак сценаріїв і ймовірність реалізації в оцінюваннях.

Revision ID: 0003_attack_trees
Revises: 0002_normalize
Create Date: 2026-11-13
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_attack_trees"
down_revision = "0002_normalize"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_tree_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scenario_id", sa.Integer(),
                  sa.ForeignKey("risk_scenarios.id", ondelete="CASCADE"), nullable=False),
        sa.Column("parent_id", sa.Integer(),
                  sa.ForeignKey("attack_tree_nodes.id", ondelete="CASCADE")),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("gate", sa.String(4), nullable=False),
        sa.Column("probability", sa.Numeric(5, 4)),
        sa.Column("vulnerability_id", sa.Integer(),
                  sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL")),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.CheckConstraint("gate IN ('LEAF', 'AND', 'OR')", name="ck_tree_nodes_gate"),
        sa.CheckConstraint("probability IS NULL OR (probability >= 0 AND probability <= 1)",
                           name="ck_tree_nodes_probability"),
        sa.CheckConstraint("gate <> 'LEAF' OR probability IS NOT NULL",
                           name="ck_tree_nodes_leaf_probability"),
    )
    op.create_index("ix_attack_tree_nodes_scenario_id", "attack_tree_nodes", ["scenario_id"])
    op.create_index("ix_attack_tree_nodes_parent_id", "attack_tree_nodes", ["parent_id"])
    with op.batch_alter_table("risk_assessments") as batch:
        batch.add_column(sa.Column("likelihood", sa.Numeric(5, 4)))
        batch.add_column(sa.Column("residual_likelihood", sa.Numeric(5, 4)))


def downgrade() -> None:
    with op.batch_alter_table("risk_assessments") as batch:
        batch.drop_column("residual_likelihood")
        batch.drop_column("likelihood")
    op.drop_table("attack_tree_nodes")
