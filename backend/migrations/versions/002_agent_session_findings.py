"""Persist complete Agent findings alongside session progress.

Revision ID: 002
Revises: 001
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("agent_sessions")}
    if "findings" not in columns:
        op.add_column("agent_sessions", sa.Column("findings", sa.JSON(), nullable=True))


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("agent_sessions")}
    if "findings" in columns:
        op.drop_column("agent_sessions", "findings")
