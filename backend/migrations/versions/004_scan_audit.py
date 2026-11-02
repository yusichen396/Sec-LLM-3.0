"""Add the scan audit trail.

Revision ID: 004
Revises: 003
"""
from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "scan_audit" in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        "scan_audit",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(8), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("task_type", sa.String(50), nullable=True),
        sa.Column("authorization_ref", sa.String(200), nullable=True),
        sa.Column("scope_json", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), server_default="running"),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_scan_audit_session"),
    )
    op.create_index("idx_scan_audit_user", "scan_audit", ["user_id"])


def downgrade() -> None:
    if "scan_audit" in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table("scan_audit")
