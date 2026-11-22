"""Add scan_findings: findings become queryable rows instead of a JSON blob.

Revision ID: 005
Revises: 004
"""
from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "scan_findings" in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(8), nullable=False),
        sa.Column("evidence_id", sa.String(64), nullable=True),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("target", sa.String(500), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
    )
    # 按会话查发现是报告页和复盘的主路径
    op.create_index("idx_scan_findings_session", "scan_findings", ["session_id"])
    op.create_index("idx_scan_findings_severity", "scan_findings", ["severity"])


def downgrade() -> None:
    if "scan_findings" in set(sa.inspect(op.get_bind()).get_table_names()):
        op.drop_table("scan_findings")
