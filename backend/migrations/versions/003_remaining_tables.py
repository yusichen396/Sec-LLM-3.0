"""Create the tables that init_db() used to own (log_records, chat_histories, knowledge_files).

Revision ID: 003
Revises: 002

Keeping these in Alembic means a fresh deployment can be built either with
``alembic upgrade head`` or with the startup ``init_db()`` and end up with the
same schema.
"""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    existing = _tables()
    if "log_records" not in existing:
        op.create_table(
            "log_records",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("filename", sa.String(255), nullable=True),
            sa.Column("upload_time", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("threat_level", sa.String(50), nullable=True),
            sa.Column("attack_type", sa.String(100), nullable=True),
            sa.Column("source_ip", sa.String(50), nullable=True),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("status", sa.String(20), server_default="unresolved"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_log_records_user_id", "log_records", ["user_id"])
    if "chat_histories" not in existing:
        op.create_table(
            "chat_histories",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("title", sa.String(32), nullable=False),
            sa.Column("messages", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        )
        op.create_index("idx_chat_histories_user_id", "chat_histories", ["user_id"])
    if "knowledge_files" not in existing:
        op.create_table(
            "knowledge_files",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("filename", sa.String(255), nullable=False),
            sa.Column("upload_time", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("file_size", sa.Integer(), nullable=True),
            sa.Column("chunk_count", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(20), server_default="indexed"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_knowledge_files_user_id", "knowledge_files", ["user_id"])


def downgrade() -> None:
    existing = _tables()
    for table in ("knowledge_files", "chat_histories", "log_records"):
        if table in existing:
            op.drop_table(table)
