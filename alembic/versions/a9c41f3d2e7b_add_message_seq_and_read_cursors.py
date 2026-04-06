"""add message seq and conversation read cursors

Revision ID: a9c41f3d2e7b
Revises: f5a3c2b1e8d0
Create Date: 2026-04-06

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a9c41f3d2e7b"
down_revision: Union[str, Sequence[str], None] = "f5a3c2b1e8d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("messages", sa.Column("seq", sa.Integer(), nullable=True))

    op.execute(
        """
        WITH ranked_messages AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY conversation_id
                       ORDER BY created_at ASC, id ASC
                   ) AS next_seq
            FROM messages
        )
        UPDATE messages
        SET seq = ranked_messages.next_seq
        FROM ranked_messages
        WHERE messages.id = ranked_messages.id;
        """
    )

    op.alter_column("messages", "seq", nullable=False)
    op.create_index(
        "ix_messages_conversation_id_seq",
        "messages",
        ["conversation_id", "seq"],
        unique=True,
    )

    op.create_table(
        "conversation_read_cursors",
        sa.Column("conversation_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("last_seen_seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("conversation_id", "user_id"),
    )
    op.create_index(
        "ix_conversation_read_cursors_user_id",
        "conversation_read_cursors",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_conversation_read_cursors_user_id", table_name="conversation_read_cursors")
    op.drop_table("conversation_read_cursors")

    op.drop_index("ix_messages_conversation_id_seq", table_name="messages")
    op.drop_column("messages", "seq")
