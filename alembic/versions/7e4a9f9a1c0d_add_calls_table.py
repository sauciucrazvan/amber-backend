"""add calls table

Revision ID: 7e4a9f9a1c0d
Revises: 1c161eed8cb9
Create Date: 2026-03-26

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7e4a9f9a1c0d"
down_revision: Union[str, Sequence[str], None] = "1c161eed8cb9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "calls",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("conversation_id", sa.String(length=32), nullable=True),
        sa.Column("caller_user_id", sa.Integer(), nullable=False),
        sa.Column("callee_user_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("end_reason", sa.String(length=32), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("caller_user_id <> callee_user_id", name="ck_calls_no_self"),
        sa.CheckConstraint(
            "status IN ('initiated', 'ringing', 'accepted', 'rejected', 'canceled', 'ended', 'missed', 'failed')",
            name="ck_calls_status",
        ),
        sa.ForeignKeyConstraint(["callee_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["caller_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["ended_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(op.f("ix_calls_conversation_id"), "calls", ["conversation_id"], unique=False)
    op.create_index(op.f("ix_calls_caller_user_id"), "calls", ["caller_user_id"], unique=False)
    op.create_index(op.f("ix_calls_callee_user_id"), "calls", ["callee_user_id"], unique=False)
    op.create_index(op.f("ix_calls_status"), "calls", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_calls_status"), table_name="calls")
    op.drop_index(op.f("ix_calls_callee_user_id"), table_name="calls")
    op.drop_index(op.f("ix_calls_caller_user_id"), table_name="calls")
    op.drop_index(op.f("ix_calls_conversation_id"), table_name="calls")
    op.drop_table("calls")
