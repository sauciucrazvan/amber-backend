"""add call audit logs and metrics tables

Revision ID: f5a3c2b1e8d0
Revises: f43148259210
Create Date: 2026-03-28

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f5a3c2b1e8d0"
down_revision: Union[str, Sequence[str], None] = ("f43148259210", "7e4a9f9a1c0d")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create call_audit_logs table
    op.create_table(
        "call_audit_logs",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("call_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("event", sa.String(length=32), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["call_id"], ["calls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_call_audit_logs_call_id"), "call_audit_logs", ["call_id"], unique=False)
    op.create_index(op.f("ix_call_audit_logs_event"), "call_audit_logs", ["event"], unique=False)
    op.create_index(op.f("ix_call_audit_logs_created_at"), "call_audit_logs", ["created_at"], unique=False)

    # Create call_metrics table
    op.create_table(
        "call_metrics",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("call_id", sa.String(length=32), nullable=False),
        sa.Column("invites_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("accepts_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejects_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cancels_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_missed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_setup_failed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("setup_latency_ms", sa.Integer(), nullable=True),
        sa.Column("call_duration_ms", sa.Integer(), nullable=True),
        sa.Column("offer_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("answer_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_ice_candidate_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["call_id"], ["calls.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("call_id", name="uq_call_metrics_call_id"),
    )


def downgrade() -> None:
    op.drop_table("call_metrics")
    op.drop_table("call_audit_logs")
