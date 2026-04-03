"""add call mode to calls

Revision ID: b7a9e8d3f4c1
Revises: f5a3c2b1e8d0
Create Date: 2026-04-03

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b7a9e8d3f4c1"
down_revision: Union[str, Sequence[str], None] = "f5a3c2b1e8d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "calls",
        sa.Column("call_mode", sa.String(length=8), nullable=False, server_default=sa.text("'video'")),
    )
    op.create_check_constraint(
        "ck_calls_call_mode",
        "calls",
        "call_mode IN ('audio', 'video')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_calls_call_mode", "calls", type_="check")
    op.drop_column("calls", "call_mode")
