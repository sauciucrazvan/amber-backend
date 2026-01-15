"""add data_requested_at to users

Revision ID: c3a1f4f0d2e1
Revises: b1d7b5f1c2a9
Create Date: 2026-01-15

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3a1f4f0d2e1"
down_revision: Union[str, Sequence[str], None] = "b1d7b5f1c2a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS data_requested_at TIMESTAMPTZ")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS data_requested_at")
