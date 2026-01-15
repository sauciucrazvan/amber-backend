"""add recovery fields to users

Revision ID: b1d7b5f1c2a9
Revises: 76ba219a9356
Create Date: 2026-01-15

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b1d7b5f1c2a9"
down_revision: Union[str, Sequence[str], None] = "76ba219a9356"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Use IF NOT EXISTS to handle DBs created outside of Alembic
    # or where the initial migration missed these columns.
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code INTEGER")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_sent_at TIMESTAMPTZ")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS recovery_sent_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS recovery_code")
