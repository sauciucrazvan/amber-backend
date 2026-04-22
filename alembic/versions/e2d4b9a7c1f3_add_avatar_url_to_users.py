"""add avatar_url to users

Revision ID: e2d4b9a7c1f3
Revises: f5a3c2b1e8d0
Create Date: 2026-04-22

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e2d4b9a7c1f3"
down_revision: Union[str, Sequence[str], None] = "f5a3c2b1e8d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
	"""Upgrade schema."""
	op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(512)")


def downgrade() -> None:
	"""Downgrade schema."""
	op.execute("ALTER TABLE users DROP COLUMN IF EXISTS avatar_url")