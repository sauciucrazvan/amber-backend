"""merge heads

Revision ID: 6c3a6c401e57
Revises: a9c41f3d2e7b, b7a9e8d3f4c1, e2d4b9a7c1f3
Create Date: 2026-04-30 13:02:13.903396

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6c3a6c401e57'
down_revision: Union[str, Sequence[str], None] = ('a9c41f3d2e7b', 'b7a9e8d3f4c1', 'e2d4b9a7c1f3')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
