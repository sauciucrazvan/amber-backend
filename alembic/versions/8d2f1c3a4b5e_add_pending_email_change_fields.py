"""add pending email change fields

Revision ID: 8d2f1c3a4b5e
Revises: 0b4afa9079dc
Create Date: 2026-01-20

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8d2f1c3a4b5e"
down_revision: Union[str, Sequence[str], None] = "0b4afa9079dc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("users", sa.Column("email_change_new_email", sa.String(length=254), nullable=True))
    op.add_column("users", sa.Column("email_change_confirmed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("users", "email_change_confirmed_at")
    op.drop_column("users", "email_change_new_email")
