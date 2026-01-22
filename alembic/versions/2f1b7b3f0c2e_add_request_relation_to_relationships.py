"""add request relation to relationships

Revision ID: 2f1b7b3f0c2e
Revises: 9f2c1c0a4b7d
Create Date: 2026-01-22

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "2f1b7b3f0c2e"
down_revision: Union[str, Sequence[str], None] = "9f2c1c0a4b7d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_relationships_relation", "relationships", type_="check")
    op.create_check_constraint(
        "ck_relationships_relation",
        "relationships",
        "relation IN ('contact', 'blocked', 'request')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_relationships_relation", "relationships", type_="check")
    op.create_check_constraint(
        "ck_relationships_relation",
        "relationships",
        "relation IN ('contact', 'blocked')",
    )
