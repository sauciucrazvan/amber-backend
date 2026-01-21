"""create relationships table

Revision ID: 9f2c1c0a4b7d
Revises: 8d2f1c3a4b5e
Create Date: 2026-01-21

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9f2c1c0a4b7d"
down_revision: Union[str, Sequence[str], None] = "8d2f1c3a4b5e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "relationships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("other_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("user_id", "other_user_id", name="uq_relationships_user_other"),
        sa.CheckConstraint("user_id <> other_user_id", name="ck_relationships_no_self"),
        sa.CheckConstraint("relation IN ('contact', 'blocked')", name="ck_relationships_relation"),
    )

    op.create_index("ix_relationships_user_id", "relationships", ["user_id"], unique=False)
    op.create_index("ix_relationships_other_user_id", "relationships", ["other_user_id"], unique=False)
    op.create_index("ix_relationships_user_relation", "relationships", ["user_id", "relation"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_relationships_user_relation", table_name="relationships")
    op.drop_index("ix_relationships_other_user_id", table_name="relationships")
    op.drop_index("ix_relationships_user_id", table_name="relationships")
    op.drop_table("relationships")
