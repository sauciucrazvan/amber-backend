from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import base

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class Relationship(base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("user_id", "other_user_id", name="uq_relationships_user_other"),
        CheckConstraint("user_id <> other_user_id", name="ck_relationships_no_self"),
        CheckConstraint("relation IN ('contact', 'blocked')", name="ck_relationships_relation"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    other_user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    relation: Mapped[str] = mapped_column(String(16), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
