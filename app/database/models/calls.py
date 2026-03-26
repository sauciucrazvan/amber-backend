from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid4_hex() -> str:
    return uuid.uuid4().hex


class Call(base):
    __tablename__ = "calls"
    __table_args__ = (
        CheckConstraint("caller_user_id <> callee_user_id", name="ck_calls_no_self"),
        CheckConstraint(
            "status IN ('initiated', 'ringing', 'accepted', 'rejected', 'canceled', 'ended', 'missed', 'failed')",
            name="ck_calls_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False, default=_uuid4_hex)
    conversation_id: Mapped[str | None] = mapped_column(
        String(32),
        ForeignKey("conversations.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    caller_user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    callee_user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    end_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
