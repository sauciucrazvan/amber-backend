from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid4_hex() -> str:
    return uuid.uuid4().hex


class AuditLog(base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False, default=_uuid4_hex)
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    username: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
