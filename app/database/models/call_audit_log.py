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


class CallAuditLog(base):
    __tablename__ = "call_audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False, default=_uuid4_hex)
    call_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("calls.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    
    event: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(256), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
