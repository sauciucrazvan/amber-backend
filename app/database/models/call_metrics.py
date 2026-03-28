from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid4_hex() -> str:
    return uuid.uuid4().hex


class CallMetrics(base):
    __tablename__ = "call_metrics"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False, default=_uuid4_hex)
    call_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("calls.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    
    invites_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    accepts_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejects_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cancels_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    is_missed: Mapped[bool] = mapped_column(nullable=False, default=False)
    is_setup_failed: Mapped[bool] = mapped_column(nullable=False, default=False)
    
    setup_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)  # Time from ringing to accepted
    call_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)  # Time from accepted to ended
    
    offer_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    answer_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_ice_candidate_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
