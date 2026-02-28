from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import base

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid4_hex() -> str:
    return uuid.uuid4().hex

class Conversation(base):
    __tablename__ = "conversations"
    
    id: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False, default=_uuid4_hex)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    direct_pair: Mapped[str] = mapped_column(String, unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    participants = relationship("ConversationParticipants", back_populates="conversation")