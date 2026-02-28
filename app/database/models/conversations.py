from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import base

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class Conversation(base):
    __tablename__ = "conversations"
    
    id: Mapped[str] = mapped_column(String(32), primary_key=True, nullable=False, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
