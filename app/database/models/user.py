from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.database.session import base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserDB(base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    email = Column(String(254), unique=True, index=True, nullable=True)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    disabled = Column(Boolean, nullable=False, default=False)
    registered_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    refresh_jti = Column(String(128), nullable=True)
