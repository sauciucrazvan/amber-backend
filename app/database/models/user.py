from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import base

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class UserDB(base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(254), unique=True, index=True, nullable=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    
    refresh_jti: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recovery_code: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    verify_code: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    email_change_code: Mapped[int | None] = mapped_column(Integer(), nullable=True)
    email_change_new_email: Mapped[str | None] = mapped_column(String(254), nullable=True)

    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    full_name_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verify_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_change_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_change_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    data_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

