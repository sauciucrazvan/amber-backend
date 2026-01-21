from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _is_expired(sent_at: datetime | None, *, now: datetime, ttl: timedelta) -> bool:
    if sent_at is None:
        return True
    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)
    return now - sent_at > ttl
