from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from app.database.models import AuditLog

logger = logging.getLogger(__name__)
_MAX_UA_LEN = 256


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip", "").strip()
    host = request.client.host if request.client and request.client.host else ""
    return forwarded_for or real_ip or host or "unknown"


def get_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "").strip()


def log_event(
    db: Session,
    *,
    request: Request,
    event: str,
    status_code: int,
    username: str | None,
    user_id: int | None,
    details: str | None = None,
) -> None:
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)
    logger.info(
        "audit_event event=%s user=%s user_id=%s ip=%s status=%s",
        event,
        username,
        user_id,
        client_ip,
        status_code,
    )
    try:
        log_row = AuditLog(
            user_id=user_id,
            username=username,
            event=event,
            ip=client_ip or None,
            user_agent=user_agent[:_MAX_UA_LEN] or None,
            status_code=status_code,
            details=details,
        )
        db.add(log_row)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception(
            "Failed to persist audit log event=%s user=%s ip=%s",
            event,
            username,
            client_ip,
        )
