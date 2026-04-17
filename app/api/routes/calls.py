import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.api.rate_limiter import limiter, RateLimitConfig
from app.api.routes.auth import get_current_active_user
from app.database.models.calls import Call
from app.database.models.call_audit_log import CallAuditLog
from app.database.models.call_metrics import CallMetrics
from app.database.session import get_db
from app.services.calls import CallStateError, transition_call_state

router = APIRouter(prefix="/calls", tags=["calls"])


class CallEndRequest(BaseModel):
    reason: str | None = None


def _build_call_summary_for_user(call: Call, user_id: int, db: Session) -> dict:
    from app.ws.call_signaling import _build_call_summary

    return _build_call_summary(db, call, user_id)


@router.get("/v1/history")
@limiter.limit(RateLimitConfig.READ)
def get_call_history(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
    limit: int = 50,
    offset: int = 0,
):
    if limit < 1 or limit > 100:
        limit = 50
    if offset < 0:
        offset = 0

    total_count = (
        db.query(Call)
        .filter(
            (Call.caller_user_id == current_user.id) | (Call.callee_user_id == current_user.id)
        )
        .count()
    )

    calls = (
        db.query(Call)
        .filter(
            (Call.caller_user_id == current_user.id) | (Call.callee_user_id == current_user.id)
        )
        .order_by(Call.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "calls": [_build_call_summary_for_user(call, current_user.id, db) for call in calls],
    }


@router.get("/v1/{call_id}")
@limiter.limit(RateLimitConfig.READ)
def get_call_detail(
    call_id: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
):
    call = db.query(Call).filter(Call.id == call_id).one_or_none()

    if call is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="calls.not_found")

    if call.caller_user_id != current_user.id and call.callee_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="calls.forbidden")

    return _build_call_summary_for_user(call, current_user.id, db)


@router.post("/v1/{call_id}/end")
@limiter.limit(RateLimitConfig.WRITE)
def end_call_http(
    call_id: str,
    data: CallEndRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
):
    call = db.query(Call).filter(Call.id == call_id).one_or_none()

    if call is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="calls.not_found")

    if call.caller_user_id != current_user.id and call.callee_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="calls.forbidden")

    if call.status not in {"accepted"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="calls.not_in_progress",
        )

    try:
        outcome = transition_call_state(
            call,
            "ended",
            actor_user_id=current_user.id,
            end_reason=data.reason or "ended",
        )
    except CallStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.code,
        )

    if not outcome.changed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="calls.already_ended",
        )

    db.commit()
    db.refresh(call)

    from app.ws.call_signaling import _emit_call_chat_log
    from app.ws.connection_manager import manager

    try:
        asyncio.run(
            _emit_call_chat_log(
                manager,
                db,
                call,
                event="finished",
                actor_user_id=current_user.id,
            )
        )
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                _emit_call_chat_log(
                    manager,
                    db,
                    call,
                    event="finished",
                    actor_user_id=current_user.id,
                )
            )
        finally:
            loop.close()

    return _build_call_summary_for_user(call, current_user.id, db)


@router.get("/v1/{call_id}/audit-logs")
@limiter.limit(RateLimitConfig.READ)
def get_call_audit_logs(
    call_id: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
):
    """Get structured audit logs for a call (for troubleshooting)."""
    call = db.query(Call).filter(Call.id == call_id).one_or_none()

    if call is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="calls.not_found")

    if call.caller_user_id != current_user.id and call.callee_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="calls.forbidden")

    audit_logs = (
        db.query(CallAuditLog)
        .filter(CallAuditLog.call_id == call_id)
        .order_by(CallAuditLog.created_at.asc())
        .all()
    )

    return {
        "call_id": call_id,
        "audit_logs": [
            {
                "id": log.id,
                "event": log.event,
                "user_id": log.user_id,
                "details": log.details,
                "error_code": log.error_code,
                "error_message": log.error_message,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in audit_logs
        ],
    }


@router.get("/v1/{call_id}/metrics")
@limiter.limit(RateLimitConfig.READ)
def get_call_metrics(
    call_id: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
):
    """Get metrics/analytics for a call."""
    call = db.query(Call).filter(Call.id == call_id).one_or_none()

    if call is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="calls.not_found")

    if call.caller_user_id != current_user.id and call.callee_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="calls.forbidden")

    metrics = db.query(CallMetrics).filter(CallMetrics.call_id == call_id).one_or_none()

    if metrics is None:
        # Return default metrics if none exist
        metrics = CallMetrics(call_id=call_id)

    return {
        "call_id": call_id,
        "invites_sent": metrics.invites_sent,
        "accepts_received": metrics.accepts_received,
        "rejects_received": metrics.rejects_received,
        "cancels_received": metrics.cancels_received,
        "is_missed": metrics.is_missed,
        "is_setup_failed": metrics.is_setup_failed,
        "setup_latency_ms": metrics.setup_latency_ms,
        "call_duration_ms": metrics.call_duration_ms,
        "offer_received_at": metrics.offer_received_at.isoformat() if metrics.offer_received_at else None,
        "answer_received_at": metrics.answer_received_at.isoformat() if metrics.answer_received_at else None,
        "first_ice_candidate_at": metrics.first_ice_candidate_at.isoformat() if metrics.first_ice_candidate_at else None,
    }

