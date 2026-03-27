from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.api.rate_limiter import limiter, RateLimitConfig
from app.api.routes.auth import get_current_active_user
from app.database.models.calls import Call
from app.database.session import get_db
from app.services.calls import CallStateError, transition_call_state

router = APIRouter(prefix="/calls", tags=["calls"])


class CallEndRequest(BaseModel):
    reason: str | None = None


def _build_call_summary_for_user(call: Call, user_id: int, db: Session) -> dict:
    from app.ws.call_signaling import _build_call_summary

    return _build_call_summary(db, call, user_id)


@router.get("/history")
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


@router.get("/{call_id}")
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


@router.post("/{call_id}/end")
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

    return _build_call_summary_for_user(call, current_user.id, db)
