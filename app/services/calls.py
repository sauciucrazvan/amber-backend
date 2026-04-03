from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.database.models.calls import Call
from app.database.models.relationship import Relationship

ACTIVE_CALL_STATUSES = {"initiated", "ringing", "accepted"}
RINGING_CALL_STATUSES = {"initiated", "ringing"}

MAX_CONCURRENT_CALLS_PER_USER = 1

ALLOWED_TRANSITIONS = {
    ("initiated", "ringing"),
    ("ringing", "accepted"),
    ("ringing", "rejected"),
    ("ringing", "canceled"),
    ("accepted", "ended"),
    ("initiated", "missed"),
    ("ringing", "missed"),
    ("initiated", "failed"),
    ("ringing", "failed"),
    ("accepted", "failed"),
}


@dataclass(slots=True)
class CallTransitionResult:
    changed: bool
    status: str
    event: str


class CallStateError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


def _status_event_name(status: str) -> str:
    mapping = {
        "accepted": "accepted",
        "rejected": "rejected",
        "canceled": "cancel",
        "ended": "ended",
        "missed": "missed",
        "failed": "failed",
        "ringing": "ringing",
    }
    return mapping.get(status, "updated")


def count_active_calls_for_user(db: Session, user_id: int) -> int:
    return (
        db.query(Call.id)
        .filter(Call.status.in_(ACTIVE_CALL_STATUSES))
        .filter(
            or_(
                Call.caller_user_id == user_id,
                Call.callee_user_id == user_id,
            )
        )
        .count()
    )


def ensure_can_start_call(
    db: Session,
    caller_user_id: int,
    callee_user_id: int,
    *,
    callee_online: bool,
    max_concurrent_calls_per_user: int = MAX_CONCURRENT_CALLS_PER_USER,
) -> None:
    if caller_user_id == callee_user_id:
        raise CallStateError("call.invalid_target", "Cannot call yourself")

    pair_rels = (
        db.query(Relationship.relation)
        .filter(_pair_filter(caller_user_id, callee_user_id))
        .all()
    )
    relations = {relation for (relation,) in pair_rels}

    if "blocked" in relations:
        raise CallStateError("call.blocked", "Call is blocked")

    if "contact" not in relations:
        raise CallStateError("call.no_relation", "Users are not contacts")

    if not callee_online:
        raise CallStateError("call.user_offline", "Callee is offline")

    if max_concurrent_calls_per_user < 1:
        raise CallStateError("call.server_error", "Invalid max concurrent calls configuration")

    caller_active_calls = count_active_calls_for_user(db, caller_user_id)
    callee_active_calls = count_active_calls_for_user(db, callee_user_id)
    if caller_active_calls >= max_concurrent_calls_per_user or callee_active_calls >= max_concurrent_calls_per_user:
        raise CallStateError("call.busy", "One of the users is already in another call")


def create_outgoing_call(
    db: Session,
    *,
    conversation_id: str | None,
    caller_user_id: int,
    callee_user_id: int,
    call_mode: str = "video",
) -> Call:
    call = Call(
        conversation_id=conversation_id,
        caller_user_id=caller_user_id,
        callee_user_id=callee_user_id,
        status="initiated",
        call_mode=call_mode if call_mode in {"audio", "video"} else "video",
    )
    db.add(call)
    db.flush()

    transition_call_state(call, "ringing")
    return call


def transition_call_state(
    call: Call,
    target_status: str,
    *,
    actor_user_id: int | None = None,
    end_reason: str | None = None,
    at: datetime | None = None,
) -> CallTransitionResult:
    if call.status == target_status:
        return CallTransitionResult(changed=False, status=call.status, event=_status_event_name(call.status))

    transition = (call.status, target_status)
    if transition not in ALLOWED_TRANSITIONS:
        raise CallStateError("call.invalid_state", f"Cannot transition call from {call.status} to {target_status}")

    now = at or _utcnow()
    call.status = target_status

    if target_status == "accepted":
        if call.started_at is None:
            call.started_at = now
    elif target_status == "rejected":
        call.ended_at = call.ended_at or now
        call.ended_by_user_id = actor_user_id
        call.end_reason = end_reason or "rejected"
    elif target_status == "canceled":
        call.ended_at = call.ended_at or now
        call.ended_by_user_id = actor_user_id
        call.end_reason = end_reason or "canceled"
    elif target_status == "ended":
        call.ended_at = call.ended_at or now
        call.ended_by_user_id = actor_user_id
        call.end_reason = end_reason or "ended"
    elif target_status == "missed":
        call.ended_at = call.ended_at or now
        call.end_reason = end_reason or "timeout"
    elif target_status == "failed":
        call.ended_at = call.ended_at or now
        call.ended_by_user_id = actor_user_id
        call.end_reason = end_reason or "disconnect"

    return CallTransitionResult(changed=True, status=call.status, event=_status_event_name(call.status))


def fail_active_calls_for_user(
    db: Session,
    user_id: int,
    *,
    reason: str = "disconnect",
    at: datetime | None = None,
) -> list[Call]:
    active_calls = (
        db.query(Call)
        .filter(Call.status.in_(ACTIVE_CALL_STATUSES))
        .filter(
            or_(
                Call.caller_user_id == user_id,
                Call.callee_user_id == user_id,
            )
        )
        .all()
    )

    changed_calls: list[Call] = []
    for call in active_calls:
        result = transition_call_state(
            call,
            "failed",
            actor_user_id=user_id,
            end_reason=reason,
            at=at,
        )
        if result.changed:
            changed_calls.append(call)

    return changed_calls
