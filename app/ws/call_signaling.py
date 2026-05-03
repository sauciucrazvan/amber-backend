from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import WebSocket
from pydantic import ValidationError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from app.api.utils.user import get_user_db_row_by_username
from app.api.models.call import validate_webrtc_payload
from app.database.models.calls import Call
from app.database.models.call_audit_log import CallAuditLog
from app.database.models.call_metrics import CallMetrics
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.conversations import Conversation
from app.database.models.messages import Messages
from app.database.models.user import UserDB
from app.database.session import getSession
from app.services.calls import (
    RINGING_CALL_STATUSES,
    CallStateError,
    create_outgoing_call,
    ensure_can_start_call,
    fail_active_calls_for_user,
    transition_call_state,
)

CALL_TIMEOUT_SECONDS = 30
MEDIA_SETUP_TIMEOUT_SECONDS = 20

# Payload size limits (in bytes)
MAX_OFFER_SIZE = 65536  # 64KB
MAX_ANSWER_SIZE = 65536  # 64KB
MAX_ICE_CANDIDATE_SIZE = 1024  # 1KB

# Rate limiting state: user_id -> list of timestamps
_invite_rate_limit_state: dict[int, list[datetime]] = {}
INVITE_RATE_LIMIT_PER_MINUTE = 30

_ringing_timeout_tasks: dict[str, asyncio.Task] = {}
_media_setup_timeout_tasks: dict[str, asyncio.Task] = {}


def _find_direct_conversation_id(db, user_a_id: int, user_b_id: int) -> str | None:
    sorted_ids = sorted([str(user_a_id), str(user_b_id)])
    pair_key = f"{sorted_ids[0]}:{sorted_ids[1]}"
    conversation = (
        db.query(Conversation.id)
        .filter(Conversation.direct_pair == pair_key)
        .one_or_none()
    )
    if conversation is None:
        return None
    return conversation[0]


def _get_or_create_direct_conversation_id(db, user_a_id: int, user_b_id: int) -> str:
    conversation_id = _find_direct_conversation_id(db, user_a_id, user_b_id)
    if conversation_id is not None:
        return conversation_id

    sorted_ids = sorted([str(user_a_id), str(user_b_id)])
    pair_key = f"{sorted_ids[0]}:{sorted_ids[1]}"

    try:
        conversation = Conversation(type="direct", direct_pair=pair_key)
        db.add(conversation)
        db.flush()

        db.add_all(
            [
                ConversationParticipants(conversation_id=conversation.id, user_id=user_a_id),
                ConversationParticipants(conversation_id=conversation.id, user_id=user_b_id),
            ]
        )
        db.flush()
        return conversation.id
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(Conversation.id)
            .filter(Conversation.direct_pair == pair_key)
            .one()
        )
        return existing[0]


def _is_user_active(user: UserDB) -> bool:
    """Check if user is active (not disabled)."""
    return not user.disabled


def _audit_log(db, call_id: str, event: str, user_id: int | None = None, details: str | None = None, error_code: str | None = None, error_message: str | None = None) -> None:
    """Record audit log for call event."""
    try:
        log_entry = CallAuditLog(
            call_id=call_id,
            user_id=user_id,
            event=event,
            details=details,
            error_code=error_code,
            error_message=error_message,
        )
        db.add(log_entry)
        db.flush()
    except Exception:
        # Silently fail audit logging to not disrupt call flow
        pass


def _check_invite_rate_limit(user_id: int) -> bool:
    """
    Check if user has exceeded invite rate limit.
    Returns True if limit exceeded, False otherwise.
    """
    now = datetime.now(timezone.utc)

    if user_id not in _invite_rate_limit_state:
        _invite_rate_limit_state[user_id] = []

    # Remove timestamps older than 1 minute
    cutoff = now - timedelta(seconds=60)
    _invite_rate_limit_state[user_id] = [
        ts for ts in _invite_rate_limit_state[user_id]
        if ts >= cutoff
    ]

    # Check if limit exceeded
    if len(_invite_rate_limit_state[user_id]) >= INVITE_RATE_LIMIT_PER_MINUTE:
        return True

    # Add current timestamp
    _invite_rate_limit_state[user_id].append(now)
    return False


def _get_or_create_call_metrics(db, call_id: str) -> CallMetrics:
    """Get or create metrics entry for a call."""
    metrics = db.query(CallMetrics).filter(CallMetrics.call_id == call_id).one_or_none()
    if metrics is None:
        metrics = CallMetrics(call_id=call_id)
        db.add(metrics)
        db.flush()
    return metrics


def _update_call_metrics(db, call_id: str, **kwargs) -> None:
    """Update call metrics."""
    try:
        metrics = _get_or_create_call_metrics(db, call_id)
        for key, value in kwargs.items():
            if hasattr(metrics, key):
                setattr(metrics, key, value)
        db.flush()
    except Exception:
        # Silently fail metrics update to not disrupt call flow
        pass


def _is_participant(call: Call, user_id: int) -> bool:
    return call.caller_user_id == user_id or call.callee_user_id == user_id


def _other_participant_id(call: Call, user_id: int) -> int:
    if call.caller_user_id == user_id:
        return call.callee_user_id
    return call.caller_user_id


def _duration_seconds(call: Call) -> int:
    if call.started_at is None or call.ended_at is None:
        return 0

    started_at = call.started_at
    ended_at = call.ended_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    if ended_at.tzinfo is None:
        ended_at = ended_at.replace(tzinfo=timezone.utc)

    return max(0, int((ended_at - started_at).total_seconds()))


def _build_call_summary(db, call: Call, viewer_user_id: int) -> dict[str, Any]:
    peer_user_id = _other_participant_id(call, viewer_user_id)
    peer_user = db.query(UserDB).filter(UserDB.id == peer_user_id).one()

    summary = {
        "call_id": call.id,
        "status": call.status,
        "conversation_id": call.conversation_id,
        "call_mode": call.call_mode,
        "peer": {
            "id": peer_user.id,
            "username": peer_user.username,
            "display_name": peer_user.full_name or peer_user.username,
            "avatar_url": peer_user.avatar_url,
            "last_active_at": peer_user.last_active_at.isoformat() if peer_user.last_active_at else None,
        },
        "started_at": call.started_at.isoformat() if call.started_at else None,
        "ended_at": call.ended_at.isoformat() if call.ended_at else None,
        "duration_seconds": _duration_seconds(call),
        "end_reason": call.end_reason,
        "ended_by_user_id": call.ended_by_user_id,
    }

    if call.ended_by_user_id is not None:
        ended_by_user = db.query(UserDB).filter(UserDB.id == call.ended_by_user_id).one_or_none()
        if ended_by_user:
            summary["ended_by"] = {
                "id": ended_by_user.id,
                "username": ended_by_user.username,
                "display_name": ended_by_user.full_name or ended_by_user.username,
            }

    return summary


def _cancel_ringing_timeout(call_id: str) -> None:
    task = _ringing_timeout_tasks.pop(call_id, None)
    if task is not None:
        task.cancel()


def _cancel_media_setup_timeout(call_id: str) -> None:
    task = _media_setup_timeout_tasks.pop(call_id, None)
    if task is not None:
        task.cancel()


def _cancel_all_timeouts(call_id: str) -> None:
    _cancel_ringing_timeout(call_id)
    _cancel_media_setup_timeout(call_id)


def _serialize_chat_message(message: Messages) -> dict[str, Any]:
    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "seq": message.seq,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
        "edited_at": message.edited_at.isoformat() if message.edited_at else None,
        "seen": message.seen,
    }


def _build_call_log_text(event: str, actor_display_name: str | None) -> str:
    if event == "initiated":
        return f"{actor_display_name or 'Someone'} started a call"
    if event == "accepted":
        return f"{actor_display_name or 'Someone'} accepted the call"
    if event == "rejected":
        return f"{actor_display_name or 'Someone'} rejected the call"
    if event == "missed":
        return "Missed call"
    if event == "finished":
        if actor_display_name:
            return f"{actor_display_name} finished the call"
        return "Call finished"
    return "Call updated"


async def _emit_call_chat_log(
    manager: Any,
    db,
    call: Call,
    *,
    event: str,
    actor_user_id: int | None,
) -> None:
    if not call.conversation_id:
        return

    try:
        actor = None
        if actor_user_id is not None:
            actor = db.query(UserDB).filter(UserDB.id == actor_user_id).one_or_none()

        actor_display_name = None
        if actor is not None:
            actor_display_name = actor.full_name or actor.username

        sender_id = actor_user_id if actor_user_id is not None else call.caller_user_id
        log_message = Messages(
            conversation_id=call.conversation_id,
            sender_id=sender_id,
            seq=(
                int(
                    db.query(func.max(Messages.seq))
                    .filter(Messages.conversation_id == call.conversation_id)
                    .scalar()
                    or 0
                )
                + 1
            ),
            type="log",
            content={
                "text": _build_call_log_text(event, actor_display_name),
                "event": f"call.{event}",
                "call_id": call.id,
                "status": call.status,
                "actor_user_id": actor_user_id,
                "actor_display_name": actor_display_name,
                "actor_username": actor.username if actor is not None else None,
            },
        )
        db.add(log_message)
        db.commit()
        db.refresh(log_message)

        usernames = [
            username
            for (username,) in db.query(UserDB.username)
            .join(ConversationParticipants, ConversationParticipants.user_id == UserDB.id)
            .filter(ConversationParticipants.conversation_id == call.conversation_id)
            .all()
        ]
        if not usernames:
            return

        await manager.send_json_to_usernames(
            usernames,
            {
                "event": "message.created",
                "conversation_id": call.conversation_id,
                "payload": {
                    "message": _serialize_chat_message(log_message),
                },
            },
        )
    except Exception:
        # Chat log emission should not break call signaling.
        db.rollback()


async def _send_error(websocket: WebSocket, code: str, message: str) -> None:
    await websocket.send_json(
        {
            "type": "error",
            "code": code,
            "message": message,
        }
    )


async def _send_ack(websocket: WebSocket, event: str, payload: dict[str, Any]) -> None:
    await websocket.send_json(
        {
            "type": "ack",
            "event": event,
            "payload": payload,
        }
    )


async def _notify_call_state(manager: Any, db, call: Call, event: str) -> None:
    caller = db.query(UserDB).filter(UserDB.id == call.caller_user_id).one()
    callee = db.query(UserDB).filter(UserDB.id == call.callee_user_id).one()

    caller_payload = {
        "type": "call",
        "event": event,
        "payload": _build_call_summary(db, call, caller.id),
    }
    callee_payload = {
        "type": "call",
        "event": event,
        "payload": _build_call_summary(db, call, callee.id),
    }

    await manager.send_json_to_username(caller.username, caller_payload)
    await manager.send_json_to_username(callee.username, callee_payload)


async def _ringing_timeout(call_id: str, manager: Any, timeout_seconds: int) -> None:
    try:
        await asyncio.sleep(timeout_seconds)

        db = getSession()
        try:
            call = db.query(Call).filter(Call.id == call_id).one_or_none()
            if call is None or call.status not in RINGING_CALL_STATUSES:
                return

            outcome = transition_call_state(call, "missed", end_reason="timeout")
            if not outcome.changed:
                return

            db.commit()
            db.refresh(call)

            # Log missed call and update metrics
            _audit_log(db, call_id, "missed", details="Timeout during ringing")
            _update_call_metrics(db, call_id, is_missed=True)
            db.commit()

            await _emit_call_chat_log(
                manager,
                db,
                call,
                event="missed",
                actor_user_id=None,
            )

            await _notify_call_state(manager, db, call, outcome.event)
        finally:
            db.close()
    except asyncio.CancelledError:
        return
    finally:
        _ringing_timeout_tasks.pop(call_id, None)


def _schedule_ringing_timeout(call_id: str, manager: Any, timeout_seconds: int = CALL_TIMEOUT_SECONDS) -> None:
    _cancel_ringing_timeout(call_id)
    _ringing_timeout_tasks[call_id] = asyncio.create_task(_ringing_timeout(call_id, manager, timeout_seconds))


async def _media_setup_timeout(call_id: str, manager: Any, timeout_seconds: int) -> None:
    try:
        await asyncio.sleep(timeout_seconds)

        db = getSession()
        try:
            call = db.query(Call).filter(Call.id == call_id).one_or_none()
            if call is None or call.status != "accepted":
                return

            try:
                outcome = transition_call_state(call, "failed", end_reason="media-timeout")
            except CallStateError:
                return

            if not outcome.changed:
                return

            db.commit()
            db.refresh(call)

            # Log media setup failure and update metrics
            _audit_log(db, call_id, "media_setup_timeout", details="Media setup did not complete in time")
            _update_call_metrics(db, call_id, is_setup_failed=True)
            db.commit()

            await _notify_call_state(manager, db, call, outcome.event)
        finally:
            db.close()
    except asyncio.CancelledError:
        return
    finally:
        _media_setup_timeout_tasks.pop(call_id, None)


def _schedule_media_setup_timeout(
    call_id: str,
    manager: Any,
    timeout_seconds: int = MEDIA_SETUP_TIMEOUT_SECONDS,
) -> None:
    _cancel_media_setup_timeout(call_id)
    _media_setup_timeout_tasks[call_id] = asyncio.create_task(
        _media_setup_timeout(call_id, manager, timeout_seconds)
    )


def _validate_call_conversation(db, conversation_id: str, caller_user_id: int, callee_user_id: int) -> str | None:
    participants = (
        db.query(ConversationParticipants.user_id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    )
    participant_ids = {user_id for (user_id,) in participants}
    if {caller_user_id, callee_user_id}.issubset(participant_ids):
        return conversation_id

    return None


async def _handle_invite(websocket: WebSocket, manager: Any, sender_username: str, message: dict[str, Any]) -> None:
    target_username = str(message.get("to") or "").strip().lower()
    if not target_username:
        await _send_error(websocket, "call.invalid_target", "Missing callee username")
        return

    if target_username == sender_username:
        await _send_error(websocket, "call.invalid_target", "Cannot call yourself")
        return

    db = getSession()
    try:
        caller = get_user_db_row_by_username(db, sender_username)
        callee = get_user_db_row_by_username(db, target_username)
        if caller is None or callee is None:
            await _send_error(websocket, "call.invalid_target", "Invalid callee")
            return

        # Validate that both users are active
        if not _is_user_active(caller):
            await _send_error(websocket, "call.forbidden", "Caller account is disabled")
            return
        
        if not _is_user_active(callee):
            await _send_error(websocket, "call.forbidden", "Callee account is disabled")
            return

        # Rate limit: check if caller has exceeded invite limit
        if _check_invite_rate_limit(caller.id):
            await _send_error(websocket, "call.rate_limited", f"Too many invites. Max {INVITE_RATE_LIMIT_PER_MINUTE} per minute")
            _audit_log(db, "", "invite_rate_limit_exceeded", caller.id, f"User exceeded rate limit")
            return

        existing_call = (
            db.query(Call)
            .filter(Call.caller_user_id == caller.id)
            .filter(Call.callee_user_id == callee.id)
            .filter(Call.status.in_(RINGING_CALL_STATUSES))
            .order_by(Call.created_at.desc())
            .first()
        )
        if existing_call is not None:
            await _send_ack(
                websocket,
                "call.invite",
                {
                    "call_id": existing_call.id,
                    "status": existing_call.status,
                    "duplicate": True,
                },
            )
            return

        try:
            ensure_can_start_call(
                db,
                caller.id,
                callee.id,
                callee_online=manager.is_user_online(callee.username),
            )
        except CallStateError as exc:
            await _send_error(websocket, exc.code, exc.message)
            _audit_log(db, "", "invite_validation_failed", caller.id, error_code=exc.code)
            return

        conversation_id = None
        requested_conversation_id = str(message.get("conversation_id") or "").strip()
        requested_mode = str(message.get("mode") or message.get("call_mode") or "video").strip().lower()
        call_mode = requested_mode if requested_mode in {"audio", "video"} else "video"
        if requested_conversation_id:
            conversation_id = _validate_call_conversation(db, requested_conversation_id, caller.id, callee.id)
        if conversation_id is None:
            conversation_id = _get_or_create_direct_conversation_id(db, caller.id, callee.id)

        call = create_outgoing_call(
            db,
            conversation_id=conversation_id,
            caller_user_id=caller.id,
            callee_user_id=callee.id,
            call_mode=call_mode,
        )
        db.commit()
        db.refresh(call)

        # Log invite action
        _audit_log(db, call.id, "invite", caller.id)
        _update_call_metrics(db, call.id, invites_sent=1)
        db.commit()

        await _emit_call_chat_log(
            manager,
            db,
            call,
            event="initiated",
            actor_user_id=caller.id,
        )

        await _send_ack(
            websocket,
            "call.invite",
            {
                "call_id": call.id,
                "status": call.status,
                "call_mode": call.call_mode,
            },
        )

        await manager.send_json_to_username(
            callee.username,
            {
                "type": "call",
                "event": "ringing",
                "payload": {
                    "call_id": call.id,
                    "conversation_id": conversation_id,
                    "mode": call.call_mode,
                    "call_mode": call.call_mode,
                    "from": {
                        "id": caller.id,
                        "username": caller.username,
                        "display_name": caller.full_name or caller.username,
                        "avatar_url": caller.avatar_url,
                    },
                },
            },
        )

        _schedule_ringing_timeout(call.id, manager)
    finally:
        db.close()


async def _handle_ringing_transition(
    websocket: WebSocket,
    manager: Any,
    sender_username: str,
    message: dict[str, Any],
    *,
    accepted: bool,
) -> None:
    call_id = str(message.get("call_id") or "").strip()
    if not call_id:
        await _send_error(websocket, "call.invalid_id", "Missing call id")
        return

    db = getSession()
    try:
        sender = get_user_db_row_by_username(db, sender_username)
        call = db.query(Call).filter(Call.id == call_id).one_or_none()

        if sender is None or call is None:
            await _send_error(websocket, "call.not_found", "Call not found")
            return

        # Validate sender is active
        if not _is_user_active(sender):
            await _send_error(websocket, "call.forbidden", "User account is disabled")
            _audit_log(db, call_id, "reject_inactive_user", sender.id)
            return

        if sender.id != call.callee_user_id:
            await _send_error(websocket, "call.forbidden", "Only callee can answer or reject")
            return

        _cancel_ringing_timeout(call.id)

        if not accepted:
            reject_all = bool(message.get("reject_all"))
            if not reject_all:
                await _send_ack(
                    websocket,
                    "call.reject",
                    {
                        "call_id": call.id,
                        "status": call.status,
                        "applied": False,
                        "scope": "device",
                    },
                )
                return

        target_status = "accepted" if accepted else "rejected"
        ack_event = "call.accept" if accepted else "call.reject"
        try:
            transition_outcome = transition_call_state(
                call,
                target_status,
                actor_user_id=sender.id,
            )
        except CallStateError as exc:
            await _send_error(websocket, exc.code, exc.message)
            _audit_log(db, call_id, "transition_failed", sender.id, error_code=exc.code)
            return

        db.commit()
        db.refresh(call)

        # Log and update metrics
        event = "accept" if accepted else "reject"
        _audit_log(db, call_id, event, sender.id)
        if accepted:
            # Calculate setup latency from creation to acceptance
            if call.created_at:
                setup_latency_ms = int((datetime.now(timezone.utc) - call.created_at).total_seconds() * 1000)
                _update_call_metrics(db, call_id, accepts_received=1, setup_latency_ms=setup_latency_ms)
        else:
            _update_call_metrics(db, call_id, rejects_received=1)
        db.commit()

        if transition_outcome.changed and not accepted:
            await _emit_call_chat_log(
                manager,
                db,
                call,
                event="rejected",
                actor_user_id=sender.id,
            )

        await _send_ack(websocket, ack_event, {"call_id": call.id, "status": call.status, "applied": transition_outcome.changed})
        if transition_outcome.changed:
            if accepted:
                _schedule_media_setup_timeout(call.id, manager)
                caller_payload = {
                    "type": "call",
                    "event": "call.accepted",
                    "payload": _build_call_summary(db, call, call.caller_user_id),
                }
                await manager.send_json_to_username(
                    (db.query(UserDB.username).filter(UserDB.id == call.caller_user_id).one())[0],
                    caller_payload,
                )

                terminated_elsewhere_payload = {
                    "type": "call",
                    "event": "call.terminated_elsewhere",
                    "payload": {
                        "call_id": call.id,
                        "status": call.status,
                        "accepted_by_user_id": sender.id,
                    },
                }
                await manager.send_json_to_username_except(
                    sender.username,
                    terminated_elsewhere_payload,
                    excluded_websocket=websocket,
                )
                return

            await _notify_call_state(manager, db, call, transition_outcome.event)
        elif accepted:
            await websocket.send_json(
                {
                    "type": "call",
                    "event": "call.terminated_elsewhere",
                    "payload": {
                        "call_id": call.id,
                        "status": call.status,
                    },
                }
            )
    finally:
        db.close()


async def _handle_cancel_or_end(
    websocket: WebSocket,
    manager: Any,
    sender_username: str,
    message: dict[str, Any],
    *,
    end_call: bool,
) -> None:
    db = getSession()
    try:
        sender = get_user_db_row_by_username(db, sender_username)
        if sender is None:
            await _send_error(websocket, "call.not_found", "Call not found")
            return

        call_id = str(message.get("call_id") or "").strip()
        call: Call | None = None

        if call_id:
            call = db.query(Call).filter(Call.id == call_id).one_or_none()
        elif not end_call:
            target_username = str(message.get("to") or "").strip().lower()
            if target_username:
                callee = get_user_db_row_by_username(db, target_username)
                if callee is not None:
                    call = (
                        db.query(Call)
                        .filter(Call.caller_user_id == sender.id)
                        .filter(Call.callee_user_id == callee.id)
                        .filter(Call.status.in_(RINGING_CALL_STATUSES))
                        .order_by(Call.created_at.desc())
                        .first()
                    )

        if call is None:
            await _send_error(websocket, "call.not_found", "Call not found")
            return

        # Validate sender is active
        if not _is_user_active(sender):
            await _send_error(websocket, "call.forbidden", "User account is disabled")
            _audit_log(db, call_id, "cancel_inactive_user" if not end_call else "end_inactive_user", sender.id)
            return

        if not _is_participant(call, sender.id):
            await _send_error(websocket, "call.forbidden", "User is not a participant")
            return

        if end_call:
            ack_event = "call.end"
            try:
                transition_outcome = transition_call_state(
                    call,
                    "ended",
                    actor_user_id=sender.id,
                    end_reason=str(message.get("reason") or "ended"),
                )
            except CallStateError as exc:
                await _send_error(websocket, exc.code, exc.message)
                _audit_log(db, call_id, "end_failed", sender.id, error_code=exc.code)
                return
        else:
            if sender.id != call.caller_user_id:
                await _send_error(websocket, "call.forbidden", "Only caller can cancel a ringing call")
                return
            ack_event = "call.cancel"
            try:
                transition_outcome = transition_call_state(
                    call,
                    "canceled",
                    actor_user_id=sender.id,
                    end_reason="canceled",
                )
            except CallStateError as exc:
                await _send_error(websocket, exc.code, exc.message)
                _audit_log(db, call_id, "cancel_failed", sender.id, error_code=exc.code)
                return

        _cancel_all_timeouts(call.id)

        db.commit()
        db.refresh(call)

        event = "cancel" if not end_call else "end"
        _audit_log(db, call_id, event, sender.id)
        if end_call and call.started_at and call.ended_at:
            duration_ms = int((call.ended_at - call.started_at).total_seconds() * 1000)
            _update_call_metrics(db, call_id, call_duration_ms=duration_ms)
        db.commit()

        if transition_outcome.changed and end_call:
            await _emit_call_chat_log(
                manager,
                db,
                call,
                event="finished",
                actor_user_id=sender.id,
            )

        await _send_ack(websocket, ack_event, {"call_id": call.id, "status": call.status})
        if transition_outcome.changed:
            await _notify_call_state(manager, db, call, transition_outcome.event)

            if not end_call:
                callee_username_row = (
                    db.query(UserDB.username)
                    .filter(UserDB.id == call.callee_user_id)
                    .one_or_none()
                )
                if callee_username_row is not None:
                    callee_username = callee_username_row[0]
                    legacy_payload = _build_call_summary(db, call, call.callee_user_id)

                    await manager.send_json_to_username(
                        callee_username,
                        {
                            "type": "call",
                            "event": "canceled",
                            "payload": legacy_payload,
                        },
                    )
                    await manager.send_json_to_username(
                        callee_username,
                        {
                            "type": "call",
                            "event": "ended",
                            "payload": legacy_payload,
                        },
                    )
    finally:
        db.close()


async def handle_user_disconnected(manager: Any, username: str) -> None:
    db = getSession()
    try:
        user = get_user_db_row_by_username(db, username)
        if user is None:
            return

        changed_calls = fail_active_calls_for_user(db, user.id, reason="disconnect")
        if not changed_calls:
            return

        for call in changed_calls:
            _cancel_all_timeouts(call.id)
            _audit_log(db, call.id, "disconnect", user.id, details="User disconnected unexpectedly")

        db.commit()
        for call in changed_calls:
            db.refresh(call)
            await _notify_call_state(manager, db, call, "failed")
    finally:
        db.close()


async def _handle_webrtc_relay(
    websocket: WebSocket,
    manager: Any,
    sender_username: str,
    message: dict[str, Any],
    *,
    event: str,
    ack_event: str | None = None,
) -> None:
    call_id = str(message.get("call_id") or "").strip()
    if not call_id:
        await _send_error(websocket, "call.invalid_id", "Missing call id")
        return

    db = getSession()
    try:
        sender = get_user_db_row_by_username(db, sender_username)
        call = db.query(Call).filter(Call.id == call_id).one_or_none()
        if sender is None or call is None:
            await _send_error(websocket, "call.not_found", "Call not found")
            return

        if not _is_user_active(sender):
            await _send_error(websocket, "call.forbidden", "User account is disabled")
            _audit_log(db, call_id, f"{event}_inactive_user", sender.id)
            return

        if call.status != "accepted":
            await _send_error(websocket, "call.invalid_state", "Call is not accepted")
            return

        if not _is_participant(call, sender.id):
            await _send_error(websocket, "call.forbidden", "User is not a participant")
            return

        target_user_id = _other_participant_id(call, sender.id)
        target_user = db.query(UserDB).filter(UserDB.id == target_user_id).one_or_none()
        if target_user is None:
            await _send_error(websocket, "call.invalid_target", "Target user not found")
            return

        payload = message.get("payload")
        if payload is None:
            await _send_error(websocket, "call.invalid_payload", "Missing payload")
            return

        try:
            validated_payload = validate_webrtc_payload(payload, event)
        except (ValidationError, ValueError) as exc:
            await _send_error(websocket, "call.invalid_payload", str(exc))
            _audit_log(db, call_id, f"{event}_validation_failed", sender.id, error_message=str(exc))
            return

        # Log WebRTC event and update metrics
        _audit_log(db, call_id, event, sender.id)
        
        now = datetime.now(timezone.utc)
        metrics_update = {}
        if event == "offer":
            metrics_update["offer_received_at"] = now
        elif event == "answer":
            metrics_update["answer_received_at"] = now
        elif event == "ice-candidate":
            metrics_update["first_ice_candidate_at"] = now
        
        if metrics_update:
            _update_call_metrics(db, call_id, **metrics_update)
        db.commit()

        await manager.send_json_to_username(
            target_user.username,
            {
                "type": "webrtc",
                "event": event,
                "payload": {
                    "call_id": call.id,
                    "from_user_id": sender.id,
                    "from_username": sender.username,
                    "data": validated_payload,
                },
            },
        )

        _cancel_media_setup_timeout(call.id)

        await _send_ack(websocket, ack_event or f"webrtc.{event}", {"call_id": call.id})
    finally:
        db.close()


async def _handle_chat_read_cursor_update(
    websocket: WebSocket,
    manager: Any,
    sender_username: str,
    message: dict[str, Any],
) -> None:
    payload = message.get("payload")
    if not isinstance(payload, dict):
        await _send_error(websocket, "chat.invalid_payload", "Missing payload")
        return

    conversation_id = str(payload.get("conversation_id") or "").strip()
    if not conversation_id:
        await _send_error(websocket, "chat.invalid_conversation", "Missing conversation_id")
        return

    upto_seq_raw = payload.get("upto_seq")
    if not isinstance(upto_seq_raw, int):
        await _send_error(websocket, "chat.invalid_upto_seq", "upto_seq must be an integer")
        return

    if upto_seq_raw < 0:
        await _send_error(websocket, "chat.invalid_upto_seq", "upto_seq must be >= 0")
        return

    db = getSession()
    try:
        sender = get_user_db_row_by_username(db, sender_username)
        if sender is None:
            await _send_error(websocket, "chat.unauthorized", "Unknown sender")
            return

        is_participant = (
            db.query(ConversationParticipants)
            .filter(
                ConversationParticipants.conversation_id == conversation_id,
                ConversationParticipants.user_id == sender.id,
            )
            .first()
        )
        if not is_participant:
            await _send_error(websocket, "chat.not_participating", "Not a participant")
            return

        max_seq = int(
            db.query(func.max(Messages.seq))
            .filter(Messages.conversation_id == conversation_id)
            .scalar()
            or 0
        )
        target_seq = max(0, min(upto_seq_raw, max_seq))

        row = (
            db.query(ConversationReadCursor)
            .filter(
                ConversationReadCursor.conversation_id == conversation_id,
                ConversationReadCursor.user_id == sender.id,
            )
            .one_or_none()
        )

        now = datetime.now(timezone.utc)
        previous_seq = 0
        if row is None:
            row = ConversationReadCursor(
                conversation_id=conversation_id,
                user_id=sender.id,
                last_seen_seq=target_seq,
                last_seen_at=now,
                updated_at=now,
            )
            db.add(row)
            next_seq = target_seq
        else:
            previous_seq = int(row.last_seen_seq or 0)
            next_seq = max(previous_seq, target_seq)
            if next_seq > previous_seq:
                row.last_seen_seq = next_seq
                row.last_seen_at = now
                row.updated_at = now

        db.commit()
        changed = next_seq > previous_seq

        if changed:
            participant_usernames = [
                username
                for (username,) in db.query(UserDB.username)
                .join(ConversationParticipants, ConversationParticipants.user_id == UserDB.id)
                .filter(ConversationParticipants.conversation_id == conversation_id)
                .all()
            ]

            if participant_usernames:
                await manager.send_json_to_usernames(
                    participant_usernames,
                    {
                        "event": "conversation.read_cursor.updated",
                        "conversation_id": conversation_id,
                        "payload": {
                            "reader_id": sender.id,
                            "last_seen_seq": next_seq,
                            "last_seen_at": (row.last_seen_at.isoformat() if row.last_seen_at else now.isoformat()),
                        },
                    },
                )

        await _send_ack(
            websocket,
            "chat.read_cursor.update",
            {
                "conversation_id": conversation_id,
                "last_seen_seq": next_seq,
                "updated": changed,
            },
        )
    finally:
        db.close()


async def handle_signaling_message(
    websocket: WebSocket,
    manager: Any,
    sender_username: str,
    message: dict[str, Any],
) -> None:
    event = str(message.get("event") or "").strip().lower()
    if not event:
        await _send_error(websocket, "signal.invalid_event", "Missing event")
        return

    event_handlers = {
        "call.invite": lambda: _handle_invite(websocket, manager, sender_username, message),
        "call.cancel": lambda: _handle_cancel_or_end(websocket, manager, sender_username, message, end_call=False),
        "call.accept": lambda: _handle_ringing_transition(websocket, manager, sender_username, message, accepted=True),
        "call.reject": lambda: _handle_ringing_transition(websocket, manager, sender_username, message, accepted=False),
        "call.end": lambda: _handle_cancel_or_end(websocket, manager, sender_username, message, end_call=True),
        "webrtc.offer": lambda: _handle_webrtc_relay(websocket, manager, sender_username, message, event="offer"),
        "webrtc.answer": lambda: _handle_webrtc_relay(websocket, manager, sender_username, message, event="answer"),
        "webrtc.ice-candidate": lambda: _handle_webrtc_relay(websocket, manager, sender_username, message, event="ice-candidate"),
        "chat.read_cursor.update": lambda: _handle_chat_read_cursor_update(websocket, manager, sender_username, message),
        "call.media-state": lambda: _handle_webrtc_relay(
            websocket,
            manager,
            sender_username,
            message,
            event="media-state",
            ack_event="call.media-state",
        ),
    }

    handler = event_handlers.get(event)
    if handler is not None:
        await handler()
        return

    await _send_error(websocket, "signal.unsupported_event", f"Unsupported event: {event}")
