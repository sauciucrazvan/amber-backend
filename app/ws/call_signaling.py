from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket
from sqlalchemy import and_, or_

from app.api.utils.user import get_user_db_row_by_username
from app.database.models.calls import Call
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversations import Conversation
from app.database.models.relationship import Relationship
from app.database.models.user import UserDB
from app.database.session import getSession

ACTIVE_CALL_STATUSES = {"initiated", "ringing", "accepted"}
RINGING_CALL_STATUSES = {"initiated", "ringing"}
CALL_TIMEOUT_SECONDS = 30

_timeout_tasks: dict[str, asyncio.Task] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


def _is_blocked_pair(db, user_a_id: int, user_b_id: int) -> bool:
    return (
        db.query(Relationship.id)
        .filter(_pair_filter(user_a_id, user_b_id))
        .filter(Relationship.relation == "blocked")
        .first()
        is not None
    )


def _is_contact_pair(db, user_a_id: int, user_b_id: int) -> bool:
    return (
        db.query(Relationship.id)
        .filter(_pair_filter(user_a_id, user_b_id))
        .filter(Relationship.relation == "contact")
        .first()
        is not None
    )


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


def _status_event_name(status: str) -> str:
    mapping = {
        "accepted": "accepted",
        "rejected": "rejected",
        "canceled": "canceled",
        "ended": "ended",
        "missed": "missed",
        "failed": "failed",
    }
    return mapping.get(status, "updated")


def _build_call_summary(db, call: Call, viewer_user_id: int) -> dict[str, Any]:
    peer_user_id = _other_participant_id(call, viewer_user_id)
    peer_user = db.query(UserDB).filter(UserDB.id == peer_user_id).one()

    return {
        "call_id": call.id,
        "status": call.status,
        "conversation_id": call.conversation_id,
        "peer": {
            "id": peer_user.id,
            "username": peer_user.username,
            "display_name": peer_user.full_name or peer_user.username,
        },
        "started_at": call.started_at.isoformat() if call.started_at else None,
        "ended_at": call.ended_at.isoformat() if call.ended_at else None,
        "duration_seconds": _duration_seconds(call),
        "end_reason": call.end_reason,
        "ended_by_user_id": call.ended_by_user_id,
    }


def _cancel_timeout(call_id: str) -> None:
    task = _timeout_tasks.pop(call_id, None)
    if task is not None:
        task.cancel()


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

            call.status = "missed"
            call.end_reason = "timeout"
            call.ended_at = _utcnow()
            db.commit()
            db.refresh(call)

            await _notify_call_state(manager, db, call, "missed")
        finally:
            db.close()
    except asyncio.CancelledError:
        return
    finally:
        _timeout_tasks.pop(call_id, None)


def _schedule_ringing_timeout(call_id: str, manager: Any, timeout_seconds: int = CALL_TIMEOUT_SECONDS) -> None:
    _cancel_timeout(call_id)
    _timeout_tasks[call_id] = asyncio.create_task(_ringing_timeout(call_id, manager, timeout_seconds))


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

        if not manager.is_user_online(callee.username):
            await _send_error(websocket, "call.user_offline", "Callee is offline")
            return

        if _is_blocked_pair(db, caller.id, callee.id):
            await _send_error(websocket, "call.blocked", "Call is blocked")
            return

        if not _is_contact_pair(db, caller.id, callee.id):
            await _send_error(websocket, "call.no_relation", "Users are not contacts")
            return

        active_call = (
            db.query(Call.id)
            .filter(Call.status.in_(ACTIVE_CALL_STATUSES))
            .filter(
                or_(
                    Call.caller_user_id.in_([caller.id, callee.id]),
                    Call.callee_user_id.in_([caller.id, callee.id]),
                )
            )
            .first()
        )
        if active_call is not None:
            await _send_error(websocket, "call.busy", "One of the users is already in another call")
            return

        conversation_id = None
        requested_conversation_id = str(message.get("conversation_id") or "").strip()
        if requested_conversation_id:
            conversation_id = _validate_call_conversation(db, requested_conversation_id, caller.id, callee.id)
        if conversation_id is None:
            conversation_id = _find_direct_conversation_id(db, caller.id, callee.id)

        call = Call(
            conversation_id=conversation_id,
            caller_user_id=caller.id,
            callee_user_id=callee.id,
            status="ringing",
        )
        db.add(call)
        db.commit()
        db.refresh(call)

        await _send_ack(
            websocket,
            "call.invite",
            {
                "call_id": call.id,
                "status": call.status,
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
                    "from": {
                        "id": caller.id,
                        "username": caller.username,
                        "display_name": caller.full_name or caller.username,
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

        if sender.id != call.callee_user_id:
            await _send_error(websocket, "call.forbidden", "Only callee can answer or reject")
            return

        if call.status not in RINGING_CALL_STATUSES:
            await _send_error(websocket, "call.invalid_state", "Call is no longer ringing")
            return

        _cancel_timeout(call.id)

        if accepted:
            call.status = "accepted"
            call.started_at = _utcnow()
            event = "accepted"
            ack_event = "call.accept"
        else:
            call.status = "rejected"
            call.ended_at = _utcnow()
            call.ended_by_user_id = sender.id
            call.end_reason = "rejected"
            event = "rejected"
            ack_event = "call.reject"

        db.commit()
        db.refresh(call)

        await _send_ack(websocket, ack_event, {"call_id": call.id, "status": call.status})
        await _notify_call_state(manager, db, call, event)
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

        if not _is_participant(call, sender.id):
            await _send_error(websocket, "call.forbidden", "User is not a participant")
            return

        if end_call:
            if call.status != "accepted":
                await _send_error(websocket, "call.invalid_state", "Call is not in progress")
                return

            call.status = "ended"
            call.end_reason = str(message.get("reason") or "ended")
            call.ended_by_user_id = sender.id
            call.ended_at = _utcnow()
            ack_event = "call.end"
            event = "ended"
        else:
            if sender.id != call.caller_user_id:
                await _send_error(websocket, "call.forbidden", "Only caller can cancel a ringing call")
                return
            if call.status not in RINGING_CALL_STATUSES:
                await _send_error(websocket, "call.invalid_state", "Call is no longer ringing")
                return

            call.status = "canceled"
            call.end_reason = "canceled"
            call.ended_by_user_id = sender.id
            call.ended_at = _utcnow()
            ack_event = "call.cancel"
            event = "canceled"

        _cancel_timeout(call.id)

        db.commit()
        db.refresh(call)

        await _send_ack(websocket, ack_event, {"call_id": call.id, "status": call.status})
        await _notify_call_state(manager, db, call, event)
    finally:
        db.close()


async def _handle_webrtc_relay(
    websocket: WebSocket,
    manager: Any,
    sender_username: str,
    message: dict[str, Any],
    *,
    event: str,
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

        await manager.send_json_to_username(
            target_user.username,
            {
                "type": "webrtc",
                "event": event,
                "payload": {
                    "call_id": call.id,
                    "from_user_id": sender.id,
                    "from_username": sender.username,
                    "data": message.get("payload") or {},
                },
            },
        )

        await _send_ack(websocket, f"webrtc.{event}", {"call_id": call.id})
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

    if event == "call.invite":
        await _handle_invite(websocket, manager, sender_username, message)
        return

    if event == "call.accept":
        await _handle_ringing_transition(websocket, manager, sender_username, message, accepted=True)
        return

    if event == "call.reject":
        await _handle_ringing_transition(websocket, manager, sender_username, message, accepted=False)
        return

    if event == "call.cancel":
        await _handle_cancel_or_end(websocket, manager, sender_username, message, end_call=False)
        return

    if event == "call.end":
        await _handle_cancel_or_end(websocket, manager, sender_username, message, end_call=True)
        return

    if event == "webrtc.offer":
        await _handle_webrtc_relay(websocket, manager, sender_username, message, event="offer")
        return

    if event == "webrtc.answer":
        await _handle_webrtc_relay(websocket, manager, sender_username, message, event="answer")
        return

    if event == "webrtc.ice-candidate":
        await _handle_webrtc_relay(websocket, manager, sender_username, message, event="ice-candidate")
        return

    if event == "call.media-state":
        await _handle_webrtc_relay(websocket, manager, sender_username, message, event="media-state")
        return

    await _send_error(websocket, "signal.unsupported_event", f"Unsupported event: {event}")
