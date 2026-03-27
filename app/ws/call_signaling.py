from __future__ import annotations

import asyncio
from datetime import timezone
from typing import Any

from fastapi import WebSocket

from app.api.utils.user import get_user_db_row_by_username
from app.database.models.calls import Call
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversations import Conversation
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

        try:
            ensure_can_start_call(
                db,
                caller.id,
                callee.id,
                callee_online=manager.is_user_online(callee.username),
            )
        except CallStateError as exc:
            await _send_error(websocket, exc.code, exc.message)
            return

        conversation_id = None
        requested_conversation_id = str(message.get("conversation_id") or "").strip()
        if requested_conversation_id:
            conversation_id = _validate_call_conversation(db, requested_conversation_id, caller.id, callee.id)
        if conversation_id is None:
            conversation_id = _find_direct_conversation_id(db, caller.id, callee.id)

        call = create_outgoing_call(
            db,
            conversation_id=conversation_id,
            caller_user_id=caller.id,
            callee_user_id=callee.id,
        )
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
            return

        db.commit()
        db.refresh(call)

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
                return

        _cancel_all_timeouts(call.id)

        db.commit()
        db.refresh(call)

        await _send_ack(websocket, ack_event, {"call_id": call.id, "status": call.status})
        if transition_outcome.changed:
            await _notify_call_state(manager, db, call, transition_outcome.event)
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

        _cancel_media_setup_timeout(call.id)

        await _send_ack(websocket, ack_event or f"webrtc.{event}", {"call_id": call.id})
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
