import asyncio
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.api.rate_limiter import RateLimitConfig, limiter
from app.api.routes.auth import get_current_active_user
from app.database.models import UserDB
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.conversations import Conversation
from app.database.models.messages import Messages
from app.database.models.relationship import Relationship
from app.database.session import get_db
from app.ws import connection_manager


router = APIRouter(prefix="/chats", tags=["chats"])


def _serialize_message(message: Messages, *, seen_override: bool | None = None) -> dict:
    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "seq": message.seq,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
        "edited_at": message.edited_at.isoformat() if message.edited_at else None,
        "seen": message.seen if seen_override is None else seen_override,
    }


def _dispatch_chat_event(usernames: list[str], payload: dict) -> None:
    if not usernames:
        return

    try:
        asyncio.run(connection_manager.manager.send_json_to_usernames(usernames, payload))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(connection_manager.manager.send_json_to_usernames(usernames, payload))
        finally:
            loop.close()


def _get_conversation_participant_usernames(db: Session, conversation_id: str) -> list[str]:
    return [
        username
        for (username,) in db.query(UserDB.username)
        .join(ConversationParticipants, ConversationParticipants.user_id == UserDB.id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]


def _emit_conversation_event(
    db: Session,
    conversation_id: str,
    event_type: str,
    payload: dict,
) -> None:
    usernames = _get_conversation_participant_usernames(db, conversation_id)
    _dispatch_chat_event(
        usernames,
        {
            "event": event_type,
            "conversation_id": conversation_id,
            "payload": payload,
        },
    )


def _emit_contact_last_action_updates(
    db: Session,
    actor_user_id: int,
    other_user_ids: list[int],
    action_at: datetime,
) -> None:
    if not other_user_ids:
        return

    user_rows = (
        db.query(UserDB.id, UserDB.username)
        .filter(UserDB.id.in_([actor_user_id, *other_user_ids]))
        .all()
    )
    username_by_id = {user_id: username for (user_id, username) in user_rows}

    actor_username = username_by_id.get(actor_user_id)
    if not actor_username:
        return

    for other_user_id in other_user_ids:
        other_username = username_by_id.get(other_user_id)
        if not other_username:
            continue

        _dispatch_chat_event(
            [actor_username],
            {
                "type": "contacts",
                "event": "contact.last_action.updated",
                "payload": {
                    "user_id": other_user_id,
                    "last_action_at": action_at.isoformat(),
                },
            },
        )

        _dispatch_chat_event(
            [other_username],
            {
                "type": "contacts",
                "event": "contact.last_action.updated",
                "payload": {
                    "user_id": actor_user_id,
                    "last_action_at": action_at.isoformat(),
                },
            },
        )


def _serialize_last_message(message: Messages) -> dict:
    return {
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
    }


def _emit_contact_last_message_updates(
    db: Session,
    actor_user_id: int,
    other_user_ids: list[int],
    message: Messages,
) -> None:
    if not other_user_ids:
        return

    user_rows = (
        db.query(UserDB.id, UserDB.username)
        .filter(UserDB.id.in_([actor_user_id, *other_user_ids]))
        .all()
    )
    username_by_id = {user_id: username for (user_id, username) in user_rows}

    actor_username = username_by_id.get(actor_user_id)
    if not actor_username:
        return

    last_message = _serialize_last_message(message)

    for other_user_id in other_user_ids:
        other_username = username_by_id.get(other_user_id)
        if not other_username:
            continue

        _dispatch_chat_event(
            [actor_username],
            {
                "type": "contacts",
                "event": "contact.last_message.updated",
                "payload": {
                    "user_id": other_user_id,
                    "last_message": last_message,
                },
            },
        )

        _dispatch_chat_event(
            [other_username],
            {
                "type": "contacts",
                "event": "contact.last_message.updated",
                "payload": {
                    "user_id": actor_user_id,
                    "last_message": last_message,
                },
            },
        )


def _emit_read_cursor_updated(
    db: Session,
    conversation_id: str,
    reader_id: int,
    last_seen_seq: int,
    last_seen_at: datetime,
) -> None:
    _emit_conversation_event(
        db,
        conversation_id,
        "conversation.read_cursor.updated",
        {
            "reader_id": reader_id,
            "last_seen_seq": last_seen_seq,
            "last_seen_at": last_seen_at.isoformat(),
        },
    )


def _is_conversation_participant(db: Session, conversation_id: str, user_id: int) -> bool:
    return (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == user_id,
        )
        .first()
        is not None
    )


def _get_conversation_max_seq(db: Session, conversation_id: str) -> int:
    value = (
        db.query(func.max(Messages.seq))
        .filter(Messages.conversation_id == conversation_id)
        .scalar()
    )
    return int(value or 0)


def _next_message_seq(db: Session, conversation_id: str) -> int:
    return _get_conversation_max_seq(db, conversation_id) + 1


def _get_last_seen_seq(db: Session, conversation_id: str, user_id: int) -> int:
    row = (
        db.query(ConversationReadCursor.last_seen_seq)
        .filter(
            ConversationReadCursor.conversation_id == conversation_id,
            ConversationReadCursor.user_id == user_id,
        )
        .one_or_none()
    )
    if row is None:
        return 0
    return int(row[0] or 0)


def _advance_read_cursor(
    db: Session,
    conversation_id: str,
    user_id: int,
    upto_seq: int,
) -> tuple[int, int, datetime]:
    now = datetime.now(timezone.utc)
    max_seq = _get_conversation_max_seq(db, conversation_id)
    target_seq = max(0, min(int(upto_seq), max_seq))

    row = (
        db.query(ConversationReadCursor)
        .filter(
            ConversationReadCursor.conversation_id == conversation_id,
            ConversationReadCursor.user_id == user_id,
        )
        .one_or_none()
    )

    if row is None:
        row = ConversationReadCursor(
            conversation_id=conversation_id,
            user_id=user_id,
            last_seen_seq=target_seq,
            last_seen_at=now,
            updated_at=now,
        )
        db.add(row)
        return 0, target_seq, now

    previous_seq = int(row.last_seen_seq or 0)
    next_seq = max(previous_seq, target_seq)
    if next_seq == previous_seq:
        return previous_seq, next_seq, row.last_seen_at

    row.last_seen_seq = next_seq
    row.last_seen_at = now
    row.updated_at = now
    return previous_seq, next_seq, now


def _pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


def _validate_direct_chat_access(db: Session, current_user_id: int, other_user_id: int) -> None:
    if current_user_id == other_user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")

    other_user = db.query(UserDB.id).filter(UserDB.id == other_user_id).one_or_none()
    if other_user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    pair_rels = (
        db.query(Relationship.relation)
        .filter(_pair_filter(current_user_id, other_user_id))
        .all()
    )
    relations = {relation for (relation,) in pair_rels}

    if "blocked" in relations:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.blocked")

    if "contact" not in relations:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="conversations.error.no_relation")


def get_or_create_direct_conversation(db: Session, user_a_id, user_b_id):
    if user_a_id == user_b_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")

    sorted_ids = sorted([str(user_a_id), str(user_b_id)])
    pair_key = f"{sorted_ids[0]}:{sorted_ids[1]}"

    conversation = (
        db.query(Conversation)
        .filter(Conversation.direct_pair == pair_key)
        .one_or_none()
    )

    if conversation:
        return conversation

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

        db.commit()
        db.refresh(conversation)
        return conversation

    except IntegrityError:
        db.rollback()

        return (
            db.query(Conversation)
            .filter(Conversation.direct_pair == pair_key)
            .one()
        )


@router.post("/v1/direct/{other_user_id}")
@limiter.limit(RateLimitConfig.WRITE)
def open_direct_conversation(
    other_user_id: int,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
):
    _validate_direct_chat_access(db, current_user.id, other_user_id)

    conversation = get_or_create_direct_conversation(
        db,
        current_user.id,
        other_user_id,
    )

    my_last_seen_seq = _get_last_seen_seq(db, conversation.id, current_user.id)
    unseen_messages_count = (
        db.query(Messages.id)
        .filter(
            Messages.conversation_id == conversation.id,
            Messages.sender_id != current_user.id,
            Messages.seq > my_last_seen_seq,
        )
        .count()
    )

    return {
        "id": conversation.id,
        "type": conversation.type,
        "direct_pair": conversation.direct_pair,
        "created_at": conversation.created_at,
        "notifications": unseen_messages_count,
    }


class SendMessageData(BaseModel):
    text: str


@router.post("/v1/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.WRITE)
def send_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: SendMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        seq=_next_message_seq(db, conversation_id),
        type="text",
        content={"text": data.text},
    )

    participant_ids = [
        user_id
        for (user_id,) in db.query(ConversationParticipants.user_id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]
    now = datetime.now(timezone.utc)
    for other_user_id in participant_ids:
        if other_user_id == current_user.id:
            continue
        (
            db.query(Relationship)
            .filter(_pair_filter(current_user.id, other_user_id))
            .filter(Relationship.relation == "contact")
            .update({Relationship.updated_at: now}, synchronize_session=False)
        )

    db.add(message)
    db.commit()
    db.refresh(message)

    _emit_contact_last_action_updates(
        db,
        current_user.id,
        [user_id for user_id in participant_ids if user_id != current_user.id],
        now,
    )
    _emit_contact_last_message_updates(
        db,
        current_user.id,
        [user_id for user_id in participant_ids if user_id != current_user.id],
        message,
    )

    response = _serialize_message(message)
    _emit_conversation_event(
        db,
        conversation_id,
        "message.created",
        {
            "message": response,
        },
    )

    return response


@router.get("/v1/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.READ)
def fetch_messages(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    conversation_id: str,
    request: Request,
    limit: int = 20,
    before: datetime | None = None,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    query = (
        db.query(Messages)
        .filter(Messages.conversation_id == conversation_id)
    )

    if before:
        query = query.filter(Messages.created_at < before)

    messages = (
        query
        .order_by(Messages.seq.desc())
        .limit(limit)
        .all()
    )

    messages.reverse()

    cursor_rows = (
        db.query(ConversationReadCursor.user_id, ConversationReadCursor.last_seen_seq)
        .filter(ConversationReadCursor.conversation_id == conversation_id)
        .all()
    )
    cursor_by_user_id = {
        user_id: int(last_seen_seq or 0)
        for (user_id, last_seen_seq) in cursor_rows
    }
    my_last_seen_seq = cursor_by_user_id.get(current_user.id, 0)
    max_other_last_seen_seq = max(
        (seq for user_id, seq in cursor_by_user_id.items() if user_id != current_user.id),
        default=0,
    )

    payload = []
    for message in messages:
        is_seen = (
            max_other_last_seen_seq >= message.seq
            if message.sender_id == current_user.id
            else my_last_seen_seq >= message.seq
        )
        payload.append(_serialize_message(message, seen_override=is_seen))

    if before is None and messages:
        previous_seq, next_seq, last_seen_at = _advance_read_cursor(
            db,
            conversation_id,
            current_user.id,
            messages[-1].seq,
        )
        db.commit()
        if next_seq > previous_seq:
            _emit_read_cursor_updated(
                db,
                conversation_id,
                current_user.id,
                next_seq,
                last_seen_at,
            )

    return payload


class UpdateReadCursorData(BaseModel):
    upto_seq: int


@router.post("/v1/{conversation_id}/read-cursor")
@limiter.limit(RateLimitConfig.WRITE)
def update_read_cursor(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: UpdateReadCursorData,
    request: Request,
    conversation_id: str,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    previous_seq, next_seq, last_seen_at = _advance_read_cursor(
        db,
        conversation_id,
        current_user.id,
        data.upto_seq,
    )
    db.commit()

    if next_seq > previous_seq:
        _emit_read_cursor_updated(
            db,
            conversation_id,
            current_user.id,
            next_seq,
            last_seen_at,
        )

    return {
        "conversation_id": conversation_id,
        "reader_id": current_user.id,
        "last_seen_seq": next_seq,
        "updated": max(0, next_seq - previous_seq),
    }


@router.post("/v1/{conversation_id}/seen")
@limiter.limit(RateLimitConfig.WRITE)
def mark_conversation_seen(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    conversation_id: str,
    request: Request,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    previous_seq, next_seq, last_seen_at = _advance_read_cursor(
        db,
        conversation_id,
        current_user.id,
        _get_conversation_max_seq(db, conversation_id),
    )
    db.commit()

    if next_seq > previous_seq:
        _emit_read_cursor_updated(
            db,
            conversation_id,
            current_user.id,
            next_seq,
            last_seen_at,
        )

    return {
        "conversation_id": conversation_id,
        "reader_id": current_user.id,
        "seen_message_ids": [],
        "updated": max(0, next_seq - previous_seq),
        "last_seen_seq": next_seq,
    }


class ReplyMessageData(BaseModel):
    message_id: str
    text: str


@router.post("/v1/{conversation_id}/reply")
@limiter.limit(RateLimitConfig.WRITE)
def reply_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ReplyMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    parent_message = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == data.message_id,
        Messages.type == "text",
    ).first()
    if not parent_message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        seq=_next_message_seq(db, conversation_id),
        type="text",
        content={
            "text": data.text,
            "reply_to": {
                "id": parent_message.id,
                "content": {
                    "text": parent_message.content["text"],
                },
                "created_at": parent_message.created_at.isoformat() if parent_message.created_at else None,
                "sender_id": parent_message.sender_id,
                "type": parent_message.type,
            },
        },
    )

    participant_ids = [
        user_id
        for (user_id,) in db.query(ConversationParticipants.user_id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]
    now = datetime.now(timezone.utc)
    for other_user_id in participant_ids:
        if other_user_id == current_user.id:
            continue
        (
            db.query(Relationship)
            .filter(_pair_filter(current_user.id, other_user_id))
            .filter(Relationship.relation == "contact")
            .update({Relationship.updated_at: now}, synchronize_session=False)
        )

    db.add(message)
    db.commit()
    db.refresh(message)

    _emit_contact_last_action_updates(
        db,
        current_user.id,
        [user_id for user_id in participant_ids if user_id != current_user.id],
        now,
    )

    response = _serialize_message(message)
    _emit_conversation_event(
        db,
        conversation_id,
        "message.created",
        {
            "message": response,
        },
    )

    return response


class DeleteMessageData(BaseModel):
    message_id: str


@router.delete("/v1/{conversation_id}/messages", status_code=200)
@limiter.limit(RateLimitConfig.WRITE)
def delete_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: DeleteMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    message = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == data.message_id,
        Messages.type == "text",
    ).first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    if message.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="conversations.error.no_permission")

    deleted_message_id = message.id

    db.delete(message)
    db.commit()

    _emit_conversation_event(
        db,
        conversation_id,
        "message.deleted",
        {
            "message_id": deleted_message_id,
            "deleted_by": current_user.id,
        },
    )

    return JSONResponse(
        status_code=200,
        content={"message": "conversations.deleted_message"},
    )


class EditMessageData(BaseModel):
    text: str
    message_id: str


@router.patch("/v1/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.WRITE)
def edit_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EditMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = _is_conversation_participant(db, conversation_id, current_user.id)

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    message: Messages = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == data.message_id,
        Messages.type == "text",
    ).first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    if message.sender_id != current_user.id:
        raise HTTPException(status_code=422, detail="conversations.error.no_permission")

    participant_ids = [
        user_id
        for (user_id,) in db.query(ConversationParticipants.user_id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]
    now = datetime.now(timezone.utc)
    for other_user_id in participant_ids:
        if other_user_id == current_user.id:
            continue
        (
            db.query(Relationship)
            .filter(_pair_filter(current_user.id, other_user_id))
            .filter(Relationship.relation == "contact")
            .update({Relationship.updated_at: now}, synchronize_session=False)
        )

    edit_time = datetime.now(timezone.utc)
    content = dict(message.content or {})

    previous_text = content.get("text")
    if isinstance(previous_text, str):
        history = content.get("history")
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "text": previous_text,
                "date": edit_time.isoformat(),
            }
        )
        content["history"] = history

    content["text"] = data.text
    message.content = content

    message.edited_at = edit_time

    db.commit()
    db.refresh(message)

    _emit_contact_last_action_updates(
        db,
        current_user.id,
        [user_id for user_id in participant_ids if user_id != current_user.id],
        now,
    )

    response = _serialize_message(message)
    _emit_conversation_event(
        db,
        conversation_id,
        "message.edited",
        {
            "message": response,
        },
    )

    return response
