import asyncio
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.rate_limiter import limiter, RateLimitConfig
from app.api.models.user import User
from app.api.routes.auth import get_current_active_user
from app.database.models import UserDB
from app.database.models.messages import Messages
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversations import Conversation
from app.database.models.relationship import Relationship
from app.database.session import get_db
from app.ws import connection_manager


router = APIRouter(prefix="/chats", tags=["chats"])


def _serialize_message(message: Messages) -> dict:
    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
        "edited_at": message.edited_at.isoformat() if message.edited_at else None,
        "seen": message.seen,
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


def _mark_conversation_messages_seen(
    db: Session,
    conversation_id: str,
    reader_id: int,
) -> list[str]:
    seen_message_ids = [
        message_id
        for (message_id,) in db.query(Messages.id)
        .filter(
            Messages.conversation_id == conversation_id,
            Messages.seen == False,
            Messages.sender_id != reader_id,
        )
        .all()
    ]

    if not seen_message_ids:
        return []

    (
        db.query(Messages)
        .filter(
            Messages.id.in_(seen_message_ids),
            Messages.seen == False,
        )
        .update({Messages.seen: True}, synchronize_session=False)
    )
    db.commit()

    _emit_conversation_event(
        db,
        conversation_id,
        "messages.seen",
        {
            "reader_id": reader_id,
            "message_ids": seen_message_ids,
        },
    )

    return seen_message_ids

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
        conversation = Conversation(
            type="direct",
            direct_pair=pair_key
        )
        db.add(conversation)
        db.flush()

        db.add_all([
            ConversationParticipants(
                conversation_id=conversation.id,
                user_id=user_a_id
            ),
            ConversationParticipants(
                conversation_id=conversation.id,
                user_id=user_b_id
            )
        ])

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
    
@router.post("/direct/{other_user_id}")
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
        other_user_id
    )

    last_messages = (
        db.query(Messages)
        .filter(
            Messages.conversation_id == conversation.id,
            Messages.sender_id != current_user.id,
            Messages.seen == False,
        )
        .order_by(Messages.created_at.desc())
    )

    unseen_messages_count = last_messages.count()

    return {
        "id": conversation.id,
        "type": conversation.type,
        "direct_pair": conversation.direct_pair,
        "created_at": conversation.created_at,
        "notifications": unseen_messages_count
    }

class SendMessageData(BaseModel):
    text: str


@router.post("/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.WRITE)
def send_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: SendMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == current_user.id,
        )
        .first()
    )

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")
    
    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        type="text",
        content={"text": data.text}
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

@router.get("/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.READ)
def fetch_messages(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    conversation_id: str,
    request: Request,
    limit: int = 20,
    before: datetime | None = None,
):
    is_participant = (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == current_user.id,
        )
        .first()
    )

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")
    
    query = (
        db.query(Messages)
        .filter(Messages.conversation_id == conversation_id)
    )

    _mark_conversation_messages_seen(db, conversation_id, current_user.id)

    if before:
        query = query.filter(Messages.created_at < before)
    
    messages = (
        query
        .order_by(Messages.created_at.desc())
        .limit(limit)
        .all()
    )

    messages.reverse()
    return [_serialize_message(message) for message in messages]


@router.post("/{conversation_id}/seen")
@limiter.limit(RateLimitConfig.WRITE)
def mark_conversation_seen(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    conversation_id: str,
    request: Request,
):
    is_participant = (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == current_user.id,
        )
        .first()
    )

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    seen_message_ids = _mark_conversation_messages_seen(db, conversation_id, current_user.id)

    return {
        "conversation_id": conversation_id,
        "reader_id": current_user.id,
        "seen_message_ids": seen_message_ids,
        "updated": len(seen_message_ids),
    }


class ReplyMessageData(BaseModel):
    message_id: str
    text: str

@router.post("/{conversation_id}/reply")
@limiter.limit(RateLimitConfig.WRITE)
def reply_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ReplyMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == current_user.id,
        )
        .first()
    )

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")
    
    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    parent_message = db.query(Messages).filter(Messages.conversation_id == conversation_id, Messages.id == data.message_id, Messages.type == "text").first()
    if not parent_message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        type="text",
        content={"text": data.text, "reply_to": {
            "id": parent_message.id,
            "content": {
                "text": parent_message.content["text"]
            },
            "created_at": parent_message.created_at.isoformat() if parent_message.created_at else None,
            "sender_id": parent_message.sender_id,
            "type": parent_message.type,
        }}
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

@router.delete("/{conversation_id}/messages", status_code=200)
@limiter.limit(RateLimitConfig.WRITE)
def delete_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: DeleteMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == current_user.id,
        )
        .first()
    )

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")
    
    message = db.query(Messages).filter(Messages.conversation_id == conversation_id, Messages.id == data.message_id, Messages.type == "text").first()
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
        content={"message": "conversations.deleted_message"}
    )

class EditMessageData(BaseModel):
    text: str
    message_id: str

@router.patch("/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.WRITE)
def edit_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EditMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == current_user.id,
        )
        .first()
    )

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")
    
    message: Messages = db.query(Messages).filter(Messages.conversation_id == conversation_id, Messages.id == data.message_id, Messages.type == "text").first()
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

    content = dict(message.content or {})
    content["text"] = data.text
    message.content = content

    message.edited_at = datetime.now(timezone.utc)
    
    db.commit()
    db.refresh(message)

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