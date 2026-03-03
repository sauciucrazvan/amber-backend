
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


router = APIRouter(prefix="/chats", tags=["chats"])

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="chats.no_relation")


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

    last_message = (
        db.query(Messages)
        .filter(
            Messages.conversation_id == conversation.id,
            Messages.sender_id != current_user.id,
        )
        .order_by(Messages.created_at.desc())
        .first()
    )

    seen_all_messages: bool = True if last_message is None else last_message.seen

    return {
        "id": conversation.id,
        "type": conversation.type,
        "direct_pair": conversation.direct_pair,
        "created_at": conversation.created_at,
        "seen": seen_all_messages
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

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.not_participating")
    
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

    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at,
        "edited_at": message.edited_at,
        "seen": message.seen,
    }

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
        raise HTTPException(status_code=403, detail="conversations.not_participating")
    
    query = (
        db.query(Messages)
        .filter(Messages.conversation_id == conversation_id)
    )

    query.filter(Messages.seen == False, Messages.sender_id != current_user.id).update({Messages.seen: True}, synchronize_session=False)
    db.commit()

    if before:
        query = query.filter(Messages.created_at < before)
    
    messages = (
        query
        .order_by(Messages.created_at.desc())
        .limit(limit)
        .all()
    )

    messages.reverse()
    return [
        {
            "id": message.id,
            "conversation_id": message.conversation_id,
            "sender_id": message.sender_id,
            "type": message.type,
            "content": message.content,
            "created_at": message.created_at,
            "edited_at": message.edited_at,
            "seen": message.seen,
        }
        for message in messages
    ]


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
        raise HTTPException(status_code=403, detail="conversations.not_participating")
    
    parent_message = db.query(Messages).filter(Messages.conversation_id == conversation_id, Messages.id == data.message_id, Messages.type == "text").first()
    if not parent_message:
        raise HTTPException(status_code=422, detail="conversations.invalid_message")

    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        type="text",
        content={"text": data.text, "reply_to": {
            "id": parent_message.id,
            "content": parent_message.content,
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

    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": str(message.created_at),
        "edited_at": str(message.edited_at),
        "seen": message.seen,
    }

class DeleteMessageData(BaseModel):
    message_id: str

@router.delete("/{conversation_id}/delete", status_code=200)
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
        raise HTTPException(status_code=403, detail="conversations.not_participating")
    
    message = db.query(Messages).filter(Messages.conversation_id == conversation_id, Messages.id == data.message_id, Messages.type == "text").first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.invalid_message")

    if message.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="conversations.cannot_delete_message")

    db.delete(message)
    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "conversations.deleted_message"}
    )