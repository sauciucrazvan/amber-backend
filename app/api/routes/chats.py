
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.api.routes.auth import get_current_active_user
from app.database.models import UserDB
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
    
@router.post("/conversations/direct/{other_user_id}")
def open_direct_conversation(
    other_user_id: int,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],

):
    _validate_direct_chat_access(db, current_user.id, other_user_id)

    conversation = get_or_create_direct_conversation(
        db,
        current_user.id,
        other_user_id
    )

    return conversation