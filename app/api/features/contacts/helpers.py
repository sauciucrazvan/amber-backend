from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.database.models import UserDB
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.conversations import Conversation
from app.database.models.messages import Messages
from app.database.models.relationship import Relationship
from app.ws.connection_manager import manager


async def emit_contact_event(usernames: list[str], event: str, payload: dict) -> None:
    targets = [username for username in set(usernames) if username]
    if not targets:
        return

    await manager.send_json_to_usernames(
        targets,
        {
            "type": "contacts",
            "event": event,
            "payload": payload,
        },
    )


def serialize_contact_user(user: User | UserDB) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "avatar_url": user.avatar_url,
        "online": manager.is_user_online(user.username),
        "last_active_at": user.last_active_at.isoformat() if user.last_active_at else None,
    }


def pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


def direct_pair_key(a_id: int, b_id: int) -> str:
    left_id, right_id = sorted((int(a_id), int(b_id)))
    return f"{left_id}:{right_id}"


def get_last_seen_seq(db: Session, conversation_id: str, user_id: int) -> int:
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


def get_direct_notifications_count(db: Session, me_id: int, other_id: int) -> int:
    conversation_id = (
        db.query(Conversation.id)
        .filter(Conversation.direct_pair == direct_pair_key(me_id, other_id))
        .scalar()
    )
    if not conversation_id:
        return 0

    my_last_seen_seq = get_last_seen_seq(db, conversation_id, me_id)
    unread_count = (
        db.query(func.count(Messages.id))
        .filter(Messages.conversation_id == conversation_id)
        .filter(Messages.sender_id != me_id)
        .filter(Messages.seq > my_last_seen_seq)
        .scalar()
    )
    return int(unread_count or 0)


def serialize_last_message(message: Messages) -> dict:
    return {
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
    }


def get_direct_last_message(db: Session, me_id: int, other_id: int) -> dict | None:
    conversation_id = (
        db.query(Conversation.id)
        .filter(Conversation.direct_pair == direct_pair_key(me_id, other_id))
        .scalar()
    )
    if not conversation_id:
        return None

    message = (
        db.query(Messages)
        .filter(Messages.conversation_id == conversation_id)
        .order_by(Messages.seq.desc())
        .first()
    )
    if message is None:
        return None

    return serialize_last_message(message)


def blocked_ids_for_user(db: Session, user_id: int) -> set[int]:
    outgoing = {
        other_user_id
        for (other_user_id,) in db.query(Relationship.other_user_id)
        .filter(Relationship.user_id == user_id)
        .filter(Relationship.relation == "blocked")
        .all()
    }
    incoming = {
        other_user_id
        for (other_user_id,) in db.query(Relationship.user_id)
        .filter(Relationship.other_user_id == user_id)
        .filter(Relationship.relation == "blocked")
        .all()
    }
    return outgoing | incoming
