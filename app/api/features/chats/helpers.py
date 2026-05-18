import asyncio
from datetime import datetime, timezone
import emoji
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.models import UserDB
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.conversations import Conversation
from app.database.models.messages import Messages
from app.database.models.relationship import Relationship
from app.ws import connection_manager


def normalize_reaction_user_ids(raw_value: object) -> list[int]:
    if isinstance(raw_value, list):
        values = raw_value
    elif raw_value is None:
        values = []
    else:
        values = [raw_value]

    normalized: list[int] = []
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            user_id = value
        elif isinstance(value, (str, bytes, bytearray)):
            try:
                user_id = int(value)
            except ValueError:
                continue
        else:
            continue

        if user_id not in normalized:
            normalized.append(user_id)

    return normalized


def normalize_reaction_entry(raw_value: object) -> tuple[list[int], str | None]:
    if isinstance(raw_value, dict):
        user_ids = normalize_reaction_user_ids(raw_value.get("user_ids"))
        first_added_at_raw = raw_value.get("first_added_at")
        first_added_at = (
            first_added_at_raw.strip()
            if isinstance(first_added_at_raw, str) and first_added_at_raw.strip()
            else None
        )
        return user_ids, first_added_at

    user_ids = normalize_reaction_user_ids(raw_value)
    return user_ids, None


def normalize_reactions_map(raw_reactions: object) -> dict[str, dict]:
    if not isinstance(raw_reactions, dict):
        return {}

    normalized: dict[str, dict] = {}
    for emoji_key, raw_value in raw_reactions.items():
        if not isinstance(emoji_key, str) or not emoji_key:
            continue

        user_ids, first_added_at = normalize_reaction_entry(raw_value)
        if not user_ids:
            continue

        normalized[emoji_key] = {
            "user_ids": user_ids,
            "first_added_at": first_added_at,
        }

    return normalized


def serialize_reaction_details(raw_reactions: object) -> list[dict]:
    reactions = normalize_reactions_map(raw_reactions)
    rows: list[dict] = []

    for emoji_key, value in reactions.items():
        user_ids = value.get("user_ids") or []
        first_added_at = value.get("first_added_at")
        rows.append(
            {
                "emoji": emoji_key,
                "count": len(user_ids),
                "user_ids": user_ids,
                "first_added_at": first_added_at,
            }
        )

    rows.sort(
        key=lambda row: (
            row.get("first_added_at") is None,
            row.get("first_added_at") or "",
            row.get("emoji") or "",
        )
    )
    return rows


def serialize_message(message: Messages, *, seen_override: bool | None = None) -> dict:
    reaction_details = serialize_reaction_details(message.reactions)
    return {
        "id": message.id,
        "conversation_id": message.conversation_id,
        "sender_id": message.sender_id,
        "seq": message.seq,
        "type": message.type,
        "content": message.content,
        "reactions": {
            row["emoji"]: row["count"]
            for row in reaction_details
        },
        "reaction_details": reaction_details,
        "created_at": message.created_at.isoformat() if message.created_at else None,
        "edited_at": message.edited_at.isoformat() if message.edited_at else None,
        "seen": message.seen if seen_override is None else seen_override,
    }


def dispatch_chat_event(usernames: list[str], payload: dict) -> None:
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


def get_conversation_participant_usernames(db: Session, conversation_id: str) -> list[str]:
    return [
        username
        for (username,) in db.query(UserDB.username)
        .join(ConversationParticipants, ConversationParticipants.user_id == UserDB.id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]


def emit_conversation_event(
    db: Session,
    conversation_id: str,
    event_type: str,
    payload: dict,
) -> None:
    usernames = get_conversation_participant_usernames(db, conversation_id)
    dispatch_chat_event(
        usernames,
        {
            "event": event_type,
            "conversation_id": conversation_id,
            "payload": payload,
        },
    )


def emit_contact_last_action_updates(
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

        dispatch_chat_event(
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

        dispatch_chat_event(
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


def serialize_last_message(message: Messages) -> dict:
    return {
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
    }


def emit_contact_last_message_updates(
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

    last_message = serialize_last_message(message)

    for other_user_id in other_user_ids:
        other_username = username_by_id.get(other_user_id)
        if not other_username:
            continue

        dispatch_chat_event(
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

        dispatch_chat_event(
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


def emit_read_cursor_updated(
    db: Session,
    conversation_id: str,
    reader_id: int,
    last_seen_seq: int,
    last_seen_at: datetime,
) -> None:
    emit_conversation_event(
        db,
        conversation_id,
        "conversation.read_cursor.updated",
        {
            "reader_id": reader_id,
            "last_seen_seq": last_seen_seq,
            "last_seen_at": last_seen_at.isoformat(),
        },
    )


def is_conversation_participant(db: Session, conversation_id: str, user_id: int) -> bool:
    return (
        db.query(ConversationParticipants)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id == user_id,
        )
        .first()
        is not None
    )


def get_conversation_max_seq(db: Session, conversation_id: str) -> int:
    value = (
        db.query(func.max(Messages.seq))
        .filter(Messages.conversation_id == conversation_id)
        .scalar()
    )
    return int(value or 0)


def next_message_seq(db: Session, conversation_id: str) -> int:
    return get_conversation_max_seq(db, conversation_id) + 1


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


def advance_read_cursor(
    db: Session,
    conversation_id: str,
    user_id: int,
    upto_seq: int,
) -> tuple[int, int, datetime]:
    now = datetime.now(timezone.utc)
    max_seq = get_conversation_max_seq(db, conversation_id)
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


def pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


def is_only_emojis(value: str) -> bool:
    if not isinstance(value, str) or value == "":
        return False
    parts = emoji.emoji_list(value)
    return "".join(p["emoji"] for p in parts) == value


def normalize_emoji(emoji_input: str) -> str:
    if not isinstance(emoji_input, str) or emoji_input == "":
        raise ValueError("invalid")

    normalized = emoji_input
    if emoji_input.startswith(":") and emoji_input.endswith(":"):
        normalized = emoji.emojize(emoji_input, language="en")

    normalized = normalized.strip()

    if not is_only_emojis(normalized):
        raise ValueError("invalid")

    return normalized


def validate_direct_chat_access(db: Session, current_user_id: int, other_user_id: int) -> None:
    if current_user_id == other_user_id:
        raise ValueError("self")

    other_user = db.query(UserDB.id).filter(UserDB.id == other_user_id).one_or_none()
    if other_user is None:
        raise ValueError("invalid")

    pair_rels = (
        db.query(Relationship.relation)
        .filter(pair_filter(current_user_id, other_user_id))
        .all()
    )
    relations = {relation for (relation,) in pair_rels}

    if "blocked" in relations:
        raise ValueError("blocked")

    if "contact" not in relations:
        raise PermissionError("no_relation")


def get_or_create_direct_conversation(db: Session, user_a_id: int, user_b_id: int) -> Conversation:
    if user_a_id == user_b_id:
        raise ValueError("self")

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
