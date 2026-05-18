from datetime import datetime

from sqlalchemy.orm import Session

from app.api.utils.user import get_user_db_row_by_username
from app.database.models import UserDB
from app.database.models.relationship import Relationship
from app.ws import connection_manager


def _get_contact_usernames(db: Session, user_id: int) -> list[str]:
    outgoing = (
        db.query(UserDB.username)
        .join(Relationship, Relationship.other_user_id == UserDB.id)
        .filter(Relationship.user_id == user_id)
        .filter(Relationship.relation == "contact")
        .all()
    )

    incoming = (
        db.query(UserDB.username)
        .join(Relationship, Relationship.user_id == UserDB.id)
        .filter(Relationship.other_user_id == user_id)
        .filter(Relationship.relation == "contact")
        .all()
    )

    usernames = {
        username
        for (username,) in [*outgoing, *incoming]
        if isinstance(username, str) and username
    }
    return list(usernames)


async def broadcast_account_updated(username: str, db: Session) -> None:
    user_row = get_user_db_row_by_username(db, username)
    if user_row is None:
        return

    last_active_at = user_row.last_active_at
    if last_active_at is not None and isinstance(last_active_at, datetime):
        last_active_at = last_active_at.isoformat()

    registered_at = user_row.registered_at
    if registered_at is not None and isinstance(registered_at, datetime):
        registered_at = registered_at.isoformat()

    await connection_manager.manager.send_json_to_username(
        username,
        {
            "type": "account",
            "event": "account.updated",
            "payload": {
                "id": user_row.id,
                "username": user_row.username,
                "full_name": user_row.full_name,
                "email": user_row.email,
                "bio": user_row.bio,
                "avatar_url": user_row.avatar_url,
                "verified": user_row.verified,
                "last_active_at": last_active_at,
                "registered_at": registered_at,
            },
        },
    )


async def broadcast_contact_profile_updated(username: str, db: Session) -> None:
    user_row = get_user_db_row_by_username(db, username)
    if user_row is None:
        return

    recipients = _get_contact_usernames(db, user_row.id)
    if not recipients:
        return

    last_active_at = user_row.last_active_at
    if last_active_at is not None and isinstance(last_active_at, datetime):
        last_active_at = last_active_at.isoformat()

    await connection_manager.manager.send_json_to_usernames(
        recipients,
        {
            "type": "contacts",
            "event": "contact.profile.updated",
            "payload": {
                "user": {
                    "id": user_row.id,
                    "username": user_row.username,
                    "full_name": user_row.full_name,
                    "avatar_url": user_row.avatar_url,
                    "online": connection_manager.manager.is_user_online(user_row.username),
                    "last_active_at": last_active_at,
                },
            },
        },
    )
