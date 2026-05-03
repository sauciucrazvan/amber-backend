from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.api.routes.auth import get_current_active_user
from app.api.utils.user import get_user_db_row_by_username
from app.database.models import UserDB
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.conversations import Conversation
from app.database.models.messages import Messages
from app.database.models.relationship import Relationship
from app.database.session import get_db

from ..rate_limiter import limiter, RateLimitConfig

from app.ws.connection_manager import manager

router = APIRouter(prefix="/contacts", tags=["contacts"])


async def _emit_contact_event(usernames: list[str], event: str, payload: dict) -> None:
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


def _serialize_contact_user(user: User | UserDB) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "avatar_url": user.avatar_url,
        "online": manager.is_user_online(user.username),
        "last_active_at": user.last_active_at.isoformat() if user.last_active_at else None,
    }

def _pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


def _direct_pair_key(a_id: int, b_id: int) -> str:
    left_id, right_id = sorted((int(a_id), int(b_id)))
    return f"{left_id}:{right_id}"


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


def _get_direct_notifications_count(db: Session, me_id: int, other_id: int) -> int:
    conversation_id = (
        db.query(Conversation.id)
        .filter(Conversation.direct_pair == _direct_pair_key(me_id, other_id))
        .scalar()
    )
    if not conversation_id:
        return 0

    my_last_seen_seq = _get_last_seen_seq(db, conversation_id, me_id)
    unread_count = (
        db.query(func.count(Messages.id))
        .filter(Messages.conversation_id == conversation_id)
        .filter(Messages.sender_id != me_id)
        .filter(Messages.seq > my_last_seen_seq)
        .scalar()
    )
    return int(unread_count or 0)


def _serialize_last_message(message: Messages) -> dict:
    return {
        "sender_id": message.sender_id,
        "type": message.type,
        "content": message.content,
        "created_at": message.created_at.isoformat() if message.created_at else None,
    }


def _get_direct_last_message(db: Session, me_id: int, other_id: int) -> dict | None:
    conversation_id = (
        db.query(Conversation.id)
        .filter(Conversation.direct_pair == _direct_pair_key(me_id, other_id))
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

    return _serialize_last_message(message)


def _blocked_ids_for_user(db: Session, user_id: int) -> set[int]:
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


@router.get("/v1/list")
@limiter.limit(RateLimitConfig.READ)
async def list_contacts(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    me_id = current_user.id

    outgoing = (
        db.query(Relationship, UserDB)
        .join(UserDB, UserDB.id == Relationship.other_user_id)
        .filter(Relationship.user_id == me_id)
        .filter(Relationship.relation == "contact")
        .all()
    )

    incoming = (
        db.query(Relationship, UserDB)
        .join(UserDB, UserDB.id == Relationship.user_id)
        .filter(Relationship.other_user_id == me_id)
        .filter(Relationship.relation == "contact")
        .all()
    )

    by_user_id: dict[int, dict] = {}
    for (rel, other) in [*outgoing, *incoming]:
        sort_ts = rel.updated_at or rel.created_at
        payload = {
            "user": {
                "id": other.id,
                "username": other.username,
                "full_name": other.full_name,
                "avatar_url": other.avatar_url,
                "online": manager.is_user_online(other.username),
                "last_active_at": other.last_active_at.isoformat() if other.last_active_at else None,
            },
            "created_at": rel.created_at,
            "last_action_at": sort_ts,
            "notifications": _get_direct_notifications_count(db, me_id, other.id),
            "last_message": _get_direct_last_message(db, me_id, other.id),
            "_sort_ts": sort_ts,
        }
        existing = by_user_id.get(other.id)
        if existing is None or payload["_sort_ts"] > existing["_sort_ts"]:
            by_user_id[other.id] = payload

    blocked_ids = _blocked_ids_for_user(db, me_id)

    for blocked_id in blocked_ids:
        by_user_id.pop(blocked_id, None)

    items = sorted(
        by_user_id.values(),
        key=lambda x: (-(x["_sort_ts"].timestamp()), x["user"]["username"]),
    )
    
    for item in items:
        item.pop("_sort_ts", None)

    return items
      

# class AddContact(BaseModel):
#     username: str

# @router.post("/add")
# @limiter.limit(RateLimitConfig.WRITE)
# async def add_contact(
#     current_user: Annotated[User, Depends(get_current_active_user)],
#     data: AddContact,
#     db: Annotated[Session, Depends(get_db)],
#     request: Request,
# ):
#     username = (data.username or "").strip().lower()
#     if not username:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

#     if current_user.username == username:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="contacts.yourself"
#         )

#     other_user_row = get_user_db_row_by_username(db, username)
#     if other_user_row is None:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="contacts.invalid_user"
#         )

#     pair_rels = (
#         db.query(Relationship)
#         .filter(_pair_filter(current_user.id, other_user_row.id))
#         .all()
#     )
#     if any(r.relation == "blocked" for r in pair_rels):
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.blocked")

#     if any(r.relation == "contact" for r in pair_rels):
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.already_added")

#     relationship = Relationship(
#         user_id=current_user.id,
#         other_user_id=other_user_row.id,
#         relation="contact",
#     )
#     db.add(relationship)

#     try:
#         db.commit()
#     except IntegrityError:
#         db.rollback()
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.already_added")

#     return JSONResponse(status_code=200, content={"message": "contacts.added"})



class RemoveContact(BaseModel):
    username: str


@router.delete("/v1/remove")
@limiter.limit(RateLimitConfig.WRITE)
async def remove_contact(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: RemoveContact,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    rels = (
        db.query(Relationship)
        .filter(Relationship.relation == "contact")
        .filter(_pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    if not rels:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.not_found")

    for rel in rels:
        db.delete(rel)
    db.commit()

    await _emit_contact_event(
        [current_user.username, other_user_row.username],
        "contact.removed",
        {
            "user_id": current_user.id,
            "other_user_id": other_user_row.id,
        },
    )

    return JSONResponse(status_code=200, content={"message": "contacts.removed"})


class BlockUser(BaseModel):
    username: str


@router.put("/v1/block")
@limiter.limit(RateLimitConfig.WRITE)
async def block_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: BlockUser,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")
    
    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")
    if current_user.username == username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    now = datetime.now(timezone.utc)

    contact_rels = (
        db.query(Relationship)
        .filter(Relationship.relation == "contact")
        .filter(_pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    for rel in contact_rels:
        db.delete(rel)

    request_rels = (
        db.query(Relationship)
        .filter(Relationship.relation == "request")
        .filter(_pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    for rel in request_rels:
        db.delete(rel)

    existing = (
        db.query(Relationship)
        .filter(Relationship.user_id == current_user.id)
        .filter(Relationship.other_user_id == other_user_row.id)
        .one_or_none()
    )
    if existing is None:
        db.add(
            Relationship(
                user_id=current_user.id,
                other_user_id=other_user_row.id,
                relation="blocked",
            )
        )
    else:
        if existing.relation != "blocked":
            existing.relation = "blocked"
            existing.updated_at = now

    try:
        db.commit()
    except IntegrityError:
        db.rollback()

    await _emit_contact_event(
        [current_user.username, other_user_row.username],
        "contact.removed",
        {
            "user_id": current_user.id,
            "other_user_id": other_user_row.id,
        },
    )

    return JSONResponse(status_code=200, content={"message": "contacts.blocked.success"})


class UnblockUser(BaseModel):
    username: str


@router.delete("/v1/unblock")
@limiter.limit(RateLimitConfig.WRITE)
async def unblock_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: UnblockUser,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    rel = (
        db.query(Relationship)
        .filter(Relationship.user_id == current_user.id)
        .filter(Relationship.other_user_id == other_user_row.id)
        .filter(Relationship.relation == "blocked")
        .one_or_none()
    )
    if rel is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.not_blocked")

    db.delete(rel)
    db.commit()

    return JSONResponse(status_code=200, content={"message": "contacts.unblocked"})


@router.get("/v1/blocked")
@limiter.limit(RateLimitConfig.READ)
async def list_blocked(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    rows = (
        db.query(Relationship, UserDB)
        .join(UserDB, UserDB.id == Relationship.other_user_id)
        .filter(Relationship.user_id == current_user.id)
        .filter(Relationship.relation == "blocked")
        .order_by(Relationship.created_at.desc())
        .all()
    )

    return [
        {
            "user": {"id": other.id, "username": other.username},
            "created_at": rel.created_at,
        }
        for (rel, other) in rows
    ]


@router.get("/v1/requests")
@limiter.limit(RateLimitConfig.READ)
async def list_received_requests(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    blocked_ids = _blocked_ids_for_user(db, current_user.id)

    rows = (
        db.query(Relationship, UserDB)
        .join(UserDB, UserDB.id == Relationship.user_id)
        .filter(Relationship.other_user_id == current_user.id)
        .filter(Relationship.relation == "request")
        .order_by(Relationship.created_at.desc())
        .all()
    )

    return [
        {
            "user": {"id": other.id, "username": other.username, "full_name": other.full_name, "avatar_url": other.avatar_url},
            "created_at": rel.created_at,
        }
        for (rel, other) in rows
        if other.id not in blocked_ids
    ]


class RequestContact(BaseModel):
    username: str


@router.post("/v1/request")
@limiter.limit(RateLimitConfig.WRITE)
async def request_contact(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: RequestContact,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")
    if current_user.username == username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None or other_user_row.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    pair_rels = (
        db.query(Relationship)
        .filter(_pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    if any(r.relation == "blocked" for r in pair_rels):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.blocked.unreachable")
    if any(r.relation == "contact" for r in pair_rels):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.already_added")
    if any(r.relation == "request" for r in pair_rels):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.already_requested")

    request_rel = Relationship(
        user_id=current_user.id,
        other_user_id=other_user_row.id,
        relation="request",
    )
    db.add(request_rel)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.already_requested")

    await _emit_contact_event(
        [other_user_row.username],
        "contact.request.received",
        {
            "user": _serialize_contact_user(current_user),
            "created_at": request_rel.created_at.isoformat() if request_rel.created_at else None,
        },
    )

    return JSONResponse(status_code=200, content={"message": "contacts.requested"})


class AcceptContactRequest(BaseModel):
    username: str


@router.post("/v1/accept")
@limiter.limit(RateLimitConfig.WRITE)
async def accept_contact_request(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: AcceptContactRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    blocked = (
        db.query(Relationship.id)
        .filter(_pair_filter(current_user.id, other_user_row.id))
        .filter(Relationship.relation == "blocked")
        .first()
        is not None
    )
    if blocked:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.blocked.unreachable")

    rel = (
        db.query(Relationship)
        .filter(Relationship.user_id == other_user_row.id)
        .filter(Relationship.other_user_id == current_user.id)
        .filter(Relationship.relation == "request")
        .one_or_none()
    )
    if rel is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.no_request")

    rel.relation = "contact"
    rel.updated_at = datetime.now(timezone.utc)
    db.commit()

    last_action_at = rel.updated_at or rel.created_at
    await _emit_contact_event(
        [current_user.username],
        "contact.accepted",
        {
            "user": _serialize_contact_user(other_user_row),
            "created_at": rel.created_at.isoformat() if rel.created_at else None,
            "last_action_at": last_action_at.isoformat() if last_action_at else None,
        },
    )
    await _emit_contact_event(
        [other_user_row.username],
        "contact.accepted",
        {
            "user": _serialize_contact_user(current_user),
            "created_at": rel.created_at.isoformat() if rel.created_at else None,
            "last_action_at": last_action_at.isoformat() if last_action_at else None,
        },
    )
    await _emit_contact_event(
        [current_user.username],
        "contact.request.removed",
        {
            "user_id": other_user_row.id,
            "username": other_user_row.username,
        },
    )

    return JSONResponse(status_code=200, content={"message": "contacts.accepted"})


class DeclineContactRequest(BaseModel):
    username: str


@router.post("/v1/decline")
@limiter.limit(RateLimitConfig.WRITE)
async def decline_contact_request(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: DeclineContactRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    rel = (
        db.query(Relationship)
        .filter(Relationship.user_id == other_user_row.id)
        .filter(Relationship.other_user_id == current_user.id)
        .filter(Relationship.relation == "request")
        .one_or_none()
    )
    if rel is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.no_request")

    db.delete(rel)
    db.commit()

    await _emit_contact_event(
        [current_user.username],
        "contact.request.removed",
        {
            "user_id": other_user_row.id,
            "username": other_user_row.username,
        },
    )

    return JSONResponse(status_code=200, content={"message": "contacts.declined"})

@router.get("/v1/profile/{contact_username}")
@limiter.limit(RateLimitConfig.READ)
async def view_profile(
    current_user: Annotated[User, Depends(get_current_active_user)],
    contact_username: str,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not current_user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="common.unverified")

    username = (contact_username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")
    
    if current_user.username == username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")

    other_user_row = get_user_db_row_by_username(db, username)
    if other_user_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")
    
    pair_rels = (
        db.query(Relationship)
        .filter(_pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    if any(r.relation == "blocked" for r in pair_rels):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.blocked")

    if not any(r.relation == "contact" for r in pair_rels):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.not_added")
    
    user = db.query(UserDB).filter(UserDB.username == contact_username).one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "avatar_url": user.avatar_url,
        "registered_at": user.registered_at,
        "last_active_at": user.last_active_at,
        "bio": user.bio,
        "online": manager.is_user_online(user.username), 
        "verified": user.verified,
        "disabled": user.disabled,
    }