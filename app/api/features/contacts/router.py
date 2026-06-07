from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.features.auth.dependencies import get_current_active_user
from app.api.models.user import User
from app.api.rate_limiter import limiter, RateLimitConfig
from app.api.utils.audit_log import log_event
from app.api.utils.user import get_user_db_row_by_email, get_user_db_row_by_username
from app.database.models import UserDB
from app.database.models.relationship import Relationship
from app.database.session import get_db
from app.ws.connection_manager import manager

from .helpers import (
    blocked_ids_for_user,
    emit_contact_event,
    get_direct_last_message,
    get_direct_notifications_count,
    pair_filter,
    serialize_contact_user,
)
from .schemas import (
    AcceptContactRequest,
    BlockUser,
    DeclineContactRequest,
    RemoveContact,
    RequestContact,
    UnblockUser,
)


router = APIRouter(prefix="/contacts", tags=["contacts"])


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
            "notifications": get_direct_notifications_count(db, me_id, other.id),
            "last_message": get_direct_last_message(db, me_id, other.id),
            "_sort_ts": sort_ts,
        }
        existing = by_user_id.get(other.id)
        if existing is None or payload["_sort_ts"] > existing["_sort_ts"]:
            by_user_id[other.id] = payload

    blocked_ids = blocked_ids_for_user(db, me_id)

    for blocked_id in blocked_ids:
        by_user_id.pop(blocked_id, None)

    items = sorted(
        by_user_id.values(),
        key=lambda x: (-(x["_sort_ts"].timestamp()), x["user"]["username"]),
    )

    for item in items:
        item.pop("_sort_ts", None)

    return items


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
        .filter(pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    if not rels:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.not_found")

    for rel in rels:
        db.delete(rel)
    db.commit()

    await emit_contact_event(
        [current_user.username, other_user_row.username],
        "contact.removed",
        {
            "user_id": current_user.id,
            "other_user_id": other_user_row.id,
        },
    )

    log_event(
        db,
        request=request,
        event="contact_removed",
        status_code=status.HTTP_200_OK,
        username=current_user.username,
        user_id=current_user.id,
        details=f"target_username={other_user_row.username}",
    )

    return JSONResponse(status_code=200, content={"message": "contacts.removed"})


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
        .filter(pair_filter(current_user.id, other_user_row.id))
        .all()
    )
    for rel in contact_rels:
        db.delete(rel)

    request_rels = (
        db.query(Relationship)
        .filter(Relationship.relation == "request")
        .filter(pair_filter(current_user.id, other_user_row.id))
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

    await emit_contact_event(
        [current_user.username, other_user_row.username],
        "contact.removed",
        {
            "user_id": current_user.id,
            "other_user_id": other_user_row.id,
        },
    )

    log_event(
        db,
        request=request,
        event="contact_blocked",
        status_code=status.HTTP_200_OK,
        username=current_user.username,
        user_id=current_user.id,
        details=f"target_username={other_user_row.username}",
    )

    return JSONResponse(status_code=200, content={"message": "contacts.blocked.success"})


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

    log_event(
        db,
        request=request,
        event="contact_unblocked",
        status_code=status.HTTP_200_OK,
        username=current_user.username,
        user_id=current_user.id,
        details=f"target_username={other_user_row.username}",
    )

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

    blocked_ids = blocked_ids_for_user(db, current_user.id)

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

    identifier = (data.identifier or "").strip().lower()
    if not identifier:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")
    if current_user.username == identifier or current_user.email == identifier:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")

    other_user_row = get_user_db_row_by_username(db, identifier)
    if other_user_row is None:
        other_user_row = get_user_db_row_by_email(db, identifier)
        if other_user_row is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    if other_user_row.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")

    pair_rels = (
        db.query(Relationship)
        .filter(pair_filter(current_user.id, other_user_row.id))
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

    await emit_contact_event(
        [other_user_row.username],
        "contact.request.received",
        {
            "user": serialize_contact_user(current_user),
            "created_at": request_rel.created_at.isoformat() if request_rel.created_at else None,
        },
    )

    log_event(
        db,
        request=request,
        event="contact_request_sent",
        status_code=status.HTTP_200_OK,
        username=current_user.username,
        user_id=current_user.id,
        details=f"target_username={other_user_row.username}",
    )

    return JSONResponse(status_code=200, content={"message": "contacts.requested"})


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
        .filter(pair_filter(current_user.id, other_user_row.id))
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
    await emit_contact_event(
        [current_user.username],
        "contact.accepted",
        {
            "user": serialize_contact_user(other_user_row),
            "created_at": rel.created_at.isoformat() if rel.created_at else None,
            "last_action_at": last_action_at.isoformat() if last_action_at else None,
        },
    )
    await emit_contact_event(
        [other_user_row.username],
        "contact.accepted",
        {
            "user": serialize_contact_user(current_user),
            "created_at": rel.created_at.isoformat() if rel.created_at else None,
            "last_action_at": last_action_at.isoformat() if last_action_at else None,
        },
    )
    await emit_contact_event(
        [current_user.username],
        "contact.request.removed",
        {
            "user_id": other_user_row.id,
            "username": other_user_row.username,
        },
    )

    log_event(
        db,
        request=request,
        event="contact_request_accepted",
        status_code=status.HTTP_200_OK,
        username=current_user.username,
        user_id=current_user.id,
        details=f"target_username={other_user_row.username}",
    )

    return JSONResponse(status_code=200, content={"message": "contacts.accepted"})


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

    await emit_contact_event(
        [current_user.username],
        "contact.request.removed",
        {
            "user_id": other_user_row.id,
            "username": other_user_row.username,
        },
    )

    log_event(
        db,
        request=request,
        event="contact_request_declined",
        status_code=status.HTTP_200_OK,
        username=current_user.username,
        user_id=current_user.id,
        details=f"target_username={other_user_row.username}",
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
        .filter(pair_filter(current_user.id, other_user_row.id))
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
