from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.models.user import User
from app.api.routes.auth.auth import get_current_active_user
from app.api.utils.user import get_user_db_row_by_username
from app.database.models import UserDB
from app.database.models.relationship import Relationship
from app.database.session import get_db

from ...rate_limiter import limiter, RateLimitConfig

from app.ws.connection_manager import manager

router = APIRouter(prefix="/contacts", tags=["contacts"])


def _pair_filter(a_id: int, b_id: int):
    return or_(
        and_(Relationship.user_id == a_id, Relationship.other_user_id == b_id),
        and_(Relationship.user_id == b_id, Relationship.other_user_id == a_id),
    )


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


@router.get("/list")
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
            "user": {"id": other.id, "username": other.username, "full_name": other.full_name, "online": manager.is_user_online(other.username)},
            "created_at": rel.created_at,
            "_sort_ts": sort_ts,
        }
        existing = by_user_id.get(other.id)
        if existing is None or payload["_sort_ts"] > existing["_sort_ts"]:
            by_user_id[other.id] = payload

    blocked_ids = _blocked_ids_for_user(db, me_id)

    for blocked_id in blocked_ids:
        by_user_id.pop(blocked_id, None)

    items = sorted(by_user_id.values(), key=lambda x: (not x["user"]["online"], -(x["_sort_ts"].timestamp())))
    
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


@router.post("/remove")
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

    return JSONResponse(status_code=200, content={"message": "contacts.removed"})


class BlockUser(BaseModel):
    username: str


@router.post("/block")
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

    return JSONResponse(status_code=200, content={"message": "contacts.blocked.success"})


class UnblockUser(BaseModel):
    username: str


@router.post("/unblock")
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


@router.get("/blocked")
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


@router.get("/requests")
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
            "user": {"id": other.id, "username": other.username, "full_name": other.full_name},
            "created_at": rel.created_at,
        }
        for (rel, other) in rows
        if other.id not in blocked_ids
    ]


class RequestContact(BaseModel):
    username: str


@router.post("/request")
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
    if other_user_row is None:
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

    db.add(
        Relationship(
            user_id=current_user.id,
            other_user_id=other_user_row.id,
            relation="request",
        )
    )

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.already_requested")

    return JSONResponse(status_code=200, content={"message": "contacts.requested"})


class AcceptContactRequest(BaseModel):
    username: str


@router.post("/accept")
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

    return JSONResponse(status_code=200, content={"message": "contacts.accepted"})


class DeclineContactRequest(BaseModel):
    username: str


@router.post("/decline")
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

    return JSONResponse(status_code=200, content={"message": "contacts.declined"})

@router.get("/profile/{contact_username}")
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
        "verified": user.verified,
        "disabled": user.disabled,
    }