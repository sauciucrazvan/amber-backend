from datetime import datetime, timedelta, timezone
import math
import re
import secrets
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.api.models.user import User
from ...rate_limiter import limiter, RateLimitConfig
from app.api.routes.auth.auth import get_current_active_user
from app.api.utils.user import authenticate_user, get_password_hash, get_user_db_row_by_email, get_user_db_row_by_username
from app.database.session import get_db


router = APIRouter(prefix="/account", tags=["account"])

@router.get("/me", response_model=User)
async def profile(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


class ModifyPassword(BaseModel):
    current_password: str
    new_password: str
    new_password_confirmation: str

@router.post("/modify/password", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def modify_password(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ModifyPassword,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    auth_user = authenticate_user(db, current_user.username, data.current_password)
    if auth_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if data.new_password != data.new_password_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="settings.account.password.different",
        )

    password = data.new_password
    if (
        len(password) < 8
        or not any(ch.islower() for ch in password)
        or not any(ch.isupper() for ch in password)
        or not any(ch.isdigit() for ch in password)
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.invalidPassword",
        )

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_row.hashed_password = get_password_hash(password)
    user_row.refresh_jti = secrets.token_urlsafe(16)
    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.password.updated"}
    )
    

class ModifyFullname(BaseModel):
    new_full_name: str

@router.post("/modify/fullname", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def modify_name(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ModifyFullname,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    full_name = (data.new_full_name or "").strip()
    if not full_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.nameRequired",
        )
    if " " not in full_name or len(full_name.split()) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.invalidName",
        )

    if full_name == current_user.full_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="settings.account.name.same",
        )

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)
    if user_row.full_name_changed_at is not None:
        next_allowed_at = user_row.full_name_changed_at + timedelta(days=7)
        if now < next_allowed_at:
            remaining_days = math.ceil((next_allowed_at - now).total_seconds() / 86400)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "settings.account.name.tooSoon",
                    "remaining_days": remaining_days,
                },
            )

    user_row.full_name_changed_at = now
    user_row.full_name = data.new_full_name
    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.name.updated"}
    )

class ModifyEmail(BaseModel):
    new_email: str

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@router.post("/modify/email", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def modify_email(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ModifyEmail,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    email = data.new_email.strip()
    if not email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.emailRequired",
        )

    current_email = (current_user.email or "").strip()
    if email == current_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="settings.account.email.same",
        )

    if len(email) > 254 or not _EMAIL_RE.fullmatch(email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.invalidEmail",
        )

    if get_user_db_row_by_email(db, email) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.emailTaken",
        )

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_row.email = email
    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.email.updated"}
    )