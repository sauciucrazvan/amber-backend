from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Annotated, cast

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
import jwt
from sqlalchemy.orm import Session

from app.api.models.token import Token
from app.api.models.user import User
from app.api.rate_limiter import limiter, RateLimitConfig
from app.api.utils.audit_log import get_client_ip, log_event
from app.api.utils.otp_guard import clear_attempts, is_locked, register_failed_attempt
from app.api.utils.time import _is_expired
from app.api.utils.user import (
    authenticate_user,
    create_user,
    get_user_db_row_by_email,
    get_user_db_row_by_username,
)
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY
from app.database.session import get_db
from app.ws import connection_manager

from .dependencies import create_access_token, create_refresh_token, get_current_active_user
from .email import build_amber_email_html, enqueue_email
from .schemas import RefreshTokenRequest, UserCreate, Verify


router = APIRouter(prefix="/auth", tags=["auth"])


_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{1,14}[a-z0-9])?$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.post("/v1/login")
@limiter.limit(RateLimitConfig.WRITE)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    client_ip = get_client_ip(request)
    if is_locked("login_ip", client_ip):
        log_event(
            db,
            request=request,
            event="login_blocked",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            username=form_data.username,
            user_id=None,
            details="ip_locked",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="login.locked",
        )

    user = authenticate_user(db, form_data.username.lower(), form_data.password)
    if user is None:
        is_now_locked = register_failed_attempt("login_ip", client_ip)
        if is_now_locked:
            log_event(
                db,
                request=request,
                event="login_blocked",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                username=form_data.username,
                user_id=None,
                details="ip_locked",
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="login.locked",
            )
        
        log_event(
            db,
            request=request,
            event="login_failed",
            status_code=status.HTTP_401_UNAUTHORIZED,
            username=form_data.username,
            user_id=None,
            details="invalid_credentials",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.disabled:
        log_event(
            db,
            request=request,
            event="login_disabled",
            status_code=status.HTTP_410_GONE,
            username=user.username,
            user_id=user.id,
            details="account_disabled",
        )
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="login.account_disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clear_attempts("login_ip", client_ip)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.username, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.username)

    user_row = get_user_db_row_by_username(db, user.username)
    if user_row is not None:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_row.refresh_jti = payload.get("jti")
        db.add(user_row)
        db.commit()
    log_event(
        db,
        request=request,
        event="login_success",
        status_code=status.HTTP_200_OK,
        username=user.username,
        user_id=user.id,
    )
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post("/v1/register", response_model=User, status_code=status.HTTP_201_CREATED)
@limiter.limit(RateLimitConfig.WRITE)
async def register(
    request: Request,
    user: UserCreate,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    errors = []

    username = user.username.strip().lower()
    if len(username) < 3 or len(username) > 16 or not _USERNAME_RE.fullmatch(username):
        errors.append({
            "error": "register.invalidUsername",
            "field": "username"
        })

    password = user.password
    if (
        len(password) < 8
        or not any(ch.islower() for ch in password)
        or not any(ch.isupper() for ch in password)
        or not any(ch.isdigit() for ch in password)
    ):
        errors.append({
            "error": "register.invalidPassword",
            "field": "password"
        })

    full_name = (user.full_name or "").strip()
    if not full_name:
        errors.append({
            "error": "register.nameRequired",
            "field": "full_name"
        })
    elif len(full_name) > 32:
        errors.append({
            "error": "register.invalidName",
            "field": "full_name"
        })

    username_valid = not any(err["field"] == "username" for err in errors)
    if username_valid and get_user_db_row_by_username(db, username) is not None:
        errors.append({
            "error": "register.usernameTaken",
            "field": "username"
        })

    email = None
    if not user.email or not user.email.strip():
        errors.append({"error": "register.emailRequired", "field": "email"})
    else:
        candidate_email = user.email.strip()
        if len(candidate_email) > 254 or not _EMAIL_RE.fullmatch(candidate_email):
            errors.append({"error": "register.invalidEmail", "field": "email"})
        elif get_user_db_row_by_email(db, candidate_email) is not None:
            errors.append({"error": "register.emailTaken", "field": "email"})
        else:
            email = candidate_email

    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"errors": errors}
        )

    created = create_user(
        db,
        username=username,
        password=password,
        full_name=full_name,
        email=email,
    )

    log_event(
        db,
        request=request,
        event="register_success",
        status_code=status.HTTP_201_CREATED,
        username=created.username,
        user_id=created.id,
    )

    return User(
        id=created.id,
        username=created.username,
        email=created.email,
        full_name=created.full_name,
        bio=None,
        avatar_url=created.avatar_url,
        disabled=created.disabled,
        verified=created.verified,
        registered_at=created.registered_at,
        verified_at=created.verified_at,
        last_active_at=created.last_active_at,
    )


@router.post("/v1/refresh", response_model=Token)
@limiter.limit(RateLimitConfig.WRITE)
async def refresh_access_token(
    request: Request,
    body: RefreshTokenRequest,
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(body.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise credentials_exception
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        jti = payload.get("jti")
        if not jti:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception

    user_row = get_user_db_row_by_username(db, username=username)
    if user_row is None or cast(bool, user_row.disabled):
        raise credentials_exception

    if user_row.refresh_jti != jti:
        raise credentials_exception

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(username, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(username)

    payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    user_row.refresh_jti = payload.get("jti")
    db.add(user_row)
    db.commit()
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post("/v1/verify/request", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def verify_request(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
):
    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user_row.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.verify.already_verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)

    last_request_at = user_row.verify_sent_at
    if last_request_at is not None:
        if last_request_at.tzinfo is None:
            last_request_at = last_request_at.replace(tzinfo=timezone.utc)

        if now - last_request_at < timedelta(minutes=30):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="register.verify.too_soon",
            )

    user_row.verify_code = secrets.randbelow(900000) + 100000
    user_row.verify_sent_at = datetime.now(timezone.utc)
    db.commit()

    enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": user_row.email, # type: ignore
        "subject": "Amber — Verify Your Account",
        "html": build_amber_email_html(
            title="Amber — Verify Your Account",
            preheader="Verify your Amber account with this code.",
            full_name=user_row.full_name,
            username=user_row.username,
            body_html=f"""
                Before you can use Amber to its full capabilities, you need to activate your account.
                <br /><br />
                Enter the code below to complete verification.
            """.strip(),
            otp_code=str(user_row.verify_code),
            otp_label="Account Verification Code",
            footer_note="This is an automated security notification.",
        ),
    })

    return JSONResponse(
        status_code=200,
        content={"message": "register.verify.email_sent"},
    )


@router.post("/v1/verify", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def complete_verification(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: Verify,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not data.verify_code or data.verify_code is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.verify.invalid_code",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not data.verify_code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.verify.invalid_code",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if is_locked("verify", current_user.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="register.verify.locked",
        )

    if user_row.verify_sent_at is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.verify.invalid_code",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user_row.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.verify.already_verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user_row.verify_code != int(data.verify_code):
        is_now_locked = register_failed_attempt("verify", current_user.username)
        if is_now_locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="register.verify.locked",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.verify.invalid_code",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)
    if _is_expired(user_row.verify_sent_at, now=now, ttl=timedelta(minutes=30)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.too_late",
        )

    user_row.verified = True
    user_row.verified_at = datetime.now(timezone.utc)
    db.commit()

    clear_attempts("verify", current_user.username)

    await connection_manager.manager.send_json_to_username(
        current_user.username,
        {
            "type": "account",
            "event": "account.updated",
            "payload": {
                "id": user_row.id,
                "username": user_row.username,
                "full_name": user_row.full_name,
                "email": user_row.email,
                "bio": user_row.bio,
                "verified": user_row.verified,
            },
        },
    )

    return JSONResponse(
        status_code=200,
        content={"message": "register.verify.success"},
    )
