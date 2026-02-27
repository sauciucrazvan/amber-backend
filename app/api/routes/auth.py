from datetime import datetime, timedelta, timezone
import os
import re
import secrets
from typing import Annotated
from typing import cast

from fastapi.responses import JSONResponse
import resend

from app.api.models.token import Token, TokenData
from app.api.models.user import User
from app.api.utils.time import _is_expired
from app.api.utils.user import (
    authenticate_user,
    create_user,
    get_user_by_username,
    get_user_db_row_by_email,
    get_user_db_row_by_username,
)

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.api.utils.jwt import JwtAuthError, decode_access_token
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, REFRESH_TOKEN_EXPIRE_DAYS, SECRET_KEY
from app.database.session import get_db
from ..rate_limiter import limiter, RateLimitConfig

router = APIRouter(prefix="/auth", tags=["auth"])
resend.api_key = os.getenv("RESEND_API_KEY")


def _build_amber_email_html(
        *,
        title: str,
        preheader: str,
        full_name: str,
        username: str,
        body_html: str,
        otp_code: str | None = None,
        otp_label: str = "One-time code",
        footer_note: str = "This is an automated Amber notification.",
) -> str:
        otp_block = ""
        if otp_code:
                otp_block = f"""
                    <br /><br />
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px;">
                        <tr>
                            <td align="center" style="padding: 12px 16px 6px 16px; font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.08em;">
                                {otp_label}
                            </td>
                        </tr>
                        <tr>
                            <td align="center" style="padding: 0 16px 14px 16px; font-size: 32px; font-weight: 700; color: #111827; letter-spacing: 0.24em; font-family: 'Courier New', Courier, monospace;">
                                {otp_code}
                            </td>
                        </tr>
                    </table>
                """.strip()

        return f"""
                <!doctype html>
                <html>
                    <head>
                        <meta charset="UTF-8" />
                        <title>{title}</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                    </head>
                    <body style="margin: 0; padding: 0; background-color: #f4f6f8; font-family: Arial, Helvetica, sans-serif;">
                        <div style="display: none; max-height: 0; overflow: hidden; opacity: 0; color: transparent;">
                            {preheader}
                        </div>

                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f6f8; padding: 40px 0;">
                            <tr>
                                <td align="center">
                                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width: 520px; background: #ffffff; border-radius: 12px; padding: 40px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);">
                                        <tr>
                                            <td align="center" style="padding-bottom: 24px;">
                                                <img src="https://www.razvansauciuc.dev/amber.png" width="96" height="96" alt="Amber Logo" style="display: block; border-radius: 20px;" />
                                                <div style="font-size: 22px; font-weight: bold; margin-top: 12px; color: #222;">Amber</div>
                                            </td>
                                        </tr>

                                        <tr>
                                            <td style="font-size: 15px; color: #333333; line-height: 1.6;">
                                                Hello, <strong>{full_name}</strong> (<span style="color: #6b7280">@{username}</span>).
                                                <br /><br />
                                                {body_html}
                                                {otp_block}
                                            </td>
                                        </tr>

                                        <tr>
                                            <td style="padding: 28px 0 12px 0;">
                                                <hr style="border: none; border-top: 1px solid #e5e7eb;" />
                                            </td>
                                        </tr>

                                        <tr>
                                            <td align="center" style="font-size: 13px; color: #9ca3af;">
                                                <strong style="color: #374151">The Amber Team</strong><br />
                                                {footer_note}
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>
        """.strip()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def _create_jwt(data: dict, expires_delta: timedelta | None, token_type: str):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    to_encode.update({"type": token_type})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_access_token(username: str, expires_delta: timedelta | None = None) -> str:
    return _create_jwt({"sub": username}, expires_delta, "access")


def create_refresh_token(username: str) -> str:
    jti = secrets.token_urlsafe(16)
    return _create_jwt(
        {"sub": username, "jti": jti},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "refresh",
    )

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        token_data = TokenData(username=payload.get("sub"))
    except JwtAuthError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    return current_user


# Routes

#
#       LOGIN
#

@router.post("/login")
@limiter.limit(RateLimitConfig.WRITE)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="login.account_disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.username, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.username)

    user_row = get_user_db_row_by_username(db, user.username)
    if user_row is not None:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_row.refresh_jti = payload.get("jti")
        db.add(user_row)
        db.commit()
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

#
#       REGISTER
#

_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{1,16}[a-z0-9])?$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class UserCreate(BaseModel):
    username: str
    password: str
    email: str | None = None
    full_name: str | None = None

@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
@limiter.limit(RateLimitConfig.WRITE)
async def register(
    request: Request,
    user: UserCreate,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    username = user.username.strip().lower()
    if len(username) < 3 or len(username) > 32 or not _USERNAME_RE.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.invalidUsername",
        )

    password = user.password
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

    full_name = (user.full_name or "").strip()
    if not full_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.nameRequired",
        )
    
    if len(full_name) < 0 or len(full_name) > 32:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="register.invalidName",
        )
    
    # if " " not in full_name or len(full_name.split()) < 2:
    #     raise HTTPException(
    #         status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    #         detail="register.invalidName",
    #     )

    email = None
    if user.email is not None:
        candidate_email = user.email.strip()
        if candidate_email:
            if len(candidate_email) > 254 or not _EMAIL_RE.fullmatch(candidate_email):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="register.invalidEmail",
                )
            email = candidate_email

    if get_user_db_row_by_username(db, username) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.usernameTaken",
        )

    if email is not None and get_user_db_row_by_email(db, email) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="register.emailTaken",
        )

    created = create_user(
        db,
        username=username,
        password=password,
        full_name=full_name,
        email=email,
    )

    return User(
        id=created.id,
        username=created.username,
        email=created.email,
        full_name=created.full_name,
        bio=None,
        disabled=created.disabled,
        verified=created.verified,
        registered_at=created.registered_at,
        verified_at=created.verified_at,
    )

#
#   REFRESH
#

class RefreshTokenRequest(BaseModel):
    refresh_token: str

@router.post("/refresh", response_model=Token)
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

#
#   VERIFY ACCOUNT
#


@router.post("/verify/request", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def verify_request(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
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
                detail="register.verify.too_soon"
            )

    user_row.verify_code = secrets.randbelow(900000) + 100000
    user_row.verify_sent_at = datetime.now(timezone.utc)
    db.commit()

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": user_row.email, # type: ignore
        "subject": "Amber — Verify Your Account",
        "html": _build_amber_email_html(
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
        content={"message": "register.verify.email_sent"}
    )


class Verify(BaseModel):
    verify_code: str

@router.post("/verify", status_code=status.HTTP_200_OK)
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

    return JSONResponse(
        status_code=200,
        content={"message": "register.verify.success"}
    )