import base64
from datetime import datetime, timedelta, timezone
import json
import math
import os
import re
import secrets
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import resend
from sqlalchemy.orm import Session

from app.api.models.user import User
from ...rate_limiter import limiter, RateLimitConfig
from app.api.routes.auth.auth import get_current_active_user
from app.api.utils.time import _is_expired
from app.api.utils.user import authenticate_user, get_password_hash, get_user_db_row_by_email, get_user_db_row_by_username
from app.database.session import get_db

import app.api.routes.account.contacts as contacts

router = APIRouter(prefix="/account", tags=["account"])
router.include_router(contacts.router)
resend.api_key = os.getenv("RESEND_API_KEY")

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

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": auth_user.email, # type: ignore
        "subject": "Amber — Password changed",
        "html": f"""
            <div align="center">
                <section align="center">
                    <img src="https://www.razvansauciuc.dev/amber.png" width="128" height="128" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{auth_user.full_name}</u> (<b>@{auth_user.username}</b>).
                <br /><br />    
                We are letting you know that your password has been changed.
                <br />
                If you did not initiate this action, please reset your password<br />by using the 'Forgot Password' option.
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
    })

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
    password: str

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class EmailChangeRequest(BaseModel):
    new_email: str
    password: str


@router.post("/modify/email", status_code=status.HTTP_200_OK)
@router.post("/modify/email/request", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def request_email_change(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EmailChangeRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    auth_user = authenticate_user(db, current_user.username, data.password)
    if auth_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
        )

    email = (data.new_email or "").strip()
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

    now = datetime.now(timezone.utc)

    last_request_at = user_row.email_change_sent_at
    if last_request_at is not None:
        if last_request_at.tzinfo is None:
            last_request_at = last_request_at.replace(tzinfo=timezone.utc)
        if now - last_request_at < timedelta(minutes=30):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="settings.account.email.too_soon",
            )

    user_row.email_change_new_email = email
    user_row.email_change_confirmed_at = None
    user_row.email_change_code = secrets.randbelow(900000) + 100000
    user_row.email_change_sent_at = now
    db.commit()

    if user_row.email:
        resend.Emails.send({
            "from": "send@amber.razvansauciuc.dev",
            "to": user_row.email,
            "subject": "Amber — Confirm Your Email Change",
            "html": f"""
                <div align=\"center\">
                    <section align=\"center\">
                        <img src=\"https://www.razvansauciuc.dev/amber.png\" width=\"128\" height=\"128\" /><br /><b>Amber</b><br />
                    </section>
                    Hello, <u>{user_row.full_name}</u> (<b>@{user_row.username}</b>).
                    <br /><br />
                    We received a request to change your email to: <b>{email}</b>
                    <br />
                    To confirm this change, enter this code in the app: <strong>{user_row.email_change_code}</strong>
                    <br /><br />
                    <sub>If you did not request this, you can ignore this email. The code expires in 30 minutes.</sub>
                    <br /><br />
                    <b>The Amber Team — A Răzvan Sauciuc Production</b>
                </div>
            """.strip(),
        })

        return JSONResponse(status_code=200, content={"message": "settings.account.email.confirm_sent"})

    user_row.email_change_confirmed_at = now
    user_row.email_change_code = secrets.randbelow(900000) + 100000
    user_row.email_change_sent_at = now
    db.commit()

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": email,
        "subject": "Amber — Verify Your New Email",
        "html": f"""
            <div align=\"center\">
                <section align=\"center\">
                    <img src=\"https://www.razvansauciuc.dev/amber.png\" width=\"128\" height=\"128\" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{user_row.full_name}</u> (<b>@{user_row.username}</b>).
                <br /><br />
                To verify this email address belongs to you, enter this code in the app: <strong>{user_row.email_change_code}</strong>
                <br /><br />
                <sub>If you did not request this, you can ignore this email. The code expires in 30 minutes.</sub>
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
    })

    return JSONResponse(status_code=200, content={"message": "settings.account.email.verify_sent"})

class EmailChangeConfirm(BaseModel):
    code: str

@router.post("/modify/email/confirm", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def confirm_email_change(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EmailChangeConfirm,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not data.code or not data.code.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.invalid_code")

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user_row.email_change_new_email is None or user_row.email_change_code is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.no_pending")

    if user_row.email_change_confirmed_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.already_confirmed")

    now = datetime.now(timezone.utc)
    if _is_expired(user_row.email_change_sent_at, now=now, ttl=timedelta(minutes=30)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.too_late")

    if int(data.code) != user_row.email_change_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.invalid_code")

    new_email = user_row.email_change_new_email
    if get_user_db_row_by_email(db, new_email) is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="register.emailTaken")

    user_row.email_change_confirmed_at = now
    user_row.email_change_code = secrets.randbelow(900000) + 100000
    user_row.email_change_sent_at = now
    db.commit()

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": new_email,
        "subject": "Amber — Verify Your New Email",
        "html": f"""
            <div align=\"center\">
                <section align=\"center\">
                    <img src=\"https://www.razvansauciuc.dev/amber.png\" width=\"128\" height=\"128\" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{user_row.full_name}</u> (<b>@{user_row.username}</b>).
                <br /><br />
                To verify this email address belongs to you, enter this code in the app: <strong>{user_row.email_change_code}</strong>
                <br /><br />
                <sub>If you did not request this, you can ignore this email. The code expires in 30 minutes.</sub>
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
    })

    return JSONResponse(status_code=200, content={"message": "settings.account.email.verify_sent"})

class EmailChangeVerify(BaseModel):
    code: str

@router.post("/modify/email/verify", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def verify_email_change(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EmailChangeVerify,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not data.code or not data.code.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.invalid_code")

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user_row.email_change_new_email is None or user_row.email_change_code is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.no_pending")

    if user_row.email_change_confirmed_at is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.not_confirmed")

    now = datetime.now(timezone.utc)
    if _is_expired(user_row.email_change_sent_at, now=now, ttl=timedelta(minutes=30)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.too_late")

    if int(data.code) != user_row.email_change_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings.account.email.invalid_code")

    new_email = user_row.email_change_new_email
    if len(new_email) > 254 or not _EMAIL_RE.fullmatch(new_email):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="register.invalidEmail")

    if get_user_db_row_by_email(db, new_email) is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="register.emailTaken")

    user_row.email = new_email
    user_row.email_change_new_email = None
    user_row.email_change_code = None
    user_row.email_change_sent_at = None
    user_row.email_change_confirmed_at = None
    
    db.commit()

    return JSONResponse(status_code=200, content={"message": "settings.account.email.updated"})


class DeleteAccount(BaseModel):
    password: str

@router.post("/delete", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def delete_account(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: DeleteAccount,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if not data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_user = authenticate_user(db, current_user.username, data.password)
    if auth_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": user_row.email, # type: ignore
        "subject": "Amber — Your Account Has Been Deleted",
        "html": f"""
            <div align="center">
                <section align="center">
                    <img src="https://www.razvansauciuc.dev/amber.png" width="128" height="128" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{auth_user.full_name}</u> (<b>@{auth_user.username}</b>).
                <br /><br />    
                Your account has been successfully deleted and your information redacted.
                <br /><br />
                We are sorry to see you go! If you could take just 5 minutes to let us know why you've deleted your account, it would mean the world to us.
                <br /><br />
                Send us your feedback at: feedback@amber.razvansauciuc.dev
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
    })

    user_row.disabled = True
    user_row.full_name = "[redacted]"
    user_row.email = f"[redacted_{user_row.id}]"

    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.delete.success"}
    )


class RecoveryRequest(BaseModel):
    username: str

@router.post("/recovery/request", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def recovery_request(
    data: RecoveryRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request
):
    if not data.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_username",
        )
    
    user = get_user_db_row_by_username(db, data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_username",
        )

    if user.disabled:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="login.account_disabled")

    now = datetime.now(timezone.utc)

    last_request_at = user.recovery_sent_at
    if last_request_at is not None:
        if last_request_at.tzinfo is None:
            last_request_at = last_request_at.replace(tzinfo=timezone.utc)

        if now - last_request_at < timedelta(minutes=30):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="login.recovery.too_soon"
            )
    
    user.recovery_sent_at = now
    user.recovery_code = secrets.randbelow(900000) + 100000

    db.commit()

    if not user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_email",
        )

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": user.email,
        "subject": "Amber — Reset Your Password",
        "html": f"""
            <div align="center">
                <section align="center">
                    <img src="https://www.razvansauciuc.dev/amber.png" width="128" height="128" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{user.full_name}</u> (<b>@{user.username}</b>).
                <br /><br />    
                We've heard that you've forgot your password. Sorry to hear that!
                <br />
                No worries, we've got you covered - your password reset code is: <strong>{user.recovery_code}</strong>.
                <br /><br />
                <sub>If this wasn't you, you can safely ignore this email. The code will automatically expire in 30 minutes.</sub>
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
    })

    return JSONResponse(
        status_code=200,
        content={"message": "login.recovery.sent"},
    )

class ResetRequest(BaseModel):
    username: str
    code: str
    new_password: str
    new_password_confirmation: str

@router.post("/recovery/reset", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def reset_request(
    data: ResetRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request
):
    if not data.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_username",
        )
    
    if not data.code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_code",
        )
    
    if not data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_password",
        )
    
    if data.new_password != data.new_password_confirmation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.different_passwords",
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
    
    user = get_user_db_row_by_username(db, data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_username",
        )

    now = datetime.now(timezone.utc)

    if user.recovery_code is None or user.recovery_sent_at is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_code",
        )

    if not data.code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_code",
        )

    if int(data.code) != user.recovery_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_code",
        )

    if _is_expired(user.recovery_sent_at, now=now, ttl=timedelta(minutes=30)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.too_late",
        )
    
    user.hashed_password = get_password_hash(password)
    user.refresh_jti = secrets.token_urlsafe(16)
    user.recovery_code = None
    user.recovery_sent_at = None

    db.commit()

    if not user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="login.recovery.invalid_email",
        )

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": user.email,
        "subject": "Amber — Your Password Has Been Changed",
        "html": f"""
            <div align="center">
                <section align="center">
                    <img src="https://www.razvansauciuc.dev/amber.png" width="128" height="128" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{user.full_name}</u> (<b>@{user.username}</b>).
                <br /><br />    
                Your account password has been successfully changed via the recovery option.
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
    })

    return JSONResponse(
        status_code=200,
        content={"message": "login.recovery.success"},
    )


@router.get("/request/data", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def request_data(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)

    last_request_at = user_row.data_requested_at
    if last_request_at is not None:
        if last_request_at.tzinfo is None:
            last_request_at = last_request_at.replace(tzinfo=timezone.utc)

        if now - last_request_at < timedelta(days=7):
            raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="settings.account.data.too_soon",
        )

    export = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user": {
            "id": user_row.id,
            "username": user_row.username,
            "email": user_row.email,
            "full_name": user_row.full_name,
            "verified": user_row.verified,
            "disabled": user_row.disabled,
            "registered_at": user_row.registered_at.isoformat() if user_row.registered_at else None,
            "verified_at": user_row.verified_at.isoformat() if user_row.verified_at else None,
            "full_name_changed_at": user_row.full_name_changed_at.isoformat() if user_row.full_name_changed_at else None,
            "email_change_sent_at": user_row.email_change_sent_at.isoformat() if user_row.email_change_sent_at else None,
            "recovery_sent_at": user_row.recovery_sent_at.isoformat() if user_row.recovery_sent_at else None,
            "data_requested_at": user_row.data_requested_at.isoformat() if user_row.data_requested_at else None,
        },
    }

    payload_bytes = json.dumps(export, indent=2, ensure_ascii=False).encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    filename = f"amber-user-data-{user_row.username}.json"

    resend.Emails.send({
        "from": "send@amber.razvansauciuc.dev",
        "to": current_user.email, # type: ignore
        "subject": "Amber — Your Personal Data",
        "html": f"""
            <div align="center">
                <section align="center">
                    <img src="https://www.razvansauciuc.dev/amber.png" width="128" height="128" /><br /><b>Amber</b><br />
                </section>
                Hello, <u>{current_user.full_name}</u> (<b>@{current_user.username}</b>).
                <br /><br />    
                All the data we've collected about you is attached to this email.
                <br /><br />
                <b>The Amber Team — A Răzvan Sauciuc Production</b>
            </div>
        """.strip(),
        "attachments": [
            {
                "filename": filename,
                "content": payload_b64,
                "contentType": "application/json; charset=utf-8",
            }
        ],
    })

    user_row.data_requested_at = now
    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.data.sent"},
    )