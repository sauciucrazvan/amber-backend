import base64
from datetime import datetime, timedelta, timezone
import json
import math
import os
import re
import secrets
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import resend
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.models.user import User
from ..rate_limiter import limiter, RateLimitConfig
from app.api.routes.auth import get_current_active_user
from app.api.utils.time import _is_expired
from app.api.utils.user import authenticate_user, get_password_hash, get_user_db_row_by_email, get_user_db_row_by_username
from app.ws import connection_manager
from app.database.models.messages import Messages
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.relationship import Relationship
from app.database.session import get_db

router = APIRouter(prefix="/account", tags=["account"])
resend.api_key = os.getenv("RESEND_API_KEY")


def _enqueue_email(background_tasks: BackgroundTasks, payload: dict) -> None:
    background_tasks.add_task(resend.Emails.send, payload) # type: ignore


async def _broadcast_account_updated(username: str, db: Session) -> None:
    user_row = get_user_db_row_by_username(db, username)
    if user_row is None:
        return

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
                "verified": user_row.verified,
            },
        },
    )


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

@router.get("/v1/me", response_model=User)
async def profile(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user

class ModifyPassword(BaseModel):
    current_password: str
    new_password: str
    new_password_confirmation: str

@router.patch("/v1/modify/password", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def modify_password(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ModifyPassword,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": auth_user.email, # type: ignore
        "subject": "Amber — Password changed",
        "html": _build_amber_email_html(
            title="Amber — Password Changed",
            preheader="Your Amber password was successfully changed.",
            full_name=auth_user.full_name, # type: ignore
            username=auth_user.username,
            body_html="""
                We are letting you know that your password has been changed.
                <br /><br />
                If you did not initiate this action, please reset your password by using the Forgot Password option.
            """.strip(),
            footer_note="This is an automated security notification.",
        ),
    })

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.password.updated"}
    )
    

class ModifyFullname(BaseModel):
    new_full_name: str

@router.patch("/v1/modify/fullname", status_code=status.HTTP_200_OK)
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
    
    # if " " not in full_name or len(full_name.split()) < 2:
    #     raise HTTPException(
    #         status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    #         detail="register.invalidName",
    #     )

    if len(full_name) < 0 or len(full_name) > 32:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
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
    await _broadcast_account_updated(current_user.username, db)

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


@router.post("/v1/modify/email", status_code=status.HTTP_200_OK)
@router.post("/v1/modify/email/request", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def request_email_change(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EmailChangeRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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
        _enqueue_email(background_tasks, {
            "from": "send@amber.razvansauciuc.dev",
            "to": user_row.email,
            "subject": "Amber — Confirm Your Email Change",
            "html": _build_amber_email_html(
                title="Amber — Confirm Your Email Change",
                preheader="Confirm your requested Amber email change.",
                full_name=user_row.full_name,
                username=user_row.username,
                body_html=f"""
                    We received a request to change your email to: <strong>{email}</strong>
                    <br /><br />
                    To confirm this change, enter the code below in the app.
                    <br /><br />
                    <span style=\"font-size: 13px; color: #6b7280;\">If you did not request this, you can ignore this email. The code expires in 30 minutes.</span>
                """.strip(),
                otp_code=str(user_row.email_change_code),
                otp_label="Email Change Confirmation Code",
                footer_note="This is an automated security notification.",
            ),
        })

        return JSONResponse(status_code=200, content={"message": "settings.account.email.confirm_sent"})

    user_row.email_change_confirmed_at = now
    user_row.email_change_code = secrets.randbelow(900000) + 100000
    user_row.email_change_sent_at = now
    db.commit()

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": email,
        "subject": "Amber — Verify Your New Email",
        "html": _build_amber_email_html(
            title="Amber — Verify Your New Email",
            preheader="Verify your new email address for Amber.",
            full_name=user_row.full_name,
            username=user_row.username,
            body_html=f"""
                To verify this email address belongs to you, enter the code below in the app.
                <br /><br />
                <span style=\"font-size: 13px; color: #6b7280;\">If you did not request this, you can ignore this email. The code expires in 30 minutes.</span>
            """.strip(),
            otp_code=str(user_row.email_change_code),
            otp_label="New Email Verification Code",
            footer_note="This is an automated security notification.",
        ),
    })

    return JSONResponse(status_code=200, content={"message": "settings.account.email.verify_sent"})

class EmailChangeConfirm(BaseModel):
    code: str

@router.post("/v1/modify/email/confirm", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def confirm_email_change(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EmailChangeConfirm,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": new_email,
        "subject": "Amber — Verify Your New Email",
        "html": _build_amber_email_html(
            title="Amber — Verify Your New Email",
            preheader="Verify your new email address for Amber.",
            full_name=user_row.full_name,
            username=user_row.username,
            body_html=f"""
                To verify this email address belongs to you, enter the code below in the app.
                <br /><br />
                <span style=\"font-size: 13px; color: #6b7280;\">If you did not request this, you can ignore this email. The code expires in 30 minutes.</span>
            """.strip(),
            otp_code=str(user_row.email_change_code),
            otp_label="New Email Verification Code",
            footer_note="This is an automated security notification.",
        ),
    })

    return JSONResponse(status_code=200, content={"message": "settings.account.email.verify_sent"})

class EmailChangeVerify(BaseModel):
    code: str

@router.post("/v1/modify/email/verify", status_code=status.HTTP_200_OK)
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
    await _broadcast_account_updated(current_user.username, db)

    return JSONResponse(status_code=200, content={"message": "settings.account.email.updated"})


class DeleteAccount(BaseModel):
    password: str

@router.delete("/v1/delete", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def delete_account(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: DeleteAccount,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": user_row.email, # type: ignore
        "subject": "Amber — Your Account Has Been Deleted",
        "html": _build_amber_email_html(
            title="Amber — Your Account Has Been Deleted",
            preheader="Your Amber account has been deleted.",
            full_name=auth_user.full_name, # type: ignore
            username=auth_user.username,
            body_html="""
                Your account has been successfully deleted and your information redacted.
                <br /><br />
                We are sorry to see you go. If you can spare 5 minutes to share why you deleted your account, we would really appreciate your feedback.
                <br /><br />
                Send us your feedback at: <strong>feedback@amber.razvansauciuc.dev</strong>
            """.strip(),
        ),
    })

    user_row.disabled = True
    user_row.full_name = "[redacted]"
    user_row.email = f"[redacted_{user_row.id}]"

    (
        db.query(Relationship)
        .filter(Relationship.user_id == user_row.id)
        .delete(synchronize_session=False)
    )
    (
        db.query(Relationship)
        .filter(Relationship.other_user_id == user_row.id)
        .delete(synchronize_session=False)
    )
    (
        db.query(Messages)
        .filter(Relationship.user_id == user_row.id)
        .delete(synchronize_session=False)
    )
    (
        db.query(Messages)
        .filter(Relationship.other_user_id == user_row.id)
        .delete(synchronize_session=False)
    )

    db.commit()

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.delete.success"}
    )


class RecoveryRequest(BaseModel):
    username: str

@router.post("/v1/recovery/request", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def recovery_request(
    data: RecoveryRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": user.email,
        "subject": "Amber — Reset Your Password",
        "html": _build_amber_email_html(
            title="Amber — Reset Your Password",
            preheader="Use this code to reset your Amber password.",
            full_name=user.full_name,
            username=user.username,
            body_html=f"""
                We received a request to reset your password.
                <br /><br />
                Enter the code below to continue resetting your password.
                <br /><br />
                <span style=\"font-size: 13px; color: #6b7280;\">If this wasn't you, you can safely ignore this email. The code automatically expires in 30 minutes.</span>
            """.strip(),
            otp_code=str(user.recovery_code),
            otp_label="Password Reset Code",
            footer_note="This is an automated security notification.",
        ),
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

@router.post("/v1/recovery/reset", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def reset_request(
    data: ResetRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": user.email,
        "subject": "Amber — Your Password Has Been Changed",
        "html": _build_amber_email_html(
            title="Amber — Password Changed",
            preheader="Your Amber password was successfully changed.",
            full_name=user.full_name,
            username=user.username,
            body_html="""
                Your account password has been successfully changed using the recovery option.
                <br /><br />
                If you did not perform this action, please secure your account immediately.
            """.strip(),
            footer_note="This is an automated security notification.",
        ),
    })

    return JSONResponse(
        status_code=200,
        content={"message": "login.recovery.success"},
    )


@router.post("/v1/request/data", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def request_data(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    background_tasks: BackgroundTasks,
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

    relationships = (
        db.query(Relationship)
        .filter(
            or_(
                Relationship.user_id == user_row.id,
                Relationship.other_user_id == user_row.id,
            )
        )
        .order_by(Relationship.created_at.asc())
        .all()
    )

    conversation_ids = [
        conversation_id
        for (conversation_id,) in db.query(ConversationParticipants.conversation_id)
        .filter(ConversationParticipants.user_id == user_row.id)
        .all()
    ]

    messages = []
    if conversation_ids:
        messages = (
            db.query(Messages)
            .filter(Messages.conversation_id.in_(conversation_ids))
            .order_by(Messages.created_at.asc())
            .all()
        )

    export = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user": {
            "id": user_row.id,
            "username": user_row.username,
            "email": user_row.email,
            "full_name": user_row.full_name,
            "bio": user_row.bio,
            "verified": user_row.verified,
            "disabled": user_row.disabled,
            "registered_at": user_row.registered_at.isoformat() if user_row.registered_at else None,
            "verified_at": user_row.verified_at.isoformat() if user_row.verified_at else None,
            "full_name_changed_at": user_row.full_name_changed_at.isoformat() if user_row.full_name_changed_at else None,
            "email_change_sent_at": user_row.email_change_sent_at.isoformat() if user_row.email_change_sent_at else None,
            "recovery_sent_at": user_row.recovery_sent_at.isoformat() if user_row.recovery_sent_at else None,
            "data_requested_at": user_row.data_requested_at.isoformat() if user_row.data_requested_at else None,
        },
        "relationships": [
            {
                "id": relation.id,
                "user_id": relation.user_id,
                "other_user_id": relation.other_user_id,
                "relation": relation.relation,
                "created_at": relation.created_at.isoformat() if relation.created_at else None,
                "updated_at": relation.updated_at.isoformat() if relation.updated_at else None,
            }
            for relation in relationships
        ],
        "messages": [
            {
                "id": message.id,
                "conversation_id": message.conversation_id,
                "sender_id": message.sender_id,
                "seen": message.seen,
                "type": message.type,
                "content": message.content,
                "created_at": message.created_at.isoformat() if message.created_at else None,
                "edited_at": message.edited_at.isoformat() if message.edited_at else None,
            }
            for message in messages
        ],
    }

    payload_bytes = json.dumps(export, indent=2, ensure_ascii=False).encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    filename = f"amber-user-data-{user_row.username}.json"

    _enqueue_email(background_tasks, {
        "from": "send@amber.razvansauciuc.dev",
        "to": current_user.email, # type: ignore
        "subject": "Amber — Your Personal Data",
        "html": _build_amber_email_html(
            title="Amber — Your Personal Data",
            preheader="Your Amber personal data export is attached.",
            full_name=current_user.full_name, # type: ignore
            username=current_user.username,
            body_html="""
                All the data we have collected about your account is attached to this email.
            """.strip(),
        ),
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

class ModifyBio(BaseModel):
    new_bio: str

@router.patch("/v1/modify/bio", status_code=status.HTTP_200_OK)
@limiter.limit(RateLimitConfig.WRITE)
async def modify_bio(
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ModifyBio,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
):
    if data.new_bio and len(data.new_bio) > 256:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="settings.account.bio.too_long",
        )
    
    user_row = get_user_db_row_by_username(db, current_user.username)
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login.incorrectCredentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_row.bio = data.new_bio
    db.commit()
    await _broadcast_account_updated(current_user.username, db)

    return JSONResponse(
        status_code=200,
        content={"message": "settings.account.bio.updated"}
    )