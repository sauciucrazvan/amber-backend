from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Annotated
from typing import cast

from app.api.models.token import Token, TokenData
from app.api.models.user import User
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
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, REFRESH_TOKEN_EXPIRE_DAYS, SECRET_KEY
from app.database.session import get_db
from ...rate_limiter import limiter, RateLimitConfig

router = APIRouter(prefix="/auth", tags=["auth"])

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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_type = payload.get("type")
        if token_type is not None and token_type != "access":
            raise credentials_exception
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
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
    if " " not in full_name or len(full_name.split()) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="register.invalidName",
        )

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
        username=created.username,
        email=created.email,
        full_name=created.full_name,
        disabled=created.disabled,
        registered_at=created.registered_at,
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
    except InvalidTokenError:
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
