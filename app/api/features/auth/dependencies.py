from datetime import datetime, timedelta, timezone
import secrets
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.api.models.token import TokenData
from app.api.models.user import User
from app.api.utils.jwt import JwtAuthError, decode_access_token
from app.api.utils.user import get_user_by_username
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, REFRESH_TOKEN_EXPIRE_DAYS, SECRET_KEY
from app.database.session import get_db


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/v1/login")


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
