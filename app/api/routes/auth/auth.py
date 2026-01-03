from datetime import datetime, timedelta, timezone
import re
import secrets
from typing import Annotated

from app.api.models.token import Token, TokenData
from app.api.models.user import User
from app.api.utils.user import authenticate_user, get_password_hash, get_user

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, REFRESH_TOKEN_EXPIRE_DAYS, SECRET_KEY
from ...rate_limiter import limiter, RateLimitConfig

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w$CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc",
        "disabled": False,
    }
}

refresh_token_jti_by_username: dict[str, str] = {}

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
    refresh_token_jti_by_username[username] = jti
    return _create_jwt(
        {"sub": username, "jti": jti},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "refresh",
    )

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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
    user = get_user(fake_users_db, username=token_data.username)
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
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.username, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(user.username)
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
async def register(request: Request, user: UserCreate) -> User:
    username = user.username.strip().lower()
    if len(username) < 3 or len(username) > 32 or not _USERNAME_RE.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid username. Must contain no spaces or special characters. Maximum length is 16.",
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
            detail="Invalid password. Must be at least 8 characters long, have at least one lowercase letter, one uppercase letter and one digit.",
        )

    full_name = (user.full_name or "").strip()
    if not full_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Full name is required.",
        )
    if " " not in full_name or len(full_name.split()) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid full name.",
        )

    email = None
    if user.email is not None:
        candidate_email = user.email.strip()
        if candidate_email:
            if len(candidate_email) > 254 or not _EMAIL_RE.fullmatch(candidate_email):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Invalid email.",
                )
            email = candidate_email

    if username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )
    user_dict = {
        "username": username,
        "full_name": full_name,
        "email": email,
        "hashed_password": get_password_hash(password),
        "disabled": False,
    }
    fake_users_db[username] = user_dict
    return User(
        username=user_dict["username"],
        email=user_dict.get("email"),
        full_name=user_dict.get("full_name"),
        disabled=user_dict.get("disabled"),
    )

#
#   REFRESH
#

class RefreshTokenRequest(BaseModel):
    refresh_token: str

@router.post("/refresh", response_model=Token)
@limiter.limit(RateLimitConfig.WRITE)
async def refresh_access_token(request: Request, body: RefreshTokenRequest) -> Token:
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
        if not jti or refresh_token_jti_by_username.get(username) != jti:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = get_user(fake_users_db, username=username)
    if user is None or user.disabled:
        raise credentials_exception

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(username, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(username)
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

#
#   DEBUG
#

@router.get("/users/me/", response_model=User)
async def profile(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@router.get("/users/me/items/")
async def my_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]