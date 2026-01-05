from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.api.models.user import UserPrivate
from app.database.models import UserDB

from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return password_hash.hash(password)



def get_user_by_username(db: Session, username: str | None) -> UserPrivate | None:
    if not username:
        return None
    row = db.query(UserDB).filter(UserDB.username == username).one_or_none()
    if row is None:
        return None
    return UserPrivate(
        username=row.username, # type: ignore
        email=row.email, # type: ignore
        full_name=row.full_name, # type: ignore
        disabled=row.disabled, # type: ignore
        registered_at=row.registered_at, # type: ignore
        hashed_password=row.hashed_password, # type: ignore
    )

def get_user_db_row_by_username(db: Session, username: str | None) -> UserDB | None:
    if not username:
        return None
    return db.query(UserDB).filter(UserDB.username == username).one_or_none()


def get_user_db_row_by_email(db: Session, email: str | None) -> UserDB | None:
    if not email:
        return None
    return db.query(UserDB).filter(UserDB.email == email).one_or_none()



def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    full_name: str,
    email: str | None,
) -> UserPrivate:
    row = UserDB(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=get_password_hash(password),
        disabled=False,
        registered_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return UserPrivate(
        username=row.username, # type: ignore
        email=row.email, # type: ignore
        full_name=row.full_name, # type: ignore
        disabled=row.disabled, # type: ignore
        registered_at=row.registered_at, # type: ignore
        hashed_password=row.hashed_password, # type: ignore
    )

def authenticate_user(db: Session, username: str, password: str) -> UserPrivate | None:
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user
