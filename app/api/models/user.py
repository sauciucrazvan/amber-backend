from datetime import datetime
from pydantic import BaseModel


class User(BaseModel):
    id: int
    username: str
    email: str | None = None
    full_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    disabled: bool | None = None
    verified: bool | None = None
    registered_at: datetime | None = None
    verified_at: datetime | None = None
    last_active_at: datetime | None = None

class UserPrivate(User):
    hashed_password: str