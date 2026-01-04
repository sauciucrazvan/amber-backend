from datetime import datetime
from pydantic import BaseModel


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    registered_at: datetime | None = None

class UserPrivate(User):
    hashed_password: str