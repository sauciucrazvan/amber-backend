from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    password: str
    email: str | None = None
    full_name: str | None = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class Verify(BaseModel):
    verify_code: str
