import jwt
from jwt.exceptions import InvalidTokenError

from app.config import ALGORITHM, SECRET_KEY


class JwtAuthError(Exception):
    pass


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except InvalidTokenError as exc:
        raise JwtAuthError() from exc

    token_type = payload.get("type")
    if token_type is not None and token_type != "access":
        raise JwtAuthError()

    if not payload.get("sub"):
        raise JwtAuthError()

    return payload
