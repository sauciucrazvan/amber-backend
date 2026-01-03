from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.models.user import User
from app.api.routes.auth.auth import get_current_active_user
from ..rate_limiter import limiter, RateLimitConfig

router = APIRouter(prefix="/test", tags=["test"])

@router.get("/")
@limiter.limit(RateLimitConfig.READ)
async def get(request: Request):
    return {
        "detail": "Hello world"
    }


@router.get("/protected")
async def protected(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return {
        "detail": "Hello world",
    }
