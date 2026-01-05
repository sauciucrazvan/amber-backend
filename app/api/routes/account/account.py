from typing import Annotated
from fastapi import APIRouter, Depends

from app.api.models.user import User
from app.api.routes.auth.auth import get_current_active_user


router = APIRouter(prefix="/account", tags=["account"])

@router.get("/me", response_model=User)
async def profile(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user