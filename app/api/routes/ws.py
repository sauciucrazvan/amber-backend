from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.api.realtime import realtime
from app.api.utils.jwt import JwtAuthError, decode_access_token
from app.api.utils.user import get_user_db_row_by_username
from app.database.session import get_db

router = APIRouter(prefix="/ws", tags=["ws"])


def _extract_token(ws: WebSocket) -> str | None:
    token = ws.query_params.get("token")
    if token:
        return token

    authorization = ws.headers.get("authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()

    return None


async def _authenticate_ws(ws: WebSocket, db: Session):
    token = _extract_token(ws)
    if not token:
        await ws.close(code=4401)
        return None

    try:
        payload = decode_access_token(token)
    except JwtAuthError:
        await ws.close(code=4401)
        return None

    username = payload.get("sub")
    user_row = get_user_db_row_by_username(db, username)
    if user_row is None or user_row.disabled:
        await ws.close(code=4401)
        return None

    return user_row


@router.websocket("/presence")
async def ws_presence(websocket: WebSocket, db: Annotated[Session, Depends(get_db)]):
    user = await _authenticate_ws(websocket, db)
    if user is None:
        return

    await realtime.connect(user.id, websocket)
    try:
        while True:
            msg = await websocket.receive_json()
            t = msg.get("type")

            if t == "ping":
                await websocket.send_json({"type": "pong"})
            elif t == "subscribe":
                user_ids = msg.get("user_ids") or []
                statuses = await realtime.subscribe(websocket, user_ids)
                await websocket.send_json({"type": "snapshot", "statuses": statuses})
            else:
                await websocket.send_json({"type": "error", "error": "unknown_message_type"})
    except WebSocketDisconnect:
        pass
    finally:
        await realtime.disconnect(user.id, websocket)
