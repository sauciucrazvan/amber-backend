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
        return (None, 4401)

    try:
        payload = decode_access_token(token)
    except JwtAuthError:
        return (None, 4401)

    username = payload.get("sub")
    user_row = get_user_db_row_by_username(db, username)
    if user_row is None:
        return (None, 4401)
    if user_row.disabled:
        return (None, 4403)

    return (user_row, None)


@router.websocket("/presence")
async def ws_presence(websocket: WebSocket, db: Annotated[Session, Depends(get_db)]):
    user, close_code = await _authenticate_ws(websocket, db)
    await websocket.accept()
    if user is None:
        await websocket.close(code=close_code or 4401)
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
