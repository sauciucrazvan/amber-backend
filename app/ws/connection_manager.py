from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.utils.jwt import JwtAuthError, decode_access_token
from app.api.utils.user import get_user_by_username
from app.database.session import getSession

router = APIRouter(prefix="/ws", tags=["websockets"])

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[websocket] = username

    def disconnect(self, websocket: WebSocket):
        self.active_connections.pop(websocket, None)

    def get_connected_users(self) -> list[str]:
        return list(self.active_connections.values())

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()

def _extract_token(websocket: WebSocket) -> str | None:
    authorization = websocket.headers.get("authorization")
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token

    token = websocket.query_params.get("token")
    if token:
        return token

    return websocket.cookies.get("access_token")


def _authenticate_websocket(websocket: WebSocket) -> str | None:
    token = _extract_token(websocket)
    if not token:
        return None

    try:
        payload = decode_access_token(token)
    except JwtAuthError:
        return None

    username = payload.get("sub")
    db = getSession()
    try:
        user = get_user_by_username(db, username)
    finally:
        db.close()

    if user is None or user.disabled:
        return None

    return user.username

@router.websocket("/ping")
async def ws(websocket: WebSocket):
    username = _authenticate_websocket(websocket)
    if username is None:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, username)

    try:
        while True:
            await websocket.send_text(f"Pong, {username}!")
    except WebSocketDisconnect:
        manager.disconnect(websocket)