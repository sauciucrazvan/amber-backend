import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.utils.jwt import JwtAuthError, decode_access_token
from app.api.utils.user import get_user_by_username
from app.database.session import getSession

router = APIRouter(prefix="/ws", tags=["websockets"])

HEARTBEAT_TIMEOUT_SECONDS = 45

class ConnectionManager:
    def __init__(self):
        self.connections_by_user: dict[str, set[WebSocket]] = {}
        self.user_by_socket: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        if username not in self.connections_by_user:
            self.connections_by_user[username] = set()

        self.connections_by_user[username].add(websocket)
        self.user_by_socket[websocket] = username

    def disconnect(self, websocket: WebSocket):
        username = self.user_by_socket.pop(websocket, None)
        if username is None:
            return

        user_connections = self.connections_by_user.get(username)
        if user_connections is None:
            return

        user_connections.discard(websocket)
        if not user_connections:
            self.connections_by_user.pop(username, None)

    def get_connected_users(self) -> list[str]:
        return list(self.connections_by_user.keys())

    def is_user_online(self, username: str) -> bool:
        return username in self.connections_by_user

    async def broadcast(self, message: str):
        dead_connections: list[WebSocket] = []
        all_connections = [
            connection
            for user_connections in self.connections_by_user.values()
            for connection in user_connections
        ]

        for connection in all_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead_connections.append(connection)

        for connection in dead_connections:
            self.disconnect(connection)


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
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=HEARTBEAT_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                await websocket.close(code=1001, reason="Heartbeat timeout")
                break

            if message.strip().lower() in {"ping"}:
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)