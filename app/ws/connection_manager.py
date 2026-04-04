import asyncio
import json
import logging
from typing import Any, Iterable

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import or_

from app.api.utils.jwt import JwtAuthError, decode_access_token
from app.api.utils.user import get_user_by_username
from app.database.models.relationship import Relationship
from app.database.models.user import UserDB
from app.database.session import getSession
from app.ws.call_signaling import handle_signaling_message, handle_user_disconnected

router = APIRouter(prefix="/ws", tags=["websockets"])

HEARTBEAT_TIMEOUT_SECONDS = 45

logger = logging.getLogger(__name__)


def _get_client_ip(websocket: WebSocket) -> str:
    forwarded_for = websocket.headers.get("x-forwarded-for", "").split(",")[0].strip()
    real_ip = websocket.headers.get("x-real-ip", "").strip()
    host = websocket.client.host if websocket.client and websocket.client.host else ""
    return forwarded_for or real_ip or host or "unknown"


def _get_client_user_agent(websocket: WebSocket) -> str:
    return websocket.headers.get("user-agent", "unknown")


def _get_session_id(websocket: WebSocket) -> str:
    return websocket.query_params.get("session_id") or websocket.headers.get("x-amber-session-id") or ""

class ConnectionManager:
    def __init__(self):
        self.connections_by_user: dict[str, set[WebSocket]] = {}
        self.user_by_socket: dict[WebSocket, str] = {}
        self.session_by_socket: dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str) -> bool:
        client_ip = _get_client_ip(websocket)
        session_id = _get_session_id(websocket)
        became_online = username not in self.connections_by_user
        await websocket.accept()

        user_connections = self.connections_by_user.setdefault(username, set())

        existing_connections = list(user_connections)
        for connection in existing_connections:
            if not session_id:
                continue

            if self.session_by_socket.get(connection) != session_id:
                continue

            user_connections.discard(connection)
            self.user_by_socket.pop(connection, None)
            self.session_by_socket.pop(connection, None)

            try:
                await connection.close(code=1000, reason="Replaced by same-session reconnect")
            except Exception:
                pass

        user_connections.add(websocket)
        self.user_by_socket[websocket] = username
        self.session_by_socket[websocket] = session_id

        logger.info(
            "ws_connect user=%s ip=%s session_id=%s ua=%s connections=%d became_online=%s",
            username,
            client_ip,
            session_id or "unknown",
            _get_client_user_agent(websocket),
            len(user_connections),
            became_online,
        )
        return became_online

    def disconnect(self, websocket: WebSocket) -> tuple[str | None, bool]:
        username = self.user_by_socket.pop(websocket, None)
        self.session_by_socket.pop(websocket, None)
        if username is None:
            return None, False

        user_connections = self.connections_by_user.get(username)
        if user_connections is None:
            return username, False

        user_connections.discard(websocket)
        became_offline = False
        if not user_connections:
            self.connections_by_user.pop(username, None)
            became_offline = True

        logger.info(
            "ws_disconnect user=%s ip=%s session_id=%s remaining_connections=%d became_offline=%s",
            username,
            _get_client_ip(websocket),
            _get_session_id(websocket) or "unknown",
            len(user_connections),
            became_offline,
        )

        return username, became_offline

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

    async def send_json_to_username(self, username: str, payload: dict[str, Any]):
        user_connections = self.connections_by_user.get(username)
        if not user_connections:
            return

        dead_connections: list[WebSocket] = []
        for connection in list(user_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.append(connection)

        for connection in dead_connections:
            self.disconnect(connection)

    async def send_json_to_username_except(
        self,
        username: str,
        payload: dict[str, Any],
        excluded_websocket: WebSocket,
    ):
        user_connections = self.connections_by_user.get(username)
        if not user_connections:
            return

        dead_connections: list[WebSocket] = []
        for connection in list(user_connections):
            if connection == excluded_websocket:
                continue

            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.append(connection)

        for connection in dead_connections:
            self.disconnect(connection)

    async def send_json_to_usernames(self, usernames: Iterable[str], payload: dict[str, Any]):
        for username in set(usernames):
            await self.send_json_to_username(username, payload)


manager = ConnectionManager()


def _get_connected_contact_usernames(username: str) -> list[str]:
    connected_usernames = set(manager.get_connected_users())
    if not connected_usernames:
        return []

    db = getSession()
    try:
        me = get_user_by_username(db, username)
        if me is None:
            return []

        rows = (
            db.query(UserDB.username)
            .join(
                Relationship,
                or_(
                    Relationship.other_user_id == UserDB.id,
                    Relationship.user_id == UserDB.id,
                ),
            )
            .filter(Relationship.relation == "contact")
            .filter(
                or_(
                    (Relationship.user_id == me.id) & (Relationship.other_user_id == UserDB.id),
                    (Relationship.other_user_id == me.id) & (Relationship.user_id == UserDB.id),
                )
            )
            .all()
        )
    finally:
        db.close()

    return [contact_username for (contact_username,) in rows if contact_username in connected_usernames]


async def _notify_contact_presence(username: str, online: bool):
    recipients = _get_connected_contact_usernames(username)
    if not recipients:
        return

    await manager.send_json_to_usernames(
        recipients,
        {
            "type": "presence",
            "event": "user_connected" if online else "user_disconnected",
            "username": username,
            "online": online,
        },
    )

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

    became_online = await manager.connect(websocket, username)
    if became_online:
        await _notify_contact_presence(username, online=True)

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
                continue

            try:
                payload = json.loads(message)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {
                        "type": "error",
                        "code": "signal.invalid_json",
                        "message": "Invalid websocket JSON payload",
                    }
                )
                continue

            if not isinstance(payload, dict):
                await websocket.send_json(
                    {
                        "type": "error",
                        "code": "signal.invalid_payload",
                        "message": "Websocket payload must be a JSON object",
                    }
                )
                continue

            try:
                await handle_signaling_message(
                    websocket=websocket,
                    manager=manager,
                    sender_username=username,
                    message=payload,
                )
            except Exception:
                await websocket.send_json(
                    {
                        "type": "error",
                        "code": "signal.internal_error",
                        "message": "Failed to process signaling event",
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        disconnected_username, became_offline = manager.disconnect(websocket)
        if disconnected_username and became_offline:
            await handle_user_disconnected(manager, disconnected_username)
            await _notify_contact_presence(disconnected_username, online=False)
