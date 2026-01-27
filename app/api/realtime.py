import asyncio
from collections import defaultdict

from fastapi import WebSocket


class Realtime:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._sockets_by_user: dict[int, set[WebSocket]] = defaultdict(set)
        self._subs_by_socket: dict[WebSocket, set[int]] = defaultdict(set)

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            first = len(self._sockets_by_user[user_id]) == 0
            self._sockets_by_user[user_id].add(ws)
        if first:
            await self._broadcast_presence(user_id, online=True)

    async def disconnect(self, user_id: int, ws: WebSocket) -> None:
        async with self._lock:
            self._subs_by_socket.pop(ws, None)
            sockets = self._sockets_by_user.get(user_id)
            if sockets is None:
                last = False
            else:
                sockets.discard(ws)
                if not sockets:
                    self._sockets_by_user.pop(user_id, None)
                    last = True
                else:
                    last = False

        if last:
            await self._broadcast_presence(user_id, online=False)

    async def subscribe(self, ws: WebSocket, user_ids: list[int]) -> dict[int, bool]:
        async with self._lock:
            self._subs_by_socket[ws] = set(user_ids)
            return {user_id: (user_id in self._sockets_by_user) for user_id in user_ids}

    async def snapshot(self, user_ids: list[int]) -> dict[int, bool]:
        async with self._lock:
            return {user_id: (user_id in self._sockets_by_user) for user_id in user_ids}

    async def _broadcast_presence(self, user_id: int, online: bool) -> None:
        async with self._lock:
            targets = [ws for ws, subs in self._subs_by_socket.items() if user_id in subs]

        msg = {"type": "presence", "user_id": user_id, "online": online}
        for ws in targets:
            try:
                await ws.send_json(msg)
            except Exception:
                pass


realtime = Realtime()
