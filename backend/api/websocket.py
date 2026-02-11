"""WebSocket manager — broadcasts live events to all connected SOC dashboards."""
import asyncio
import json
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._connections.remove(ws)

    async def broadcast(self, data: dict):
        """Send a JSON message to every connected dashboard."""
        payload = json.dumps(data, default=str)
        dead = []
        async with self._lock:
            for ws in self._connections:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._connections.remove(ws)


ws_manager = ConnectionManager()
