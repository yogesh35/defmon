"""DefMon WebSocket manager for live real-time dashboard updates."""

import asyncio
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

from defmon.api.auth import decode_access_token

ws_router = APIRouter(prefix="/ws", tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections for live feed."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accept connection and add to active list."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.debug(f"Client connected. Active connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        """Remove connection from active list."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.debug(f"Client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict[str, Any]):
        """Broadcast JSON message to all connected clients."""
        text = json.dumps(message)
        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(text)
                except Exception as e:
                    logger.warning(f"Error broadcasting to client: {e}")


manager = ConnectionManager()


@ws_router.websocket("/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert feed.
    Requires JWT token via query parameter: /api/ws/alerts?token=<jwt>.
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008, reason="Missing auth token")
        return

    try:
        decode_access_token(token)
    except Exception:
        await websocket.close(code=1008, reason="Invalid auth token")
        return

    await manager.connect(websocket)
    try:
        while True:
            # We primarily push data to the client, but we need to await receive
            # to detect when the client disconnects.
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)
