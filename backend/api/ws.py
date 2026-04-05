"""WebSocket endpoint for real-time alert streaming."""

import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from loguru import logger

router = APIRouter()

# Connected WebSocket clients
connected_clients: list[WebSocket] = []


@router.websocket("/alerts/live")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for live alert feed."""
    await websocket.accept()
    connected_clients.append(websocket)
    logger.info(f"WebSocket client connected. Total: {len(connected_clients)}")

    try:
        while True:
            # Keep connection alive, listen for client messages
            data = await websocket.receive_text()
            # Client can send filter preferences
            logger.debug(f"WS received: {data}")
    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(connected_clients)}")


async def broadcast_alert(alert_data: dict):
    """Broadcast a new alert to all connected WebSocket clients."""
    if not connected_clients:
        return

    message = json.dumps(alert_data)
    disconnected = []

    for client in connected_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        connected_clients.remove(client)
