"""WebSocket — JWT-authenticated per-tenant live alert streaming."""
import asyncio, json
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import jwt, JWTError
from loguru import logger
from core.config import settings

router = APIRouter()


class TenantConnectionManager:
    def __init__(self):
        self._pools: dict[int, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, tenant_id: int):
        await ws.accept()
        self._pools.setdefault(tenant_id, []).append(ws)

    def disconnect(self, ws: WebSocket, tenant_id: int):
        pool = self._pools.get(tenant_id, [])
        if ws in pool:
            pool.remove(ws)

    async def broadcast(self, data: dict, tenant_id: int):
        pool = self._pools.get(tenant_id, [])
        if not pool:
            return
        message = json.dumps(data, default=str)
        dead = []
        for ws in pool:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, tenant_id)

    async def send(self, ws: WebSocket, data: dict):
        try:
            await ws.send_text(json.dumps(data, default=str))
        except Exception:
            pass


manager = TenantConnectionManager()


def _decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


@router.websocket("/alerts/live")
async def websocket_alerts(websocket: WebSocket, token: str = Query(None)):
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]
    if not token:
        await websocket.close(code=4401)
        return

    payload = _decode_token(token)
    if not payload:
        await websocket.close(code=4401)
        return

    tenant_id = payload.get("tenant_id")
    if tenant_id is None:
        # Super-admin: subscribe to all — use pool key 0
        tenant_id = 0

    await manager.connect(websocket, tenant_id)
    await manager.send(websocket, {
        "type": "connected",
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await manager.send(websocket, {"type": "pong"})
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                await manager.send(websocket, {
                    "type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
    except WebSocketDisconnect:
        manager.disconnect(websocket, tenant_id)
    except Exception as e:
        logger.debug(f"[WS] {e}")
        manager.disconnect(websocket, tenant_id)


async def broadcast_alert(alert_data: dict, tenant_id: int):
    payload = {
        "type": "new_alert",
        "alert": alert_data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await manager.broadcast(payload, tenant_id)
    # Super-admins on pool 0 see everything
    await manager.broadcast(payload, 0)
