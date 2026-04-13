"""WebSocket — per-tenant live alert streaming."""
import asyncio, json
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from loguru import logger

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
        if not pool: return
        message = json.dumps(data, default=str)
        dead = []
        for ws in pool:
            try: await ws.send_text(message)
            except: dead.append(ws)
        for ws in dead: self.disconnect(ws, tenant_id)

    async def send(self, ws: WebSocket, data: dict):
        try: await ws.send_text(json.dumps(data, default=str))
        except: pass

manager = TenantConnectionManager()

@router.websocket("/alerts/live")
async def websocket_alerts(websocket: WebSocket, tenant_id: int = Query(...)):
    await manager.connect(websocket, tenant_id)
    await manager.send(websocket, {"type": "connected", "tenant_id": tenant_id,
                                    "timestamp": datetime.now(timezone.utc).isoformat()})
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await manager.send(websocket, {"type": "pong"})
            except asyncio.TimeoutError:
                await manager.send(websocket, {"type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat()})
            except: pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, tenant_id)

async def broadcast_alert(alert_data: dict, tenant_id: int):
    await manager.broadcast({"type": "new_alert", "alert": alert_data,
                               "timestamp": datetime.now(timezone.utc).isoformat()}, tenant_id)
