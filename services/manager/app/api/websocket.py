"""CyberNest — WebSocket handler for real-time alert streaming via Redis Pub/Sub."""

import asyncio
import orjson

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError, jwt
import structlog

from app.core.config import get_settings
from app.core.redis import redis_client

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()

# Redis pub/sub channel
ALERTS_CHANNEL = "cybernest:alerts:live"
EVENTS_CHANNEL = "cybernest:events:live"


@router.websocket("/ws/alerts/live")
async def alerts_live(ws: WebSocket, token: str | None = Query(None)):
    """Real-time alert stream. Authenticates via query param token."""
    # Authenticate
    if token:
        try:
            jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        except JWTError:
            await ws.close(code=4001, reason="Invalid token")
            return

    await ws.accept()
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(ALERTS_CHANNEL)

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                await ws.send_text(message["data"])

            # Also check for client disconnect
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=0.01)
                # Client can send filter preferences
                if data:
                    logger.debug("WS client filter", data=data)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
    finally:
        await pubsub.unsubscribe(ALERTS_CHANNEL)
        await pubsub.aclose()


@router.websocket("/ws/events/live")
async def events_live(ws: WebSocket, token: str | None = Query(None)):
    """Real-time event stream for live log viewer."""
    if token:
        try:
            jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        except JWTError:
            await ws.close(code=4001, reason="Invalid token")
            return

    await ws.accept()
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(EVENTS_CHANNEL)

    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                await ws.send_text(message["data"])
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=0.01)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
    finally:
        await pubsub.unsubscribe(EVENTS_CHANNEL)
        await pubsub.aclose()


async def broadcast_alert(alert_data: dict):
    """Publish alert to Redis for all WebSocket clients."""
    await redis_client.publish(ALERTS_CHANNEL, orjson.dumps(alert_data).decode())


async def broadcast_event(event_data: dict):
    """Publish event to Redis for live event viewers."""
    await redis_client.publish(EVENTS_CHANNEL, orjson.dumps(event_data).decode())
