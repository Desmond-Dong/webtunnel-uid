"""WebSocket control channel (wss://…/ws) — the cloud's client-liveness signal.

Mirrors the official client (src/common/websocket_client.js):
  - connect: {ws|wss}://host/ws?uid=…&hostname=…
  - keepalive: websocket ping frame every 30s
  - server messages: JSON {type, timestamp, data}; 'heartbeat' triggers an
    immediate coordinator refresh, 'pong' ignored, mesh_*/update_check logged
  - reconnect with exponential backoff; code 1008 (kicked: logged in
    elsewhere) stops reconnecting like the official client
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from urllib.parse import quote

import aiohttp

_LOGGER = logging.getLogger(__name__)

PING_INTERVAL = 30.0


def ws_url_for(base_url: str, uid: str, hostname: str) -> str:
    http_url = base_url.rstrip("/")
    ws_base = ("wss://" + http_url[8:]) if http_url.startswith("https://") else (
        "ws://" + http_url[7:] if http_url.startswith("http://") else http_url)
    return f"{ws_base}/ws?uid={uid}&hostname={quote(hostname)}"


def normalize_hostname(hostname: str) -> str:
    """Official client's normalizeHostname: lowercase, strip .local, ASCII-safe."""
    host = (hostname or "").lower().split(".")[0].replace("-local", "")
    host = re.sub(r"[^a-z0-9\-]", "", host)
    return host or "homeassistant"


class WsControlClient:
    """Maintains the cloud control WebSocket."""

    def __init__(self, session: aiohttp.ClientSession, base_url: str, uid: str,
                 hostname: str, on_heartbeat_command):
        self._session = session
        self._url = ws_url_for(base_url, uid, hostname)
        self._on_heartbeat_command = on_heartbeat_command
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.connected = asyncio.Event()

    async def start(self):
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self):
        backoff = 1.0
        while not self._stop.is_set():
            try:
                await self._session_once()
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 - network layer
                _LOGGER.warning("control websocket error: %s", err)
            if self._stop.is_set():
                break
            _LOGGER.info("control websocket reconnecting in %.0fs", backoff)
            try:
                await asyncio.wait_for(self._stop.wait(), backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 60.0)

    async def _session_once(self):
        hostname = socket.gethostname() or "homeassistant"
        async with self._session.ws_connect(
                self._url, heartbeat=PING_INTERVAL, timeout=aiohttp.ClientWSTimeout(ws_close=10)) as ws:
            self.connected.set()
            _LOGGER.info("control websocket connected: %s", self._url.split('?')[0])
            ping_task = asyncio.create_task(self._ping_loop(ws))
            try:
                async for msg in ws:
                    if msg.type is aiohttp.WSMsgType.TEXT:
                        self._handle_message(msg.data)
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING,
                                      aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                        break
            finally:
                ping_task.cancel()
                self.connected.clear()
                _LOGGER.info("control websocket closed")

    async def _ping_loop(self, ws):
        while True:
            await asyncio.sleep(PING_INTERVAL)
            await ws.ping()
            _LOGGER.debug("control websocket ping sent")

    def _handle_message(self, raw: str):
        import json
        try:
            message = json.loads(raw)
        except ValueError:
            _LOGGER.debug("control websocket: non-JSON message ignored")
            return
        mtype = message.get("type")
        if mtype == "pong":
            return
        if mtype == "heartbeat":
            _LOGGER.info("control websocket: heartbeat command received")
            self._on_heartbeat_command()
            return
        if mtype and str(mtype).startswith("mesh_"):
            _LOGGER.debug("control websocket: mesh command %s ignored (not supported yet)", mtype)
            return
        _LOGGER.debug("control websocket: message type=%s ignored", mtype)
