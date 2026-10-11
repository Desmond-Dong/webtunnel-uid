"""Channel TOML parsing, server grouping and the tunnel manager."""
from __future__ import annotations

import asyncio
import io
import logging
import tarfile
import tomllib
from dataclasses import dataclass, field

from homeassistant.core import HomeAssistant

from .api import WebTunnelCloudError, decrypt_channel_config
from .const import (STATE_DISABLED, STATE_ERROR, STATE_OK, STATE_REMOTE,
                    STATE_STARTING)
from .wtclient import ClientConfig, WtClient, ProxyConfig

_LOGGER = logging.getLogger(__name__)

_SSL_BUNDLE_URL_TMPL = "{base}/download/ssl/wt_ssl.tar.gz"


@dataclass
class Channel:
    """One WebTunnel channel (heartbeat record + parsed tunnel config)."""

    id: str
    name: str
    cloud_enabled: bool
    conn_type: str
    raw: dict
    error: str | None = None
    server_key: tuple | None = None
    proxies: list[ProxyConfig] = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    public_url: str = ""
    # 本机心跳发现的通道可由本机运行；控制台合并进来的通道属于其他主机，仅监控
    local: bool = True
    remote_host: str = ""

    @property
    def local_desc(self) -> str:
        if not self.local and not self.proxies:
            ip = str(self.raw.get("local_ip") or "")
            port = str(self.raw.get("local_port") or "")
            if ip or port:
                return f"{ip}:{port}" if port else ip
        return ", ".join(f"{p.local_ip}:{p.local_port}" for p in self.proxies) or "-"


@dataclass(frozen=True)
class ServerKey:
    server_addr: str
    server_port: int
    token: str
    transport: str
    tls_ca_file: str = ""
    tls_cert_file: str = ""
    tls_key_file: str = ""
    tls_server_name: str = ""

    def as_dict(self) -> dict:
        return {
            "server_addr": self.server_addr,
            "server_port": self.server_port,
            "transport": self.transport,
        }


def parse_channel(record: dict, storage_dir: str) -> Channel:
    """Decrypt + parse one heartbeat record into a Channel."""
    ch = Channel(
        id=str(record.get("id", "")),
        name=str(record.get("name", record.get("id", ""))),
        # official client: `const enable = rec.enable === 0` — 0 means the
        # channel should be running (server stores an inverted flag)
        cloud_enabled=record.get("enable") == 0,
        conn_type=str(record.get("conn_type") or record.get("proxy_type") or ""),
        raw=record,
    )
    if record.get("web_sld") and record.get("web_domain"):
        ch.public_url = "{}://{}.{}".format(
            record.get("web_protocol", "https"), record["web_sld"], record["web_domain"])
    encrypted = record.get("config_file")
    if not encrypted:
        ch.error = "heartbeat record has no config_file"
        return ch
    try:
        toml_text = decrypt_channel_config(encrypted)
    except (WebTunnelCloudError, ValueError) as err:
        ch.error = f"config decrypt failed: {err}"
        return ch

    # $WT_DIR$ placeholder -> per-integration storage dir (cert bundle home)
    toml_text = toml_text.replace("$WT_DIR$", storage_dir)

    try:
        data = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as err:
        ch.error = f"config parse failed: {err}"
        return ch

    transport_cfg = data.get("transport") or {}
    proto = str(transport_cfg.get("protocol", "tcp")).lower()
    tls_cfg = transport_cfg.get("tls") or {}
    tls_enable = bool(tls_cfg.get("enable", False))

    if proto == "quic":
        transport = "quic"
    elif proto in ("websocket", "wss"):
        ch.error = f"transport protocol '{proto}' is not supported by the integration"
        return ch
    else:
        transport = "tls" if tls_enable else "tcp"

    key = ServerKey(
        server_addr=str(data.get("serverAddr", "")),
        server_port=int(data.get("serverPort", 0)),
        token=str((data.get("auth") or {}).get("token", "")),
        transport=transport,
        tls_ca_file=str(tls_cfg.get("trustedCaFile", "")),
        tls_cert_file=str(tls_cfg.get("certFile", "")),
        tls_key_file=str(tls_cfg.get("keyFile", "")),
        tls_server_name=str(tls_cfg.get("serverName", "")),
    )
    if not key.server_addr or not key.server_port:
        ch.error = "config is missing serverAddr/serverPort"
        return ch

    proxies: list[ProxyConfig] = []
    for px in data.get("proxies") or []:
        ptype = str(px.get("type", "tcp")).lower()
        if ptype in ("stcp", "sudp", "xtcp", "udp"):
            ch.error = f"proxy type '{ptype}' is not supported by the integration yet"
            return ch
        # 服务端生成的配置将 useEncryption/useCompression 放在 per-proxy
        # 'transport' table (WebTunnel-generated TOML uses that form)
        px_transport = px.get("transport") or {}
        use_enc = bool(px.get("useEncryption", px_transport.get("useEncryption", False)))
        use_comp = bool(px.get("useCompression", px_transport.get("useCompression", False)))
        proxies.append(
            ProxyConfig(
                name=str(px.get("name", ch.id)),
                proxy_type=ptype if ptype in ("tcp", "http", "https") else "tcp",
                remote_port=int(px.get("remotePort", 0)),
                local_ip=str(px.get("localIP", "127.0.0.1")),
                local_port=int(px.get("localPort", 0)),
                custom_domains=list(px.get("customDomains", [])),
                subdomain=str(px.get("subdomain", "")),
                use_encryption=use_enc,
                use_compression=use_comp,
            )
        )
    if not proxies:
        ch.error = "config has no [[proxies]] entry"
        return ch

    ch.server_key = key
    ch.proxies = proxies
    ch.tls = {"transport": transport, "has_ca": bool(key.tls_ca_file),
              "has_client_cert": bool(key.tls_cert_file and key.tls_key_file)}
    return ch


def _ensure_certs(hass: HomeAssistant, channels: list[Channel], base_url: str) -> None:
    """Best-effort download of the wt_ssl bundle when a channel references
    cert files that do not exist yet (mirrors the official client)."""
    import os

    missing: list[str] = []
    for ch in channels:
        if ch.server_key is None:
            continue
        for path in (ch.server_key.tls_ca_file, ch.server_key.tls_cert_file,
                     ch.server_key.tls_key_file):
            if path and not os.path.isfile(path):
                missing.append(path)
    if not missing:
        return
    import httpx

    target_dir = os.path.dirname(missing[0]) or "."
    os.makedirs(target_dir, exist_ok=True)
    url = _SSL_BUNDLE_URL_TMPL.format(base=base_url.rstrip("/"))
    try:
        resp = httpx.get(url, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
            tar.extractall(target_dir, filter="data")
        _LOGGER.info("downloaded WebTunnel SSL bundle from %s into %s", url, target_dir)
    except Exception as err:  # noqa: BLE001 - best effort only
        _LOGGER.warning("could not fetch WebTunnel SSL bundle (%s): %s", url, err)


class TunnelManager:
    """按隧道服务端分组维护 WtClient，并与云端状态保持同步。"""

    def __init__(self, hass: HomeAssistant, uid: str):
        self.hass = hass
        self.uid = uid
        self._clients: dict[tuple, WtClient] = {}
        self._tasks: dict[tuple, asyncio.Task] = {}
        self._paused: set[str] = set()   # channel ids paused locally (runtime)
        self._last_channels: list[Channel] | None = None
        self._last_base_url: str = ''

    def set_paused(self, channel_id: str, paused: bool) -> None:
        if paused:
            self._paused.add(channel_id)
        else:
            self._paused.discard(channel_id)

    def is_paused(self, channel_id: str) -> bool:
        return channel_id in self._paused

    async def sync(self, channels: list[Channel], base_url: str) -> None:
        self._last_channels = channels
        self._last_base_url = base_url
        _ensure_certs(self.hass, channels, base_url)

        active = [ch for ch in channels if not ch.error and ch.cloud_enabled
                  and ch.id not in self._paused]
        if not active:
            _LOGGER.info("no active channels (heartbeat ok, %d records)", len(channels))

        groups: dict[tuple, list[Channel]] = {}
        for ch in channels:
            if ch.error or not ch.cloud_enabled or ch.id in self._paused:
                continue
            groups.setdefault(ch.server_key, []).append(ch)

        # stop clients for servers that no longer have active channels
        for key in list(self._clients):
            if key not in groups:
                client = self._clients.pop(key)
                client.stop()
                task = self._tasks.pop(key, None)
                if task:
                    task.cancel()
                _LOGGER.info("stopped tunnel client for %s:%s", key.server_addr, key.server_port)

        # spawn/sync the rest
        for key, chans in groups.items():
            client = self._clients.get(key)
            if client is None:
                cfg = ClientConfig(
                    server_addr=key.server_addr,
                    server_port=key.server_port,
                    token=key.token,
                    transport=key.transport,
                    tls_ca_file=key.tls_ca_file,
                    tls_cert_file=key.tls_cert_file,
                    tls_key_file=key.tls_key_file,
                    tls_server_name=key.tls_server_name,
                    heartbeat_interval=30.0,
                    heartbeat_timeout=90.0,
                )
                client = WtClient(cfg, [p for ch in chans for p in ch.proxies])
                self._clients[key] = client
                self._tasks[key] = asyncio.create_task(client.run())
                _LOGGER.info("started tunnel client for %s:%s (%s)",
                             key.server_addr, key.server_port, key.transport)
            proxies = [p for ch in chans for p in ch.proxies]
            await client.update_proxies(proxies)

    async def restart_channel(self, channel_id: str) -> None:
        """Force-restart the tunnel client serving one channel."""
        for key, chans in list(self._clients.items()):
            if any(ch.id == channel_id for ch in chans):
                client = self._clients.pop(key)
                client.stop()
                task = self._tasks.pop(key, None)
                if task:
                    task.cancel()
                _LOGGER.info('restarting tunnel client for %s:%s',
                             key.server_addr, key.server_port)
                break
        # rebuild from the last known channel set
        if self._last_channels is not None:
            await self.sync(self._last_channels, self._last_base_url)

    async def stop_all(self):
        for client in self._clients.values():
            client.stop()
        for task in self._tasks.values():
            task.cancel()
        self._clients.clear()
        self._tasks.clear()

    def server_summary(self) -> list[dict]:
        """One entry per active tunnel server (for the status sensor)."""
        out = []
        for key, client in self._clients.items():
            states = [s['state'] for s in client.proxy_status.values()]
            registered = sum(1 for s in states if s == 'registered')
            out.append({
                'server': f"{key.server_addr}:{key.server_port}",
                'transport': key.transport,
                'proxies_total': len(states),
                'proxies_registered': registered,
                'connected': bool(states) and registered == len(states),
            })
        return out

    def channel_state(self, ch: Channel) -> dict:
        """Runtime status dict for one channel (for entities)."""
        if not ch.local:
            return {"state": STATE_REMOTE, "error": "", "remote_host": ch.remote_host}
        if ch.error:
            return {"state": STATE_ERROR, "error": ch.error}
        if not ch.cloud_enabled:
            return {"state": STATE_DISABLED, "error": ""}
        if self.is_paused(ch.id):
            return {"state": "paused", "error": ""}
        names = {p.name for p in ch.proxies}
        if not ch.server_key or ch.server_key not in self._clients:
                        return {"state": STATE_STARTING, "error": ""}
        client = self._clients[ch.server_key]
        states = [client.proxy_status.get(n, {}).get("state", STATE_STARTING) for n in names]
        addrs = [client.proxy_status.get(n, {}).get("remote_addr", "") for n in names]
        errors = [client.proxy_status.get(n, {}).get("error", "") for n in names]
        state = STATE_OK if all(s == "registered" for s in states) else (
            STATE_ERROR if any(s == "error" for s in states) else STATE_STARTING)
        traffic_in = sum(client.traffic.get(n, {}).get('in', 0) for n in names)
        traffic_out = sum(client.traffic.get(n, {}).get('out', 0) for n in names)
        return {"state": state, "error": "; ".join(e for e in errors if e),
                "remote_addr": ", ".join(a for a in addrs if a),
                "traffic_in": traffic_in, "traffic_out": traffic_out}
