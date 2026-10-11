"""DataUpdateCoordinator polling the WebTunnel cloud heartbeat."""
from __future__ import annotations

import datetime
import logging
import re
import socket
import time

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (WebTunnelAuthError, WebTunnelCloud, WebTunnelCloudError,
                  WebTunnelConsole)
from .const import CONF_UID, DEFAULT_SCAN_INTERVAL, DOMAIN
from .tunnel import Channel, parse_channel

_LOGGER = logging.getLogger(__name__)


class WebTunnelCoordinator(DataUpdateCoordinator[list[Channel]]):
    """Fetch channel records and parse them into Channel objects.

    The heartbeat only reports channels bound to this proxy host; for
    password-mode accounts the console's /port_mapping/all merges the rest of
    the account's channels in as monitor-only ("remote") entries.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, cloud: WebTunnelCloud):
        self.entry = entry
        self.cloud = cloud
        self.uid = entry.data.get(CONF_UID, "")
        # per-account dir for TLS bundles etc. ($WT_DIR$ in the tunnel TOML)
        safe_uid = re.sub(r"[^A-Za-z0-9_-]", "_", self.uid) or "account"
        self.storage_dir = hass.config.path("webtunnel", safe_uid)
        self.console: WebTunnelConsole | None = None
        # 原始控制台通道记录（uuid 为键），供子条目同步使用
        self.console_records: list[dict] = []
        self.last_sync_time = None
        self.last_latency_ms: float | None = None
        self.user_info: dict = {}
        self.monthly_traffic: dict = {}
        # official-client aligned, intentionally not configurable
        scan_interval = DEFAULT_SCAN_INTERVAL
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{self.uid}",
            update_interval=datetime.timedelta(seconds=scan_interval),
        )

    async def _async_update_data(self) -> list[Channel]:
        started = time.monotonic()
        try:
            records = await self.cloud.heartbeat(hostname=socket.gethostname())
        except WebTunnelAuthError as err:
            raise UpdateFailed(f"authentication failed: {err}") from err
        except WebTunnelCloudError as err:
            raise UpdateFailed(str(err)) from err
        except Exception as err:  # noqa: BLE001 - network layer
            raise UpdateFailed(f"heartbeat request failed: {err}") from err

        self.last_sync_time = datetime.datetime.now(datetime.timezone.utc)
        self.last_latency_ms = (time.monotonic() - started) * 1000
        channels: list[Channel] = []
        seen: set[str] = set()
        for record in records:
            ch = parse_channel(record, self.storage_dir)
            if ch.error:
                _LOGGER.warning("channel %s (%s): %s", ch.id, ch.name, ch.error)
            seen.add(ch.id)
            channels.append(ch)

        channels.extend(await self._async_remote_channels(seen))
        return channels

    async def _async_remote_channels(self, seen: set[str]) -> list[Channel]:
        """Merge account-wide channels bound to other hosts (monitor only)."""
        self.console_records = []
        if self.console is None or not self.console.token:
            return []
        try:
            records = await self.console.port_mapping_all()
        except Exception as err:  # noqa: BLE001 - surfaced loudly, next cycle retries
            self.console_records = []
            _LOGGER.warning("port_mapping/all failed (%s)——通道自动发现本轮跳过", err)
            return []
        self.console_records = list(records or [])
        _LOGGER.info("console reports %d channel(s) for this account",
                     len(self.console_records))
        remote: list[Channel] = []
        hostname = (socket.gethostname() or "homeassistant").lower()
        for record in records or []:
            channel_id = str(record.get("uuid") or record.get("id") or "")
            if not channel_id or channel_id in seen:
                continue
            proxy_host = str(record.get("proxy_hostname") or "")
            hosts = [h.strip().lower() for h in proxy_host.split(",") if h.strip()]
            record = dict(record)
            if hostname in hosts:
                # bound to this host but absent from the heartbeat (not started?)
                continue
            ch = Channel(
                id=channel_id,
                name=str(record.get("name") or channel_id),
                cloud_enabled=record.get("enable") == 0,
                conn_type=str(record.get("conn_type") or ""),
                raw=record,
                local=False,
                remote_host=proxy_host,
            )
            if record.get("web_sld") and record.get("web_domain"):
                ch.public_url = "{}://{}.{}".format(
                    str(record.get("web_protocol") or "https"),
                    record["web_sld"], record["web_domain"])
            remote.append(ch)
        if remote:
            _LOGGER.info("discovered %d account channel(s) running on other hosts",
                         len(remote))
        return remote
