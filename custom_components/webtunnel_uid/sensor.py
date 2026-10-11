"""WebTunnel entities: always-present account basics + per-channel sensors."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    OFFICIAL_VERSION,
    STATE_DISABLED,
    STATE_ERROR,
    STATE_OK,
    STATE_PAUSED,
    STATE_REMOTE,
    STATE_STARTING,
    STATE_UNSUPPORTED,
)
from .tunnel import Channel
from .types import (WebTunnelConfigEntry, basic_subentry_id,
                    channel_device_info, channel_subentry_id)

_LOGGER = logging.getLogger(__name__)

_defer_logged: set[str] = set()

CHANNEL_STATES = [STATE_OK, STATE_STARTING, STATE_ERROR,
                  STATE_DISABLED, STATE_PAUSED, STATE_UNSUPPORTED, STATE_REMOTE]


async def async_setup_entry(hass, entry: WebTunnelConfigEntry, async_add_entities):
    data = entry.runtime_data
    coordinator = data.coordinator

    # 账号级实体共用账号设备，归属“基础信息”子条目；
    # 通道实体不带设备，直接归属各自的通道子条目
    account_sub = basic_subentry_id(entry)
    basics = [
        WebTunnelStatusSensor(entry),
        WebTunnelChannelCountSensor(entry),
        WebTunnelActiveChannelSensor(entry),
        WebTunnelLastHeartbeatSensor(entry),
        WebTunnelHeartbeatLatencySensor(entry),
        WebTunnelServerSensor(entry),
        WebTunnelVersionSensor(entry),
        WebTunnelUserSensor(entry),
        WebTunnelMonthlyTrafficSensor(entry, 'in', 'monthly_traffic_down'),
        WebTunnelMonthlyTrafficSensor(entry, 'out', 'monthly_traffic_up'),
    ]
    async_add_entities(basics, config_subentry_id=account_sub)

    known: dict[str, list] = {}

    def _check():
        by_sub: dict[str | None, list] = {}
        for ch in coordinator.data or []:
            if ch.id in known:
                continue
            # 控制台可用时等子条目同步建好再添加，实体才能归到通道子条目下
            sub_id = channel_subentry_id(entry, ch)
            if sub_id is None and data.console is not None and data.console.token:
                if ch.id not in _defer_logged:
                    _defer_logged.add(ch.id)
                    _LOGGER.info(
                        "channel %s (%s): no matching channel subentry yet, "
                        "entities deferred", ch.id, ch.name)
                continue
            known[ch.id] = [
                WebTunnelChannelStatusSensor(entry, ch.id),
                WebTunnelChannelPublicUrlSensor(entry, ch.id),
                WebTunnelChannelLocalTargetSensor(entry, ch.id),
                WebTunnelChannelTransportSensor(entry, ch.id),
                WebTunnelChannelRemotePortSensor(entry, ch.id),
                WebTunnelChannelTypeSensor(entry, ch.id),
                WebTunnelChannelDownSensor(entry, ch.id),
                WebTunnelChannelUpSensor(entry, ch.id),
            ]
            by_sub.setdefault(sub_id, []).extend(known[ch.id])
        for sub_id, ents in by_sub.items():
            async_add_entities(ents, config_subentry_id=sub_id)

    _check()
    entry.async_on_unload(coordinator.async_add_listener(_check))


class _WebTunnelEntity(CoordinatorEntity, SensorEntity):
    """Base: device grouping + coordinator updates (account-level device)."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: WebTunnelConfigEntry):
        super().__init__(entry.runtime_data.coordinator)
        self._entry = entry
        # 账号级设备：配置页里作为“基础信息”分组显示
        self._attr_device_info = DeviceInfo(
            identifiers={(entry.domain, entry.entry_id)},
            translation_key="account_basic",
            manufacturer="WebTunnel",
            model="WebTunnel",
        )

    @property
    def channel(self) -> Channel | None:
        for ch in self.coordinator.data or []:
            if ch.id == self._channel_id:
                return ch
        return None


class _WebTunnelChannelEntity(_WebTunnelEntity):
    """Base for per-channel entities: shared account device + name placeholder."""

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry)
        self._channel_id = channel_id
        ch = next((c for c in entry.runtime_data.coordinator.data or []
                   if c.id == channel_id), None)
        self._attr_translation_placeholders = {
            "name": ch.name if ch and ch.name else channel_id}

    @property
    def device_info(self) -> DeviceInfo:
        return channel_device_info(self._entry, self._channel_id)


class WebTunnelStatusSensor(_WebTunnelEntity):
    """Hub status: online / partial / offline (always present)."""

    _attr_translation_key = "status"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["online", "partial", "offline"]
    _attr_icon = "mdi:cloud-check-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-status"

    @property
    def native_value(self) -> str | None:
        if not self.coordinator.last_update_success:
            return "offline"
        manager = self._entry.runtime_data.manager
        for ch in self.coordinator.data or []:
            if manager.channel_state(ch)["state"] in (STATE_ERROR, STATE_UNSUPPORTED):
                return "partial"
        return "online"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self._entry.runtime_data
        channels = self.coordinator.data or []
        return {
            "uid": self._entry.data.get("uid", ""),
            "cloud": self._entry.data.get("base_url", ""),
            "channel_total": len(channels),
            "channel_active": sum(1 for ch in channels
                                  if data.manager.channel_state(ch)["state"] == STATE_OK),
            "servers": data.manager.server_summary(),
            "last_sync": self.coordinator.last_sync_time.isoformat()
            if self.coordinator.last_sync_time else None,
        }


class WebTunnelChannelCountSensor(_WebTunnelEntity):
    """Number of channels reported by the cloud (always present)."""

    _attr_translation_key = "channel_count"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:counter"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-channel-count"

    @property
    def native_value(self) -> int | None:
        if not self.coordinator.last_update_success:
            return None
        return len(self.coordinator.data or [])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        manager = self._entry.runtime_data.manager
        channels = self.coordinator.data or []
        return {
            "channels": [
                {
                    "name": ch.name,
                    "type": ch.conn_type,
                    "state": manager.channel_state(ch)["state"],
                    "public_url": ch.public_url or None,
                }
                for ch in channels
            ],
        }


class WebTunnelLastHeartbeatSensor(_WebTunnelEntity):
    """Time of the last successful cloud heartbeat."""

    _attr_translation_key = "last_heartbeat"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:clock-check-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-last-heartbeat"

    @property
    def native_value(self):
        return self.coordinator.last_sync_time


class WebTunnelActiveChannelSensor(_WebTunnelEntity):
    """Number of channels currently serving traffic."""

    _attr_translation_key = "active_channels"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:lan-check"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-active-channels"

    @property
    def native_value(self) -> int | None:
        if not self.coordinator.last_update_success:
            return None
        manager = self._entry.runtime_data.manager
        return sum(1 for ch in self.coordinator.data or []
                   if manager.channel_state(ch)["state"] == STATE_OK)


class WebTunnelHeartbeatLatencySensor(_WebTunnelEntity):
    """Round-trip time of the last cloud heartbeat."""

    _attr_translation_key = "heartbeat_latency"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "ms"
    _attr_suggested_display_precision = 0
    _attr_icon = "mdi:speedometer"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-heartbeat-latency"

    @property
    def native_value(self) -> int | None:
        latency = self.coordinator.last_latency_ms
        return round(latency) if latency is not None else None


class WebTunnelServerSensor(_WebTunnelEntity):
    """Tunnel servers this client is connected to."""

    _attr_translation_key = "tunnel_servers"
    _attr_icon = "mdi:server-network-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-servers"

    @property
    def native_value(self) -> int | None:
        return len(self._entry.runtime_data.manager.server_summary())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"servers": self._entry.runtime_data.manager.server_summary()}


class WebTunnelUserSensor(_WebTunnelEntity):
    """Account the integration is running for (console profile when available)."""

    _attr_translation_key = "user"
    _attr_icon = "mdi:account-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-user"

    @property
    def native_value(self) -> str:
        info = getattr(self.coordinator, "user_info", None) or {}
        nickname = info.get("nickname")
        if nickname:
            return nickname
        data = self._entry.data
        return data.get("username") or data.get("uid", "")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self._entry.data
        info = getattr(self.coordinator, "user_info", None) or {}
        attrs = {
            "uid": data.get("uid", ""),
            "login_mode": data.get("mode", ""),
            "cloud": data.get("base_url", ""),
            "version": OFFICIAL_VERSION,
        }
        for key in ("nickname", "telephone", "email", "reg_time"):
            if info.get(key):
                attrs[key] = info[key]
        return attrs


class WebTunnelMonthlyTrafficSensor(_WebTunnelEntity):
    """Monthly tunnel traffic reported by the cloud (inflow or outflow).

    HA has no bit-based data-size unit, so the native unit is a plain "Mb"
    (megabits, bytes * 8); without a device class the UI cannot auto-convert.
    """

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = "Mb"
    _attr_suggested_display_precision = 2

    def __init__(self, entry: WebTunnelConfigEntry, direction: str, key: str):
        super().__init__(entry)
        self._entry = entry
        self._direction = direction
        self._attr_translation_key = key
        self._attr_icon = "mdi:download" if direction == "in" else "mdi:upload"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-monthly-{self._direction}"

    @property
    def native_value(self) -> float | None:
        traffic = getattr(self.coordinator, "monthly_traffic", None)
        if not traffic:
            return 0.0
        series = traffic.get("inflow" if self._direction == "in" else "outflow") or []
        try:
            total_bytes = sum(int(v) for v in series)
        except (TypeError, ValueError):
            return None
        return round(total_bytes * 8 / 1_000_000, 2)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        traffic = getattr(self.coordinator, "monthly_traffic", None) or {}
        return {"daily_dates": traffic.get("date") or []}


class WebTunnelChannelTrafficBase(_WebTunnelChannelEntity):
    """Base for per-channel traffic counters (bytes via the tunnel)."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    def _traffic(self) -> tuple[int, int] | None:
        manager = self._entry.runtime_data.manager
        ch = self.channel
        if ch is None:
            return None
        status = manager.channel_state(ch)
        return status.get("traffic_in", 0), status.get("traffic_out", 0)


class WebTunnelChannelDownSensor(WebTunnelChannelTrafficBase):
    """Data received through this channel (visitor -> local service), in Mbit."""

    _attr_translation_key = "traffic_down"
    _attr_native_unit_of_measurement = "Mb"
    _attr_suggested_display_precision = 2
    _attr_icon = "mdi:download"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-down"

    @property
    def native_value(self) -> float | None:
        t = self._traffic()
        return round(t[0] * 8 / 1_000_000, 2) if t else None


class WebTunnelChannelUpSensor(WebTunnelChannelTrafficBase):
    """Data sent through this channel (local service -> visitor), in Mbit."""

    _attr_translation_key = "traffic_up"
    _attr_native_unit_of_measurement = "Mb"
    _attr_suggested_display_precision = 2
    _attr_icon = "mdi:upload"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-up"

    @property
    def native_value(self) -> float | None:
        t = self._traffic()
        return round(t[1] * 8 / 1_000_000, 2) if t else None


class WebTunnelVersionSensor(_WebTunnelEntity):
    """Reported client version (aligned with the official client)."""

    _attr_translation_key = "version"
    _attr_icon = "mdi:tag-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-version"

    @property
    def native_value(self) -> str:
        return OFFICIAL_VERSION


class WebTunnelChannelStatusSensor(_WebTunnelChannelEntity):
    """Per-channel status (appears when the cloud reports the channel)."""

    _attr_translation_key = "channel_status"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = CHANNEL_STATES
    _attr_icon = "mdi:lan-connect"

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-status"

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    @property
    def native_value(self) -> str | None:
        manager = self._entry.runtime_data.manager
        ch = self.channel
        if ch is None:
            return None
        return manager.channel_state(ch)["state"]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self._entry.runtime_data
        manager = data.manager
        ch = self.channel
        if ch is None:
            return {}
        status = manager.channel_state(ch)
        attrs: dict[str, Any] = {
            "channel_type": ch.conn_type,
            "local_target": ch.local_desc,
            "use_encryption": any(p.use_encryption for p in ch.proxies),
            "use_compression": any(p.use_compression for p in ch.proxies),
            "error": status.get("error", ""),
        }
        if not ch.local:
            attrs["running_host"] = ch.remote_host
        if ch.server_key:
            attrs["transport"] = ch.server_key.transport
            attrs["server"] = f"{ch.server_key.server_addr}:{ch.server_key.server_port}"
        if status.get("remote_addr"):
            attrs["remote_address"] = status["remote_addr"]
        return attrs

    @property
    def icon(self) -> str:
        return "mdi:lan-connect" if self.native_value == STATE_OK else "mdi:lan-disconnect"


class WebTunnelChannelLocalTargetSensor(_WebTunnelChannelEntity):
    """Local address this channel forwards to."""

    _attr_translation_key = "local_target"
    _attr_icon = "mdi:server-network"

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-local"

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    @property
    def native_value(self) -> str | None:
        ch = self.channel
        return ch.local_desc if ch else None


class WebTunnelChannelRemotePortSensor(_WebTunnelChannelEntity):
    """Public remote port assigned on the tunnel server (tcp/udp only)."""

    _attr_translation_key = "remote_port"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:ethernet"

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-remote-port"

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    @property
    def native_value(self) -> int | None:
        ch = self.channel
        if ch is None:
            return None
        for p in ch.proxies:
            if p.remote_port:
                return p.remote_port
        return None


class WebTunnelChannelTypeSensor(_WebTunnelChannelEntity):
    """Channel type reported by the cloud (web / tcp / ...)."""

    _attr_translation_key = "channel_type"
    _attr_icon = "mdi:shape-outline"

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-type"

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    @property
    def native_value(self) -> str | None:
        ch = self.channel
        return ch.conn_type or None if ch else None


class WebTunnelChannelTransportSensor(_WebTunnelChannelEntity):
    """到隧道服务端的传输方式（quic/tcp/tls）。"""

    _attr_translation_key = "transport"
    _attr_icon = "mdi:swap-horizontal"

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-transport"

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    @property
    def native_value(self) -> str | None:
        ch = self.channel
        if ch is None or ch.server_key is None:
            return None
        return ch.server_key.transport

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        ch = self.channel
        if ch is None:
            return {}
        return {
            "use_encryption": any(p.use_encryption for p in ch.proxies),
            "use_compression": any(p.use_compression for p in ch.proxies),
            "tunnel_server": f"{ch.server_key.server_addr}:{ch.server_key.server_port}"
            if ch.server_key else None,
        }


class WebTunnelChannelPublicUrlSensor(_WebTunnelChannelEntity):
    """Public address used to reach this channel from outside."""

    _attr_translation_key = "public_url"
    _attr_icon = "mdi:earth"

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry, channel_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-url"

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success

    @property
    def native_value(self) -> str | None:
        manager = self._entry.runtime_data.manager
        ch = self.channel
        if ch is None:
            return None
        if ch.public_url:
            return ch.public_url
        status = manager.channel_state(ch)
        return status.get("remote_addr") or None
