"""WebTunnel binary sensors: control websocket + per-channel cloud/server state."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .types import (WebTunnelConfigEntry, basic_subentry_id,
                    channel_device_info, channel_subentry_id)


async def async_setup_entry(hass, entry: WebTunnelConfigEntry, async_add_entities):
    entities = [WebTunnelWsConnectedSensor(entry)]
    async_add_entities(entities, config_subentry_id=basic_subentry_id(entry))

    data = entry.runtime_data
    coordinator = data.coordinator
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
                WebTunnelCloudEnabledSensor(entry, ch.id),
                WebTunnelServerOnlineSensor(entry, ch.id),
            ]
            by_sub.setdefault(sub_id, []).extend(known[ch.id])
        for sub_id, ents in by_sub.items():
            async_add_entities(ents, config_subentry_id=sub_id)

    _check()
    entry.async_on_unload(coordinator.async_add_listener(_check))


class WebTunnelWsConnectedSensor(CoordinatorEntity, BinarySensorEntity):
    """Whether the cloud control websocket is connected (client liveness)."""

    _attr_translation_key = "ws_connected"
    _attr_has_entity_name = True
    _attr_should_poll = True
    _attr_icon = "mdi:websocket"

    def __init__(self, entry: WebTunnelConfigEntry):
        super().__init__(entry.runtime_data.coordinator)
        self._entry = entry
        self._attr_device_info = DeviceInfo(
            identifiers={(entry.domain, entry.entry_id)},
            translation_key="account_basic",
            manufacturer="WebTunnel",
            model="WebTunnel",
        )

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-ws-connected"

    @property
    def is_on(self) -> bool | None:
        ws = self._entry.runtime_data.ws
        return ws.connected.is_set() if ws else None


class _WebTunnelBinaryBase(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: WebTunnelConfigEntry, channel_id: str):
        super().__init__(entry.runtime_data.coordinator)
        self._entry = entry
        self._channel_id = channel_id
        self._attr_device_info = channel_device_info(entry, channel_id)
        ch = next((c for c in entry.runtime_data.coordinator.data or []
                   if c.id == channel_id), None)
        self._attr_translation_placeholders = {
            "name": ch.name if ch and ch.name else channel_id}

    @property
    def channel(self):
        for ch in self.coordinator.data or []:
            if ch.id == self._channel_id:
                return ch
        return None

    @property
    def available(self) -> bool:
        return self.channel is not None and self.coordinator.last_update_success


class WebTunnelCloudEnabledSensor(_WebTunnelBinaryBase):
    """Whether the channel is enabled on the cloud side."""

    _attr_translation_key = "cloud_enabled"
    _attr_icon = "mdi:toggle-switch-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-cloud-enabled"

    @property
    def is_on(self) -> bool | None:
        ch = self.channel
        return ch.cloud_enabled if ch else None


class WebTunnelServerOnlineSensor(_WebTunnelBinaryBase):
    """Whether the tunnel server reports this channel online."""

    _attr_translation_key = "server_online"
    _attr_icon = "mdi:server"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-{self._channel_id}-server-online"

    @property
    def is_on(self) -> bool | None:
        ch = self.channel
        if ch is None:
            return None
        return bool(ch.raw.get("serv_online"))
