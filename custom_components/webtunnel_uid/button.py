"""Per-account button to force-rebuild all tunnel clients."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.helpers.device_registry import DeviceInfo

from .types import WebTunnelConfigEntry, basic_subentry_id


async def async_setup_entry(hass, entry: WebTunnelConfigEntry, async_add_entities):
    # 与其他账号级实体一致：设备必须挂到“基础信息”子条目，
    # 否则设备注册表会在重载时把设备拽出子条目（同一设备多处注册以最后为准）
    async_add_entities([WebTunnelReconnectButton(entry)],
                       config_subentry_id=basic_subentry_id(entry))


class WebTunnelReconnectButton(ButtonEntity):
    """Reconnect every tunnel client (drop and rebuild connections)."""

    _attr_translation_key = "reconnect"
    _attr_has_entity_name = True
    _attr_icon = "mdi:reload"

    def __init__(self, entry: WebTunnelConfigEntry):
        self._entry = entry
        self._attr_device_info = DeviceInfo(
            identifiers={(entry.domain, entry.entry_id)},
            translation_key="account_basic",
            manufacturer="WebTunnel",
            model="WebTunnel",
        )

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}-reconnect"

    @property
    def available(self) -> bool:
        return self._entry.runtime_data is not None

    async def async_press(self):
        data = self._entry.runtime_data
        await data.manager.stop_all()
        await data.manager.sync(data.coordinator.data or [], data.cloud.base_url)
