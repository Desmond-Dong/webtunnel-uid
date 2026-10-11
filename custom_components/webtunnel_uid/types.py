"""Shared types for the WebTunnel integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo

from .api import WebTunnelCloud, WebTunnelConsole
from .coordinator import WebTunnelCoordinator
from .tunnel import Channel, TunnelManager
from .wscontrol import WsControlClient

from .const import (CONF_CHANNEL_ID, DOMAIN, SUBENTRY_TYPE_BASIC,
                    SUBENTRY_TYPE_CHANNEL)


@dataclass
class WebTunnelData:
    """Runtime data bound to a config entry (one account)."""

    cloud: WebTunnelCloud
    coordinator: WebTunnelCoordinator
    manager: TunnelManager
    ws: WsControlClient
    console: WebTunnelConsole | None = None


type WebTunnelConfigEntry = ConfigEntry[WebTunnelData]


def channel_subentry_id(entry: WebTunnelConfigEntry, channel: Channel) -> str | None:
    """Subentry id mirroring this channel (None when not mirrored yet).

    心跳记录、控制台记录、创建通道响应三处的通道标识字段不一致
    （id / uuid），这里取多候选互 match，并用控制台记录做 id<->uuid 桥接。
    """
    raw = channel.raw or {}
    candidates = {str(channel.id or ""), str(raw.get("uuid") or ""),
                  str(raw.get("id") or "")} - {""}
    # 桥接：控制台记录同时携带 id 与 uuid
    runtime = entry.runtime_data
    records = getattr(runtime.coordinator, "console_records", None) if runtime else None
    for rec in records or []:
        if str(rec.get("id") or "") in candidates and rec.get("uuid"):
            candidates.add(str(rec["uuid"]))
    for sub in entry.subentries.values():
        if sub.subentry_type != SUBENTRY_TYPE_CHANNEL:
            continue
        stored = {str(sub.data.get(CONF_CHANNEL_ID, "")),
                  str(sub.data.get("id") or ""),
                  str(sub.unique_id or "")} - {""}
        if candidates & stored:
            return sub.subentry_id
    # ID 字段对不上时按通道名兜底（子条目标题即通道名）
    if channel.name:
        for sub in entry.subentries.values():
            if (sub.subentry_type == SUBENTRY_TYPE_CHANNEL
                    and sub.title == channel.name):
                return sub.subentry_id
    return None


def channel_device_info(entry: WebTunnelConfigEntry, channel_id: str) -> DeviceInfo:
    """One device per channel (named after the channel), owned by its subentry.

    HA 的子条目卡片只渲染设备行：通道实体必须挂在通道设备上才会显示在
    对应子条目下。同一设备的所有注册都传同一个 config_subentry_id，
    避免归属抖动。
    """
    ch: Channel | None = next(
        (c for c in entry.runtime_data.coordinator.data or [] if c.id == channel_id),
        None,
    )
    return DeviceInfo(
        identifiers={(entry.domain, f"{entry.entry_id}-{channel_id}")},
        name=ch.name if ch and ch.name else channel_id,
        manufacturer="WebTunnel",
        model=str(ch.conn_type or "channel") if ch else "channel",
    )


def basic_subentry_id(entry: WebTunnelConfigEntry) -> str | None:
    """Id of the account's single 基础信息 subentry (None before it exists)."""
    for sub in entry.subentries.values():
        if sub.subentry_type == SUBENTRY_TYPE_BASIC:
            return sub.subentry_id
    return None


async def basic_subentry_title(hass) -> str:
    """Localized title for the basic subentry / account device."""
    from homeassistant.helpers.translation import async_get_translations
    data = await async_get_translations(hass, hass.config.language,
                                        "config_subentries", [DOMAIN])
    # async_get_translations 返回扁平的点分键
    key = f"component.{DOMAIN}.config_subentries.{SUBENTRY_TYPE_BASIC}.entry_type"
    if isinstance(data, dict) and data.get(key):
        return str(data[key])
    return "基础信息"
