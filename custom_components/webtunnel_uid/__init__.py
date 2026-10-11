"""The WebTunnel integration: one account per entry, channels via subentries."""
from __future__ import annotations

import logging
import socket

from homeassistant.config_entries import ConfigSubentry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryError, ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (WebTunnelAuthError, WebTunnelCloud, WebTunnelCloudError,
                  WebTunnelConsole, WebTunnelSession)
from .const import (CONF_BASE_URL, CONF_CHANNEL_ID, CONF_CONSOLE_TOKEN,
                    CONF_LOCAL_PORT, CONF_MODE, CONF_NAME, CONF_PASSWORD,
                    CONF_UID, CONF_USERNAME, CONF_WEB_DOMAIN,
                    CONSOLE_API_PREFIX, DOMAIN, SUBENTRY_TYPE_CHANNEL)
from .coordinator import WebTunnelCoordinator
from .tunnel import TunnelManager
from .types import (WebTunnelConfigEntry, WebTunnelData,
                    basic_subentry_title)
from .wscontrol import WsControlClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BINARY_SENSOR, Platform.BUTTON, Platform.SENSOR]


async def async_setup(hass, config) -> bool:
    """uid 集成无需 HTTP 路由。"""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: WebTunnelConfigEntry) -> bool:
    # 同 uid 只能有一个客户端在跑：主集成/本集成重复配置会互相抢通道，
    # 服务端会拒绝后注册者（表现为通道状态不正常、流量统计为 0）
    for other in hass.config_entries.async_entries():
        if (other.domain != DOMAIN and other.entry_id != entry.entry_id
                and other.data.get(CONF_UID) == entry.data.get(CONF_UID)):
            _LOGGER.warning(
                "uid %s 同时配置在了 %s 集成 (%s) 里：两个客户端会争抢同一通道，"
                "请删除其中一个，只保留一个在运行",
                entry.data.get(CONF_UID), other.domain, other.title)

    cloud = WebTunnelCloud(
        base_url=entry.data.get(CONF_BASE_URL, ""),
        uid=entry.data.get(CONF_UID, ""),
        session=async_get_clientsession(hass),
    )
    # one verification round trip so a bad entry fails fast
    try:
        await cloud.verify_uid()
    except WebTunnelAuthError as err:
        await cloud.aclose()
        raise ConfigEntryError(f"认证失败: {err}") from err
    except WebTunnelCloudError as err:
        await cloud.aclose()
        raise ConfigEntryNotReady(f"云端连接失败: {err}") from err

    manager = TunnelManager(hass, entry.data.get(CONF_UID, ""))
    coordinator = WebTunnelCoordinator(hass, entry, cloud)

    @callback
    def _on_heartbeat_command():
        # wscontrol 的回调是同步调用：这里只负责调度刷新任务
        entry.async_create_task(hass, coordinator.async_request_refresh())

    ws = WsControlClient(
        session=async_get_clientsession(hass),
        base_url=entry.data.get(CONF_BASE_URL, ""),
        uid=entry.data.get(CONF_UID, ""),
        hostname=socket.gethostname(),
        on_heartbeat_command=_on_heartbeat_command,
    )

    console: WebTunnelConsole | None = None
    if entry.data.get(CONF_MODE) == "password" and entry.data.get(CONF_USERNAME):
        session_helper = WebTunnelSession(
            base_url=entry.data.get(CONF_BASE_URL, ""),
            username=entry.data.get(CONF_USERNAME, ""),
            password=entry.data.get(CONF_PASSWORD, ""),
            session=async_get_clientsession(hass),
        )
        try:
            await session_helper.refresh()
        except WebTunnelAuthError as err:
            _LOGGER.warning("console session login failed: %s", err)
        else:
            console = WebTunnelConsole(
                # 控制台接口在 /service 前缀下（与官方云控制台一致）
                base_url=entry.data.get(CONF_BASE_URL, "").rstrip("/")
                + CONSOLE_API_PREFIX,
                uid=session_helper.uid or entry.data.get(CONF_UID, ""),
                # 控制台会话优先：login4acct（图片验证码登录）换取的令牌
                token=entry.data.get(CONF_CONSOLE_TOKEN)
                or session_helper.token or "",
                session=async_get_clientsession(hass),
                hostname=socket.gethostname(),
            )
            console._session_helper = session_helper  # noqa: SLF001 - relogin on expiry
        # 控制台客户端供协调器合并账号全量通道（发现运行在其他主机上的通道）
        coordinator.console = console

    entry.runtime_data = WebTunnelData(cloud=cloud, coordinator=coordinator, manager=manager,
                                       ws=ws, console=console)

    # 每个账号一个“基础信息”子条目，账号级设备/实体都归属它
    try:
        await _async_ensure_basic_subentry(hass, entry)
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning("creating the basic subentry failed: %s", err)

    await coordinator.async_config_entry_first_refresh()
    await manager.sync(coordinator.data or [], cloud.base_url)
    # 子条目同步失败不应阻断整个条目启动（下个心跳周期会重试）
    try:
        await _async_sync_channel_subentries(hass, entry)
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning("channel subentry sync failed (retries on next refresh): %s", err)
    await ws.start()

    def _on_coordinator_update():
        entry.async_create_task(hass, _sync_tunnels(hass, entry))
    entry.async_on_unload(coordinator.async_add_listener(_on_coordinator_update))

    if entry.runtime_data.console and entry.runtime_data.console.token:
        console_client = entry.runtime_data.console
        account_uid = entry.data.get(CONF_UID, "")
        async def _fetch_extras():
            try:
                coordinator.user_info = await console_client.get_user_info()
            except Exception as err:
                _LOGGER.warning("[%s] 用户信息获取失败: %s", account_uid, err)
            try:
                coordinator.monthly_traffic = await console_client.monthly_traffic()
            except Exception as err:
                _LOGGER.warning("[%s] 月流量获取失败: %s", account_uid, err)
        entry.async_create_task(hass, _fetch_extras())

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # seed the channel-subentry map so removals can be diffed at any time
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        s.subentry_id: str(s.data.get(CONF_CHANNEL_ID, ""))
        for s in entry.subentries.values()
        if s.subentry_type == SUBENTRY_TYPE_CHANNEL
    }
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    _LOGGER.info("WebTunnel 集成就绪 (uid=%s)", entry.data.get(CONF_UID))
    return True


async def _async_ensure_basic_subentry(hass: HomeAssistant, entry: WebTunnelConfigEntry) -> None:
    """Create the single 基础信息 subentry if missing (all account entities live there)."""
    from .const import SUBENTRY_TYPE_BASIC
    for sub in entry.subentries.values():
        if sub.subentry_type == SUBENTRY_TYPE_BASIC:
            return
        sub = ConfigSubentry(
            data={},
            subentry_type=SUBENTRY_TYPE_BASIC,
            title=await basic_subentry_title(hass),
            unique_id=f"{DOMAIN}-basic",
        )
        hass.config_entries.async_add_subentry(entry, sub)
        _LOGGER.debug("created the basic subentry for entry %s", entry.entry_id)

    # 注意：这里绝不写设备注册表。设备归属由实体注册时的
    # config_subentry_id 决定，老实例的残留状态用重建条目恢复。
    _LOGGER.debug("basic subentry ready for entry %s", entry.entry_id)


async def _sync_tunnels(hass: HomeAssistant, entry: WebTunnelConfigEntry) -> None:
    """Re-sync tunnel clients + channel subentries after every coordinator refresh."""
    data = entry.runtime_data
    await data.manager.sync(data.coordinator.data or [], data.cloud.base_url)
    changed = await _async_sync_channel_subentries(hass, entry)
    if changed:
        # 新子条目刚建好：重新通知平台监听器，通道实体才能挂到子条目设备下
        data.coordinator.async_update_listeners()


async def _async_sync_channel_subentries(
    hass: HomeAssistant, entry: WebTunnelConfigEntry
) -> bool:
    """Mirror the account's cloud channels into channel subentries.

    Sources: 控制台全量记录（密码账号）+ 心跳通道（host-bound；uid 账号
    没有控制台令牌，心跳是唯一来源）。Channels created elsewhere show up
    automatically; channels deleted from the cloud drop their subentry.
    Idempotent. Returns True when the subentry set changed.
    """
    runtime = entry.runtime_data
    if runtime is None:
        return False

    def _keys(record: dict) -> set[str]:
        return {str(record.get("uuid") or ""), str(record.get("id") or "")} - {""}

    # 控制台全量记录优先（含其他主机上的通道），心跳通道按 id/uuid 去重合并
    records: list[dict] = []
    seen: list[set[str]] = []
    for record in runtime.coordinator.console_records or []:
        keys = _keys(record)
        if not keys:
            continue
        records.append(record)
        seen.append(keys)
    for ch in runtime.coordinator.data or []:
        raw = dict(ch.raw or {})
        keys = {k for k in (str(raw.get("uuid") or ""), str(raw.get("id") or ""),
                            str(ch.id or "")) if k}
        if not keys or any(keys & s for s in seen):
            continue
        records.append(raw)
        seen.append(keys)
    if not records:
        return False

    want: dict[str, ConfigSubentry] = {}
    for record in records:
        channel_id = str(record.get("uuid") or record.get("id") or "")
        if not channel_id:
            continue
        name = str(record.get("name") or channel_id)
        want[channel_id] = ConfigSubentry(
            data={
                CONF_CHANNEL_ID: channel_id,
                # 心跳记录只有数字 id：一并存储供实体归属匹配
                "id": str(record.get("id") or ""),
                CONF_NAME: name,
                CONF_WEB_DOMAIN: str(record.get("web_domain") or ""),
                CONF_LOCAL_PORT: record.get("local_port") or 0,
            },
            subentry_type=SUBENTRY_TYPE_CHANNEL,
            title=name,
            unique_id=channel_id,
        )

    current: dict[str, ConfigSubentry] = {}
    for sub in entry.subentries.values():
        if sub.subentry_type == SUBENTRY_TYPE_CHANNEL and sub.unique_id:
            current[sub.unique_id] = sub

    # 只用公开的子条目 API：async_update_entry 不接受 subentries 参数
    changed = False
    for channel_id, sub in want.items():
        existing = current.get(channel_id)
        try:
            if existing is None:
                hass.config_entries.async_add_subentry(entry, sub)
                changed = True
                _LOGGER.debug("discovered channel %s (%s) as a subentry",
                              channel_id, sub.title)
            elif existing.title != sub.title:
                hass.config_entries.async_update_subentry(entry, existing,
                                                          title=sub.title)
                changed = True
        except (HomeAssistantError, TypeError) as err:
            _LOGGER.warning("syncing channel subentry %s (%s) failed: %s",
                            channel_id, sub.title, err)
    for channel_id, existing in current.items():
        if channel_id not in want:
            try:
                hass.config_entries.async_remove_subentry(entry, existing.subentry_id)
                changed = True
                _LOGGER.info("channel %s no longer exists on the cloud; "
                             "dropping its subentry", channel_id)
            except (HomeAssistantError, TypeError) as err:
                _LOGGER.warning("removing subentry for channel %s failed: %s",
                                channel_id, err)
    return changed


async def _async_update_listener(hass: HomeAssistant, entry: WebTunnelConfigEntry) -> None:
    await _async_prune_removed_channels(hass, entry)
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_prune_removed_channels(hass: HomeAssistant,
                                        entry: WebTunnelConfigEntry) -> None:
    """Delete the cloud channel when its channel subentry is removed.

    The subentry map is kept in hass.data so a removal (which happens before
    this listener runs) can be detected by diffing against the previous set.
    """
    store = hass.data.setdefault(DOMAIN, {})
    current = {
        s.subentry_id: str(s.data.get(CONF_CHANNEL_ID, ""))
        for s in entry.subentries.values()
        if s.subentry_type == SUBENTRY_TYPE_CHANNEL
    }
    previous = store.get(entry.entry_id)
    store[entry.entry_id] = current
    if previous is None:
        return
    removed = [cid for sid, cid in previous.items()
               if sid not in current and cid]
    if not removed:
        return
    runtime = entry.runtime_data
    console = runtime.console if runtime else None
    if console is None or not console.token:
        _LOGGER.warning("[%s] channel subentry removed without a console token; "
                        "the cloud channel was kept",
                        entry.data.get(CONF_UID, ""))
        return
    # 通道已从云端消失（外部删除）：子条目由同步移除，此时不要再删云端
    known: set[str] = set()
    if runtime is not None:
        for ch in runtime.coordinator.data or []:
            known.add(ch.id)
            for key in ("uuid", "id"):
                value = str(ch.raw.get(key) or "")
                if value:
                    known.add(value)
    for channel_id in removed:
        if channel_id not in known:
            _LOGGER.debug("channel %s already gone from the cloud; skipping delete",
                          channel_id)
            continue
        try:
            # 官方要求先停止通道才能删除；停用 → 删除 → 清空回收站
            try:
                await console.enable_port_mapping(channel_id, False)
            except WebTunnelCloudError as err:
                _LOGGER.debug("stopping channel %s before delete failed: %s",
                              channel_id, err)
            await console.batch_delete([channel_id])
            try:
                await console.clear_recycle()
            except WebTunnelCloudError as err:
                _LOGGER.warning("clearing the recycle bin failed: %s", err)
            _LOGGER.info("deleted channel %s from the cloud (subentry removed)",
                         channel_id)
        except WebTunnelCloudError as err:
            _LOGGER.warning("deleting channel %s failed: %s", channel_id, err)


async def async_unload_entry(hass: HomeAssistant, entry: WebTunnelConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        data = entry.runtime_data
        await data.manager.stop_all()
        await data.ws.stop()
        await data.cloud.aclose()
        entry.runtime_data = None
    return unload_ok
