"""WebTunnel cloud API client (login / heartbeat / config decryption)."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import socket
import time

import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .const import (
    CONSOLE_FRONTEND_VERSION,
    DEFAULT_BASE_URL,
    ENDPOINT_CAPTCHA_CHECK,
    ENDPOINT_CAPTCHA_GET,
    ENDPOINT_HEARTBEAT,
    ENDPOINT_LOGIN,
    ENDPOINT_LOGIN4ACCT,
    OFFICIAL_VERSION,
)

_LOGGER = logging.getLogger(__name__)

# Hardcoded in the official client (src/common/common.js) — public knowledge.
_CONFIG_KEY = b"0CoJUm6Qyw8W8jud"
_CONFIG_IV = b"0102030405060708"


class WebTunnelCloudError(Exception):
    """Base error talking to the WebTunnel cloud."""


class WebTunnelAuthError(WebTunnelCloudError):
    """Invalid credentials / uid."""


class WebTunnelCaptchaError(WebTunnelCloudError):
    """goCaptcha verification failed (captcha/check rejected the dots)."""


class WebTunnelCaptchaRequired(WebTunnelCloudError):
    """The cloud demands a human verification for this action."""


def decrypt_channel_config(hex_text: str) -> str:
    """解密通道的 TOML 配置（AES-128-CBC，hex 编码，PKCS7 填充）。"""
    ciphertext = bytes.fromhex(hex_text.strip())
    decryptor = Cipher(algorithms.AES(_CONFIG_KEY), modes.CBC(_CONFIG_IV)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    if not 1 <= pad_len <= 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise WebTunnelCloudError("invalid padding in decrypted channel config")
    return padded[:-pad_len].decode("utf-8")


def md5_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def parse_captcha_payload(payload: dict) -> tuple[str, bytes, bytes, tuple[int, int] | None]:
    """Extract (key, image, thumb, image size) from a goCaptcha get response."""
    data = payload.get("data") or {}
    key = str(data.get("key") or "")
    image_b64 = str(data.get("imageBase64") or "").split(",")[-1]
    if not key or not image_b64:
        raise WebTunnelCloudError("captcha response missing key/image")
    image = base64.b64decode(image_b64)
    thumb_b64 = str(data.get("thumbBase64") or "").split(",")[-1]
    thumb = base64.b64decode(thumb_b64) if thumb_b64 else b""
    size = None
    if image[:8] == b"\x89PNG\r\n\x1a\n" and len(image) >= 24:
        size = (int.from_bytes(image[16:20], "big"),
                int.from_bytes(image[20:24], "big"))
    return key, image, thumb, size


class WebTunnelCloud:
    """Minimal client for the WebTunnel cloud control plane."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, uid: str | None = None,
                 session: aiohttp.ClientSession | None = None):
        self.base_url = base_url.rstrip("/")
        self.uid = uid
        self._session = session
        self._owned_session = None

    async def _http(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._owned_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15))
            self._session = self._owned_session
        return self._session

    async def aclose(self):
        if self._owned_session:
            await self._owned_session.close()

    async def login_password(self, username: str, password: str) -> dict:
        """Login with username/password, returns {'uid', 'nickname'}."""
        session = await self._http()
        async with session.get(
            f"{self.base_url}{ENDPOINT_LOGIN}",
            params={
                "shell-version": OFFICIAL_VERSION,
                "username": username,
                "passwd": md5_password(password),
            },
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        if not payload.get("success"):
            raise WebTunnelAuthError(payload.get("message") or "login rejected")
        data = payload.get("data") or {}
        uid = data.get("uid")
        if not uid:
            raise WebTunnelAuthError("login response did not contain a uid")
        # 登录返回的身份字段决定后续心跳/控制台调用的归属，留档排查
        _LOGGER.info("login4client response fields: %s (uid=%s)",
                     sorted(data.keys()), uid)
        return data

    @staticmethod
    def _local_ip() -> str:
        """Best-effort LAN IP (a 127.x address is rejected by the cloud)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            sock.close()

    async def heartbeat(self, hostname: str = "") -> list[dict]:
        """Poll channel records (config_file is the AES-encrypted tunnel TOML).

        The body mirrors the official client's heartbeat; the cloud rejects
        requests whose shape deviates (force must be a boolean, an ip that
        parses as a loopback address is refused, etc.).
        """
        session = await self._http()
        local_ip = await asyncio.get_running_loop().run_in_executor(
            None, self._local_ip)
        hostname = hostname or socket.gethostname() or "homeassistant"
        async with session.post(
            f"{self.base_url}{ENDPOINT_HEARTBEAT}",
            json={
                "platform": "linux",
                "arch": "x64",
                "release": "",
                "hostname": hostname,
                "ip": local_ip,
                "is_admin": False,
                "privilege_user": "user",
                "uid": self.uid,
                "force": True,
                "virtual_ip": "",
                "runMode": "linux",
                "version": "vs.260601",
                "consolePort": 9600,
                "totalMem": "0.00",
                "freeMem": "0.00",
                "cpuLoad": "0.00",
                "upTime": 0,
                "localPortCheckResult": {},
                "domainCheckResult": {},
                "dnsRepairResult": "",
            },
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        if not payload.get("success"):
            message = payload.get("message") or "heartbeat rejected"
            if "uid" in message.lower() or "登录" in message or "password" in message:
                raise WebTunnelAuthError(message)
            raise WebTunnelCloudError(message)
        records = payload.get("data")
        return records if isinstance(records, list) else []

    async def verify_uid(self) -> list[dict]:
        """Validate a uid by issuing one heartbeat; returns the records."""
        return await self.heartbeat()

    async def get_captcha(self) -> tuple[str, bytes, bytes, tuple[int, int] | None]:
        """Fetch a goCaptcha click image for the console login.

        Returns (key, image_png, thumb_png, (width, height) for PNG images).
        """
        session = await self._http()
        async with session.get(f"{self.base_url}{ENDPOINT_CAPTCHA_GET}") as resp:
            resp.raise_for_status()
            payload = await resp.json()
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "captcha get failed")
        return parse_captcha_payload(payload)

    async def check_captcha(self, key: str, dots: str) -> None:
        """Verify the manually provided click coordinates for `key`."""
        session = await self._http()
        async with session.post(
            f"{self.base_url}{ENDPOINT_CAPTCHA_CHECK}", json={"key": key, "dots": dots}
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        if not payload.get("success"):
            raise WebTunnelCaptchaError(payload.get("message") or "captcha check failed")

    async def login4acct(self, username: str, password: str, captcha_key: str) -> dict:
        """Console account login (captcha-verified); returns console session data."""
        session = await self._http()
        async with session.post(
            f"{self.base_url}{ENDPOINT_LOGIN4ACCT}",
            json={
                "uid": int(time.time() * 1000),
                "username": username,
                "passwd": md5_password(password),
                "autoLogin": True,
                "captchaKey": captcha_key,
                "version": CONSOLE_FRONTEND_VERSION,
            },
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        if not payload.get("success"):
            raise WebTunnelAuthError(payload.get("message") or "login4acct failed")
        return payload.get("data") or {}


class WebTunnelSession:
    """Password-mode console session: fresh token via login4client.

    The login endpoint requires no captcha and the token stays valid for the
    official client's two-week window; this helper transparently re-logs-in
    when the server reports an invalid token.
    """

    def __init__(self, base_url: str, username: str, password: str,
                 session: aiohttp.ClientSession | None = None):
        self.cloud = WebTunnelCloud(base_url=base_url, session=session)
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.uid: str | None = None
        self.token: str | None = None

    async def refresh(self) -> None:
        data = await self.cloud.login_password(self.username, self.password)
        self.uid = data.get("uid")
        self.token = data.get("token")
        self.cloud.uid = self.uid

    async def aclose(self):
        await self.cloud.aclose()


class WebTunnelConsole:
    """Token-authenticated console API (channel management, traffic, user info).

    login4client (no captcha) returns {uid, token}; the token authenticates
    console endpoints via Token/Uid request headers for its validity window
    (two weeks per the official client's auto-login contract). Password mode
    stores the token and refreshes it transparently on expiry.
    """

    def __init__(self, base_url: str, uid: str, token: str,
                 session: aiohttp.ClientSession | None = None,
                 hostname: str = ""):
        self.base_url = base_url.rstrip("/")
        self.uid = uid
        self.token = token
        self.hostname = hostname or socket.gethostname() or "homeassistant"
        self._session = session
        self._owned_session = None

    async def _http(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._owned_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15))
            self._session = self._owned_session
        return self._session

    async def aclose(self):
        if self._owned_session:
            await self._owned_session.close()

    def _headers(self) -> dict:
        # 与官方桌面客户端的请求拦截器保持一致：platform/arch/shell-version/
        # hostname 只在客户端环境存在（纯浏览器请求没有），服务器据此区分
        # 客户端与网页端（验证码/风控策略不同）
        headers: dict = {
            "Token": self.token,
            "Uid": self.uid,
            "platform": "linux",
            "arch": "x64",
            "shell-version": OFFICIAL_VERSION,
        }
        try:
            self.hostname.encode("ascii")
        except UnicodeEncodeError:
            headers["hostname"] = base64.b64encode(
                self.hostname.encode("utf-8")).decode("ascii")
            headers["hostname-encoded"] = "base64"
        else:
            headers["hostname"] = self.hostname
        return headers

    async def _get(self, path: str, params: dict | None = None) -> dict:
        return await self._request("GET", path, params=params)

    async def _post(self, path: str, payload: dict) -> dict:
        return await self._request("POST", path, json_payload=payload)

    async def _request(self, method: str, path: str, params: dict | None = None,
                       json_payload: dict | None = None, _retry: bool = True) -> dict:
        session = await self._http()
        kwargs: dict = {"headers": self._headers()}
        if params:
            kwargs["params"] = params
        if json_payload is not None:
            kwargs["json"] = json_payload
        async with session.request(method, f"{self.base_url}{path}", **kwargs) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        # token 过期（2 周窗口）时透明重登一次
        if (not payload.get("success") and _retry
                and "重新登录" in str(payload.get("message", ""))
                and getattr(self, "_session_helper", None)):
            await self._session_helper.refresh()
            self.uid = self._session_helper.uid or self.uid
            self.token = self._session_helper.token or self.token
            return await self._request(method, path, params=params,
                                       json_payload=json_payload, _retry=False)
        return payload

    async def get_user_info(self) -> dict:
        payload = await self._get("/user/get_user_info")
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "get_user_info failed")
        return payload.get("data") or {}

    async def monthly_traffic(self) -> dict:
        payload = await self._get("/traffic/curr_month_traffic")
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "traffic failed")
        return payload.get("data") or {}

    async def get_captcha(self) -> tuple[str, bytes, bytes, tuple[int, int] | None]:
        """goCaptcha click image fetched with this console session's identity.

        Same exchange as the official console SPA: the verification result
        binds to this session (Token/Uid headers), so the next management
        request (e.g. add_port_mapping) passes without being challenged.
        """
        payload = await self._get("/login/captcha/get")
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "captcha get failed")
        return parse_captcha_payload(payload)

    async def check_captcha(self, key: str, dots: str) -> None:
        """Verify the click coordinates; marks this console session verified."""
        payload = await self._post("/login/captcha/check", {"key": key, "dots": dots})
        if not payload.get("success"):
            raise WebTunnelCaptchaError(payload.get("message") or "captcha check failed")

    async def get_proxy_server(self, conn_type: str = "web") -> list:
        """Tunnel server (线路) list; items carry label/vip_level/tag/maint/fee."""
        payload = await self._get("/port_mapping/get_proxy_server",
                                  {"conn_type": conn_type})
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "get_proxy_server failed")
        return payload.get("data") or []

    async def web_domains(self) -> dict:
        """Available web domains for the channel form (official fallback list
        applies when the cloud returns nothing usable)."""
        payload = await self._get("/port_mapping/web_domains")
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "web_domains failed")
        return payload.get("data") or {}

    async def port_mapping_all(self) -> list:
        """Account-wide channel records (official shape: data.data = page rows).

        Paginates like the official console table (page_index/page_size with
        the root group conditions) so channels beyond the default page size
        are still discovered.
        """
        records: list = []
        page = 0
        while page < 50:
            payload = await self._get("/port_mapping/all", params={
                "page_index": page,
                "page_size": 50,
                "cond[proxyList]": "'root'",
                "cond[groupList]": "'root'",
            })
            if not payload.get("success"):
                raise WebTunnelCloudError(payload.get("message") or "port_mapping/all failed")
            data = payload.get("data") or {}
            rows = data.get("data") if isinstance(data, dict) else data
            if not isinstance(rows, list):
                break
            records.extend(rows)
            total = data.get("total") if isinstance(data, dict) else None
            page += 1
            if not rows or (isinstance(total, int) and len(records) >= total):
                break
        return records

    async def terminal_list(self) -> list:
        payload = await self._get("/port_mapping/get_terminal_list")
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "terminal_list failed")
        return payload.get("data") or []

    @staticmethod
    def _create_form(name: str, local_ip: str, local_port: int,
                     proxy_hostname: str, proxy_channel: str = "",
                     web_domain: str = "pgrm.cc", web_sld: str = "") -> dict:
        """Field set mirrors the official cloud console's add form (web type,
        directOpen = no access password): unset values are null (not ""),
        safePasswdPolicy stays "-1" (the server column is an integer and
        rejects ""), proxyChannel null = server assigns a line randomly,
        transport defaults to quic.
        """
        return {
            "name": name,
            "group": "root",
            "connType": "web",
            "localIpType": "localhost",
            "localIp": local_ip,
            "localPort": str(local_port),
            "proxyHostname": [proxy_hostname],
            "proxyIp": None,
            "proxyType": "public",
            "proxyChannel": proxy_channel or None,
            "remotePort": None,
            "virtualIp": None,
            "shareDir": None,
            "comments": None,
            "webProtocol": "https",
            "webSld": web_sld,
            "webDomain": web_domain,
            "webSrcUrl": None,
            "webSrcHttps": False,
            "webSrcSelfSigned": False,
            "webAccName": None,
            "webAccPasswd": None,
            "webSecurityEnabled": False,
            "acctType": "0",
            "safePasswd": None,
            "safePasswdPolicy": "-1",
            "stcpSecretKey": None,
            "xtcpFallbackRelay": False,
            "osUsername": None,
            "osPasswd": None,
            "remoteApp": None,
            "remoteAppArgs": None,
            "recording": 1,
            "transportProtocol": "quic",
            "enableEncryption": True,
            "enableCompression": True,
            "enableLog": True,
        }

    async def add_port_mapping(self, name: str, local_ip: str, local_port: int,
                               proxy_hostname: str, proxy_channel: str = "",
                               web_domain: str = "pgrm.cc", web_sld: str = "") -> dict:
        """Create a web channel; returns the created record (uuid, ...)."""
        import secrets
        if not web_sld:
            web_sld = "wt" + secrets.token_hex(4)
        form = self._create_form(name, local_ip, local_port, proxy_hostname,
                                 proxy_channel, web_domain, web_sld)
        payload = await self._post("/port_mapping/add", {"form": form})
        if not payload.get("success"):
            message = str(payload.get("message") or "port_mapping/add failed")
            if "验证码" in message or "captcha" in message.lower():
                raise WebTunnelCaptchaRequired(message)
            raise WebTunnelCloudError(message)
        return payload.get("data") or {}

    async def batch_delete(self, ids: list[str]) -> None:
        # 官方控制台把 ids 作为数组查询参数展开（ids[]=a&ids[]=b）
        payload = await self._get("/port_mapping/batch_del",
                                  params=[("ids[]", cid) for cid in ids])
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "batch_del failed")

    async def clear_recycle(self) -> None:
        """清空云端通道回收站（删除的通道先进回收站，不清会一直占位）。"""
        payload = await self._get("/port_mapping/clear_recycle", params={})
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "clear_recycle failed")

    async def enable_port_mapping(self, channel_id: str, enable: bool) -> None:
        payload = await self._get("/port_mapping/enable",
                                  {"id": channel_id, "enable": 0 if enable else 1})
        if not payload.get("success"):
            raise WebTunnelCloudError(payload.get("message") or "enable failed")
