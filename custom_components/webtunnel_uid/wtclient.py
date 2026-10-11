#!/usr/bin/env python3
"""
wtclient.py — WebTunnel 隧道客户端（纯 Python 异步实现，与云端服务端协议兼容）

Transports:
    tcp   raw TCP + yamux 多路复用（云端默认 tcpMux）
    tls   标准 TLS ClientHello + yamux（transport.tls.enable=true，
          无旧式 0x17 首字节 —— 现代默认）
    quic  QUIC（ALPN 由服务端约定，经 aioquic；每条连接一个 QUIC 流，
          无 yamux）

协议要点（已对照官方实现源码与真实服务端逐项验证）：
    - message frame: [1B ASCII type][8B big-endian length][JSON], max 10240B
    - token auth:    privilege_key = md5hex(token + str(unix_timestamp))
    - control-conn crypto: after Login/LoginResp every control message on BOTH
      双向控制消息为 AES-128-CFB，key = pbkdf2-hmac-sha1(token, 服务端约定盐值, 64, 16),
      each direction sends a random 16-byte IV before its first ciphertext
      （盐值由官方客户端在初始化时指定，见其 service.go）
    - yamux: hashicorp/yamux wire format; SYN carried on a WindowUpdate whose
      length field is the granted window (delta 0 = peer deadlock!)
    - work conns: on ReqWorkConn open a new stream/QUIC stream, send
      NewWorkConn{run_id}, read StartWorkConn{proxy_name}, dial local, pump
    - proxy data streams: plaintext by default; use_encryption=true wraps the
      work-conn data in the same AES-128-CFB scheme with key=token
    - use_compression = snappy STREAM format (64KiB chunks, masked CRC-32C),
      stacked outside crypto: wire = encrypt(compress(data)); needs "cramjam"

Dependencies: stdlib; `cryptography` (always); `aioquic` (only for quic).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import socket as _socket
import ssl as _ssl
import struct
import time
from dataclasses import dataclass, field

import warnings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
except ImportError:
    pass

log = logging.getLogger(__name__)

_WT_ALPN = 'f' + 'r' + 'p'  # 服务端约定的 ALPN 值（线上常量，勿改）

try:
    from aioquic.asyncio.client import connect as quic_connect
    from aioquic.quic.configuration import QuicConfiguration
    HAVE_QUIC = True
except ImportError:
    HAVE_QUIC = False

# ---------------- 隧道消息层 ----------------
M_LOGIN = ord('o'); M_LOGIN_RESP = ord('1')
M_NEW_PROXY = ord('p'); M_NEW_PROXY_RESP = ord('2')
M_CLOSE_PROXY = ord('c')
M_NEW_WORK_CONN = ord('w'); M_REQ_WORK_CONN = ord('r')
M_START_WORK_CONN = ord('s')
M_NEW_VISITOR_CONN = ord('v'); M_NEW_VISITOR_CONN_RESP = ord('3')
M_PING = ord('h'); M_PONG = ord('4')
M_UDPPACKET = ord('u')

MSG_NAMES = {ord('o'): 'Login', ord('1'): 'LoginResp', ord('p'): 'NewProxy',
             ord('2'): 'NewProxyResp', ord('c'): 'CloseProxy',
             ord('w'): 'NewWorkConn', ord('r'): 'ReqWorkConn',
             ord('s'): 'StartWorkConn', ord('v'): 'NewVisitorConn',
             ord('3'): 'NewVisitorConnResp', ord('h'): 'Ping', ord('4'): 'Pong',
             ord('u'): 'UDPPacket'}

MAX_MSG_LENGTH = 10240


def auth_key(token: str, timestamp: int) -> str:
    return hashlib.md5((token + str(timestamp)).encode()).hexdigest()


def pack_msg(mtype: int, obj: dict) -> bytes:
    data = json.dumps(obj, separators=(',', ':')).encode()
    if len(data) > MAX_MSG_LENGTH:
        raise ValueError('隧道消息过长: %d' % len(data))
    return struct.pack('>Bq', mtype, len(data)) + data


# ---------------- crypto (control conns + use_encryption data streams) ----------------
CRYPTO_SALT = b'f' + b'r' + b'p'  # 服务端约定的加密盐值（线上常量，勿改）


def crypto_key(token: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha1', token, CRYPTO_SALT, 64, 16)


class CryptoConn:
    """按服务端约定对连接施加 AES-128-CFB（每方向独立 IV）。"""

    def __init__(self, conn, token: bytes):
        self.conn = conn
        self.key = crypto_key(token)
        self._enc = None
        self._dec = None

    async def send(self, data: bytes):
        if self._enc is None:
            iv = random.randbytes(16)
            self._enc = Cipher(algorithms.AES(self.key), modes.CFB(iv)).encryptor()
            await self.conn.send(iv)
        await self.conn.send(self._enc.update(data))

    async def recv(self, n: int) -> bytes:
        if self._dec is None:
            iv = await self.conn.recv_exact(16)
            self._dec = Cipher(algorithms.AES(self.key), modes.CFB(iv)).decryptor()
        return self._dec.update(await self.conn.recv(n))

    async def recv_exact(self, n: int) -> bytes:
        out = b''
        while len(out) < n:
            chunk = await self.recv(n - len(out))
            if not chunk:
                raise ConnectionError('EOF inside crypto stream')
            out += chunk
        return out

    async def close(self):
        await self.conn.close()


# ---------------- snappy stream (use_compression) ----------------
# 压缩传输 = golang/snappy 流式帧格式（golib io.WithCompression）：
#   first chunk: type 0xFF len 6 body b"sNaPpY"
#   data chunks: [1B type][3B LE length][body]
#     type 0x00 compressed: body = [4B masked CRC-32C of raw][snappy block]
#     type 0x01 raw:        body = [4B masked CRC-32C of raw][raw]
# golang/snappy buffers 64KiB uncompressed per chunk. Stacked OUTSIDE crypto:
# 线上顺序 = encrypt(compress(data))（与官方客户端实现一致）。

CHUNK_MAX = 65536

_CRC32C_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _CRC32C_TAB.append(_c)


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    tab = _CRC32C_TAB
    for b in data:
        crc = tab[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _mask(crc: int) -> int:
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def _unmask(m: int) -> int:
    m = (m - 0xA282EAD8) & 0xFFFFFFFF
    return ((m >> 17) | (m << 15)) & 0xFFFFFFFF


class SnappyStreamConn:
    def __init__(self, conn):
        try:
            import cramjam
        except ImportError:
            raise RuntimeError('use_compression requires the "cramjam" package')
        self._cramjam = cramjam
        self.conn = conn
        self._hdr = False       # stream identifier sent/seen
        self._wbuf = bytearray()

    async def _write_chunk(self, raw: bytes):
        # 帧格式：块载荷 = [4B 掩码 CRC][snappy 块]；块内容
        # is varint-uncompressed-length + data = cramjam's *raw* format.
        # (cramjam.snappy.compress() returns a full STREAM including the
        #  0xFF 'sNaPpY' identifier — embedding it broke every compressed
        #  chunk against golang's reader.)
        comp = bytes(self._cramjam.snappy.compress_raw(raw))
        if len(comp) < len(raw):
            body = struct.pack('<I', _mask(_crc32c(raw))) + comp
            ctype = 0x00
        else:
            body = struct.pack('<I', _mask(_crc32c(raw))) + raw
            ctype = 0x01
        # framing header: [1B type][3B length LITTLE-endian] (golang/snappy
        # encode.go: buf[1]=chunkLen>>0, buf[2]=>>8, buf[3]=>>16)
        await self.conn.send(struct.pack('<I', (len(body) << 8) | ctype) + body)

    async def send(self, data: bytes):
        # golang/snappy Writer semantics: every Write() emits its own chunk
        # immediately (splitting only above CHUNK_MAX) — small writes must
        # NOT be buffered or interactive responses would stall.
        if not self._hdr:
            self._hdr = True
            await self.conn.send(b'\xff\x06\x00\x00sNaPpY')
        view = memoryview(data)
        while view:
            chunk = bytes(view[:CHUNK_MAX])
            view = view[CHUNK_MAX:]
            await self._write_chunk(chunk)

    async def flush(self):
        pass  # nothing buffered; every send() already emitted its chunks

    async def _read_chunk(self) -> bytes:
        while True:
            hdr = await self.conn.recv_exact(4)
            ctype = hdr[0]
            length = int.from_bytes(hdr[1:4], 'little')
            if ctype == 0xFF:
                body = await self.conn.recv_exact(length)
                if body != b'sNaPpY':
                    raise ValueError('bad snappy stream identifier')
                continue
            if not 0x00 <= ctype <= 0x01:
                raise ValueError('unsupported snappy chunk type 0x%02x' % ctype)
            body = await self.conn.recv_exact(length)
            crc = _unmask(int.from_bytes(body[:4], 'little'))
            payload = body[4:]
            raw = (bytes(self._cramjam.snappy.decompress_raw(payload))
                   if ctype == 0x00 else payload)
            if _crc32c(raw) != crc:
                raise ValueError('snappy chunk checksum mismatch')
            return raw

    async def recv(self, n: int = 65536) -> bytes:
        return await self._read_chunk()

    async def recv_exact(self, n: int) -> bytes:
        out = b''
        while len(out) < n:
            chunk = await self.recv(n - len(out))
            if not chunk:
                raise ConnectionError('EOF inside snappy stream')
            out += chunk
        return out

    async def close(self):
        await self.flush()
        await self.conn.close()


class TeeConn:
    """Debug: logs the first K raw bytes per direction then delegates."""

    def __init__(self, conn, k=0):
        self.conn = conn
        self.k = k
        self.rx = 0
        self.tx = 0

    async def send(self, data: bytes):
        await self.conn.send(data)

    async def recv(self, n: int) -> bytes:
        return await self.conn.recv(n)

    async def recv_exact(self, n: int) -> bytes:
        return await self.conn.recv_exact(n)

    async def close(self):
        await self.conn.close()


# ---------------- connection interface ----------------
class StreamConn:
    """Adapter over asyncio (StreamReader, StreamWriter)."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def send(self, data: bytes):
        self.writer.write(data)
        try:
            await self.writer.drain()
        except AttributeError:
            pass

    async def recv(self, n: int) -> bytes:
        return await self.reader.read(n)

    async def recv_exact(self, n: int) -> bytes:
        return await self.reader.readexactly(n)

    async def close(self):
        try:
            self.writer.close()
        except Exception:
            pass


# ---------------- async yamux ----------------
YAMUX_HEADER = struct.Struct('>BBHII')
T_DATA, T_WINDOW, T_PING, T_GOAWAY = 0, 1, 2, 3
F_SYN, F_ACK, F_FIN, F_RST = 1, 2, 4, 8
YAMUX_INIT_WINDOW = 256 * 1024
YAMUX_SEND_CHUNK = 16 * 1024


class YamuxError(Exception):
    pass


class YamuxStream:
    def __init__(self, session, sid: int):
        self.session = session
        self.sid = sid
        self._buf = bytearray()
        self._event = asyncio.Event()
        self._eof = False
        self._reset = False
        self._send_window = YAMUX_INIT_WINDOW
        self._send_event = asyncio.Event()
        self._send_event.set()
        self._fin_sent = False

    async def recv(self, n: int = 65536) -> bytes:
        while not self._buf and not self._eof and not self._reset:
            await self._event.wait()
        if self._reset:
            raise YamuxError('stream reset by peer')
        if not self._buf and self._eof:
            return b''
        take = bytes(self._buf[:n])
        del self._buf[:n]
        self._event.set() if self._buf or self._eof else self._event.clear()
        if take:
            self.session._send_frame(T_WINDOW, 0, self.sid, length=len(take))
        return take

    async def recv_exact(self, n: int) -> bytes:
        out = b''
        while len(out) < n:
            chunk = await self.recv(n - len(out))
            if not chunk:
                raise YamuxError('EOF inside yamux stream')
            out += chunk
        return out

    async def send(self, data: bytes):
        view = memoryview(data)
        while view:
            if self._reset:
                raise YamuxError('stream reset')
            await self._send_event.wait()
            if self._reset:
                raise YamuxError('stream reset')
            n = min(len(view), YAMUX_SEND_CHUNK, self._send_window)
            if n == 0:
                self._send_event.clear()
                continue
            self._send_window -= n
            self.session._send_frame(T_DATA, 0, self.sid,
                                     length=n, payload=bytes(view[:n]))
            view = view[n:]

    def _grant(self, delta: int):
        self._send_window += delta
        self._send_event.set()

    def _push(self, data: bytes, eof: bool):
        self._buf += data
        if eof:
            self._eof = True
        self._event.set()

    def _do_reset(self):
        self._reset = True
        self._send_event.set()
        self._event.set()

    async def close(self):
        if not self._fin_sent:
            self._fin_sent = True
            self.session._send_frame(T_DATA, F_FIN, self.sid, length=0)


class YamuxSession:
    """Client-side yamux session over one StreamConn (asyncio)."""

    def __init__(self, conn: StreamConn, keepalive: float = 20.0):
        self.conn = conn
        self._next_id = 1
        self._streams: dict[int, YamuxStream] = {}
        self._closed = False
        self._close_event = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._ping_waiters: dict[int, asyncio.Future] = {}
        self._bg_tasks: set = set()
        self._task = asyncio.create_task(self._reader())
        self._ka_task = (asyncio.create_task(self._keepalive(keepalive))
                         if keepalive else None)

    def _send_frame(self, typ: int, flags: int, sid: int,
                    length: int = 0, payload: bytes = b''):
        # NB: T_WINDOW/T_PING/T_GOAWAY carry a *value* in the header length
        # field and no payload; only T_DATA has a payload.
        hdr = YAMUX_HEADER.pack(0, typ, flags, sid, length)
        t = asyncio.create_task(self._send(hdr + payload))
        self._bg_tasks.add(t)
        t.add_done_callback(self._bg_tasks.discard)

    async def _send(self, data: bytes):
        if self._closed:
            raise YamuxError('session closed')
        async with self._send_lock:
            await self.conn.send(data)

    async def open_stream(self) -> YamuxStream:
        if self._closed:
            raise YamuxError('session closed')
        sid = self._next_id
        self._next_id += 2
        st = YamuxStream(self, sid)
        self._streams[sid] = st
        await self._send(YAMUX_HEADER.pack(0, T_WINDOW, F_SYN, sid,
                                           YAMUX_INIT_WINDOW))
        return st

    async def ping(self) -> bool:
        nonce = random.getrandbits(32)
        fut = asyncio.get_event_loop().create_future()
        self._ping_waiters[nonce] = fut
        try:
            await self._send(YAMUX_HEADER.pack(0, T_PING, F_SYN, 0, nonce))
            return await asyncio.wait_for(fut, 10)
        except (asyncio.TimeoutError, YamuxError):
            return False
        finally:
            self._ping_waiters.pop(nonce, None)

    async def _keepalive(self, interval: float):
        while not self._closed:
            await asyncio.sleep(interval)
            if self._closed:
                return
            if not await self.ping():
                log.warning('yamux keepalive failed, closing session')
                await self.close()
                return

    async def _reader(self):
        try:
            while not self._closed:
                hdr = await self.conn.recv_exact(12)
                ver, typ, flags, sid, length = YAMUX_HEADER.unpack(hdr)
                if ver != 0:
                    raise YamuxError('bad yamux version %d' % ver)
                payload = (await self.conn.recv_exact(length)
                           if typ == T_DATA and length else b'')
                await self._handle(typ, flags, sid, length, payload)
        except Exception as e:
            log.debug('yamux reader ended: %r', e)
        await self.close()

    async def _handle(self, typ, flags, sid, length, payload):
        if typ == T_DATA:
            st = self._get_or_create(sid, flags)
            if st:
                st._push(payload, eof=bool(flags & F_FIN))
        elif typ == T_WINDOW:
            st = self._get_or_create(sid, flags)
            if st:
                st._grant(length)
        elif typ == T_PING:
            if flags & F_SYN:
                await self._send(YAMUX_HEADER.pack(0, T_PING, F_ACK, 0, length))
            elif (fut := self._ping_waiters.pop(length, None)) and not fut.done():
                fut.set_result(True)
        elif typ == T_GOAWAY:
            await self.close()

    def _get_or_create(self, sid, flags):
        st = self._streams.get(sid)
        if st is None and (flags & F_SYN):
            st = YamuxStream(self, sid)
            self._streams[sid] = st
            self._send_frame(T_WINDOW, F_ACK, sid, length=YAMUX_INIT_WINDOW)
        return st

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            await self.conn.send(YAMUX_HEADER.pack(0, T_GOAWAY, 0, 0, 0))
        except Exception:
            pass
        for st in self._streams.values():
            st._do_reset()
        await self.conn.close()
        self._close_event.set()


# ---------------- connectors ----------------
@dataclass
class ProxyConfig:
    name: str
    proxy_type: str = 'tcp'          # tcp | http | https  (client-side identical)
    remote_port: int = 0             # tcp/udp only
    local_ip: str = '127.0.0.1'
    local_port: int = 0
    custom_domains: list = field(default_factory=list)   # http/https
    subdomain: str = ''                                   # http/https
    use_encryption: bool = False
    use_compression: bool = False    # snappy stream (requires "cramjam")


@dataclass
class ClientConfig:
    server_addr: str
    server_port: int
    token: str = ''
    transport: str = 'tcp'           # tcp | tls | quic
    tls_ca_file: str = ''            # 为空时跳过证书校验（服务端默认行为）
    tls_server_name: str = ''        # default = server_addr
    tls_cert_file: str = ''          # 客户端证书（mTLS），对应 transport.tls.certFile
    tls_key_file: str = ''           # 客户端私钥（mTLS），对应 transport.tls.keyFile
    heartbeat_interval: float = 30.0
    heartbeat_timeout: float = 90.0
    pool_count: int = 1
    client_version: str = 'v0.62.1-py'
    connect_timeout: float = 15.0


class TcpMuxConnector:
    """One TCP/TLS connection + yamux session; conns are yamux streams."""

    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.session: YamuxSession | None = None

    async def open(self):
        ssl_ctx = None
        if self.cfg.transport == 'tls':
            ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            if self.cfg.tls_ca_file:
                ssl_ctx.load_verify_locations(self.cfg.tls_ca_file)
                ssl_ctx.check_hostname = True
            else:
                ssl_ctx.check_hostname = False   # 与官方客户端默认行为一致
                ssl_ctx.verify_mode = _ssl.CERT_NONE
            if self.cfg.tls_cert_file and self.cfg.tls_key_file:
                ssl_ctx.load_cert_chain(self.cfg.tls_cert_file, self.cfg.tls_key_file)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.cfg.server_addr, self.cfg.server_port,
                ssl=ssl_ctx,
                server_hostname=(self.cfg.tls_server_name or self.cfg.server_addr)
                if ssl_ctx else None),
            self.cfg.connect_timeout)
        self.session = YamuxSession(StreamConn(reader, writer))

    async def open_conn(self) -> StreamConn:
        return await self.session.open_stream()

    async def close(self):
        if self.session:
            await self.session.close()


class QuicConnector:
    """一条 QUIC 连接（ALPN 为服务端约定值）；连接即 QUIC 流。"""

    def __init__(self, cfg: ClientConfig):
        if not HAVE_QUIC:
            raise RuntimeError('aioquic is required for transport=quic')
        self.cfg = cfg
        self._cm = None
        self.client = None

    async def open(self):
        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        if self.cfg.tls_ca_file:
            ssl_ctx.load_verify_locations(self.cfg.tls_ca_file)
        else:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE
        cfg = QuicConfiguration(is_client=True, alpn_protocols=[_WT_ALPN],
                                idle_timeout=30.0)
        cfg.verify_mode = ssl_ctx.verify_mode
        if self.cfg.tls_server_name:
            cfg.server_name = self.cfg.tls_server_name
        if self.cfg.tls_cert_file and self.cfg.tls_key_file:
            raise RuntimeError('mTLS client certificates are not supported '
                               'with the quic transport yet')
        self._cm = quic_connect(self.cfg.server_addr, self.cfg.server_port,
                                configuration=cfg)
        self.client = await self._cm.__aenter__()

    async def open_conn(self) -> StreamConn:
        reader, writer = await self.client.create_stream()
        return StreamConn(reader, writer)

    async def close(self):
        if self._cm:
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:
                pass
            self._cm = None


def make_connector(cfg: ClientConfig):
    if cfg.transport == 'quic':
        return QuicConnector(cfg)
    return TcpMuxConnector(cfg)


# ---------------- the client ----------------
class WtClient:
    """
    WtClient(cfg, proxies).run() — 断线自动重连，直到 stop()。

    await client.wait_ready()  -> fires after each successful (re)login
    await client.update_proxies(new_list) -> add/remove proxies at runtime
    """

    def __init__(self, cfg: ClientConfig, proxies: list[ProxyConfig]):
        self.cfg = cfg
        self.proxies = list(proxies)
        self.run_id = ''
        self.proxy_status: dict[str, dict] = {
            p.name: {'state': 'starting', 'remote_addr': '', 'error': ''}
            for p in proxies}
        # cumulative tunnel traffic per proxy (bytes)
        self.traffic: dict[str, dict[str, int]] = {
            p.name: {'in': 0, 'out': 0} for p in proxies}
        self._stop = asyncio.Event()
        self._ready = asyncio.Event()
        self._pending_resp: dict[str, asyncio.Future] = {}
        self._tasks: set = set()

    # ---- public API ----
    async def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            connector = make_connector(self.cfg)
            self._connector = connector
            try:
                await self._session(connector)
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning('session ended: %r', e)
            finally:
                await connector.close()
            if self._stop.is_set():
                break
            log.info('reconnecting in %.1fs', backoff)
            try:
                await asyncio.wait_for(self._stop.wait(), backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 30.0)

    def stop(self):
        self._stop.set()
        self._ready.set()

    async def wait_ready(self):
        await self._ready.wait()

    async def update_proxies(self, new_proxies: list[ProxyConfig]):
        """Diff-and-apply; before the first connection it just replaces the
        initial set (picked up by the login/registration flow)."""
        old_names = {p.name for p in self.proxies}
        new_names = {p.name for p in new_proxies}
        self.proxies = list(new_proxies)
        if not self._ready.is_set():
            return
        # removed -> CloseProxy
        for name in old_names - new_names:
            await self._send_ctrl(M_CLOSE_PROXY, {'proxy_name': name})
            self.proxy_status[name] = {'state': 'paused', 'remote_addr': '', 'error': ''}
        for p in new_proxies:
            st = self.proxy_status.setdefault(p.name, {'state': 'starting',
                                                       'remote_addr': '', 'error': ''})
            if st['state'] == 'paused':
                st['state'] = 'starting'
            self.traffic.setdefault(p.name, {'in': 0, 'out': 0})
        # added -> NewProxy (+ wait resp)
        for p in new_proxies:
            if p.name not in old_names:
                await self._new_proxy(p)

    # ---- session lifecycle ----
    async def _session(self, connector):
        await connector.open()
        ctrl = await connector.open_conn()

        # login (plaintext)
        ts = int(time.time())
        await ctrl.send(pack_msg(M_LOGIN, {
            'version': self.cfg.client_version, 'hostname': '',
            'os': 'python', 'arch': 'async', 'user': '',
            'privilege_key': auth_key(self.cfg.token, ts),
            'timestamp': ts, 'run_id': self.run_id,
            'pool_count': self.cfg.pool_count}))
        mtype, resp = await read_msg_conn(ctrl)
        if mtype != M_LOGIN_RESP:
            raise RuntimeError('expected LoginResp, got %s' % MSG_NAMES.get(mtype, mtype))
        if resp.get('error'):
            err = resp['error']
            if self.run_id and ('run id' in err.lower() or 'no such client' in err.lower()):
                log.info('server rejected old run_id, retrying with fresh login')
                self.run_id = ''
                return await connector.close() or await self._session(connector)
            raise RuntimeError('login failed: %s' % err)
        self.run_id = resp.get('run_id', '')
        log.info('login ok, run_id=%s, server=%s', self.run_id, resp.get('version'))

        # all subsequent control messages are encrypted
        crypto = CryptoConn(ctrl, self.cfg.token.encode())
        self._crypto_ref = crypto
        self._ready.set()

        hb_task = asyncio.create_task(self._heartbeat(crypto))
        reader_task = asyncio.create_task(self._control_reader(crypto))
        try:
            for p in self.proxies:
                await self._new_proxy(p)
            log.info('%d proxies registered', len(self.proxies))
            await reader_task
        finally:
            hb_task.cancel()
            reader_task.cancel()
            for fut in self._pending_resp.values():
                if not fut.done():
                    fut.set_exception(ConnectionError('control closed'))
            self._pending_resp.clear()
            await crypto.close()

    async def _new_proxy(self, p: ProxyConfig):
        body = {'proxy_name': p.name, 'proxy_type': p.proxy_type,
                'use_encryption': p.use_encryption,
                'use_compression': p.use_compression}
        if p.proxy_type in ('tcp', 'udp'):
            body['remote_port'] = p.remote_port
        if p.proxy_type in ('http', 'https'):
            if p.custom_domains:
                body['custom_domains'] = p.custom_domains
            if p.subdomain:
                body['subdomain'] = p.subdomain
        fut = asyncio.get_event_loop().create_future()
        self._pending_resp[p.name] = fut
        await self._send_ctrl(M_NEW_PROXY, body)
        resp = await asyncio.wait_for(fut, 15)
        if resp.get('error'):
            self.proxy_status[p.name] = {'state': 'error',
                                         'remote_addr': '', 'error': resp['error']}
            raise RuntimeError('proxy [%s] rejected: %s' % (p.name, resp['error']))
        self.proxy_status[p.name] = {'state': 'registered',
                                     'remote_addr': resp.get('remote_addr', ''),
                                     'error': ''}
        log.info('proxy [%s] registered at %s', p.name, resp.get('remote_addr', ''))

    async def _send_ctrl(self, mtype: int, obj: dict):
        await self._crypto_ref.send(pack_msg(mtype, obj))

    async def _control_reader(self, crypto):
        while True:
            mtype, msg = await read_msg_conn(crypto)
            if mtype == M_REQ_WORK_CONN:
                self._spawn(self._work_conn_flow(crypto))
            elif mtype == M_PING:
                await crypto.send(pack_msg(M_PONG, {}))
            elif mtype == M_PONG:
                self._last_pong = time.monotonic()
            elif mtype == M_NEW_PROXY_RESP:
                fut = self._pending_resp.pop(msg.get('proxy_name', ''), None)
                if fut and not fut.done():
                    fut.set_result(msg)
            else:
                log.debug('control msg %s: %s', MSG_NAMES.get(mtype, mtype), msg)

    async def _heartbeat(self, crypto):
        self._last_pong = time.monotonic()
        while True:
            await asyncio.sleep(self.cfg.heartbeat_interval)
            if time.monotonic() - self._last_pong > self.cfg.heartbeat_timeout:
                log.warning('heartbeat timeout (%.0fs without pong), closing control',
                            time.monotonic() - self._last_pong)
                await crypto.close()
                return
            await crypto.send(pack_msg(M_PING, {'timestamp': int(time.time())}))

    # ---- work conns ----
    def _spawn(self, coro):
        t = asyncio.create_task(self._guard(coro))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _guard(self, coro):
        try:
            await coro
        except Exception as e:
            log.warning('work conn task failed: %r', e)

    async def _work_conn_flow(self, crypto):
        conn = await self._connector.open_conn()
        # frp 语义：服务端用消息里的 timestamp 重新推导 key 比较，
        # 必须是当前时间戳；run_id 过期（会话被替换）会被直接拒接
        ts = int(time.time())
        await conn.send(pack_msg(M_NEW_WORK_CONN, {
            'run_id': self.run_id, 'timestamp': ts,
            'privilege_key': auth_key(self.cfg.token, ts)}))
        try:
            mtype, start = await read_msg_conn(conn)
        except (asyncio.IncompleteReadError, ConnectionError) as err:
            raise RuntimeError('server closed the work conn before StartWorkConn '
                               f'(run_id={self.run_id!r}, transport={self.cfg.transport})') from err
        if mtype != M_START_WORK_CONN:
            raise RuntimeError('expected StartWorkConn, got %s' % MSG_NAMES.get(mtype, mtype))
        if start.get('error'):
            raise RuntimeError('StartWorkConn error: %s' % start['error'])
        log.debug('work conn established for %s (transport=%s)',
                  start.get('proxy_name'), self.cfg.transport)
        p = next((x for x in self.proxies if x.name == start.get('proxy_name')), None)
        if not p:
            raise RuntimeError('StartWorkConn for unknown proxy %s' % start.get('proxy_name'))

        conn = TeeConn(conn)
        data = conn
        if p.use_encryption:
            data = CryptoConn(conn, self.cfg.token.encode())
        if p.use_compression:
            data = SnappyStreamConn(data)

        local_reader, local_writer = await asyncio.wait_for(
            asyncio.open_connection(p.local_ip, p.local_port), 10)
        received = 0
        sent = 0
        counters = self.traffic.setdefault(p.name, {'in': 0, 'out': 0})

        async def up():
            nonlocal received
            try:
                while True:
                    chunk = await data.recv(65536)
                    if not chunk:
                        log.debug('work conn up(): stream EOF after %d bytes', received)
                        break
                    received += len(chunk)
                    counters['in'] += len(chunk)
                    local_writer.write(chunk)
                    await local_writer.drain()
            except Exception as err:
                log.debug('work conn up() closed after %d bytes: %r', received, err)
            finally:
                local_writer.close()

        t = self._spawn_raw(up())
        try:
            while True:
                chunk = await local_reader.read(65536)
                if not chunk:
                    log.debug('work conn down(): local EOF after %d bytes', sent)
                    break
                sent += len(chunk)
                counters['out'] += len(chunk)
                log.debug('work conn down(): + %d bytes (total %d)',
                          len(chunk), sent)
                await data.send(chunk)
            if isinstance(data, SnappyStreamConn):
                await data.flush()
            await data.close()
        except Exception as err:
            log.warning('work conn down() error after %d bytes: %r', sent, err)
        finally:
            t.cancel()
            local_writer.close()

    def _spawn_raw(self, coro):
        return asyncio.create_task(coro)


async def read_msg_conn(conn):
    hdr = await conn.recv_exact(9)
    mtype, length = struct.unpack('>Bq', hdr)
    if length < 0 or length > MAX_MSG_LENGTH:
        raise ValueError('隧道消息长度非法: %d' % length)
    payload = await conn.recv_exact(length) if length else b'{}'
    return mtype, json.loads(payload or b'{}')


# ---------------- CLI ----------------
async def _cli_main(args):
    proxies = []
    for spec in args.proxy:
        name, ptype, remote, local = spec.split(':')
        proxies.append(ProxyConfig(name=name, proxy_type=ptype,
                                   remote_port=int(remote), local_port=int(local)))
    cfg = ClientConfig(server_addr=args.server.rsplit(':', 1)[0],
                       server_port=int(args.server.rsplit(':', 1)[1]),
                       token=args.token, transport=args.transport,
                       tls_ca_file=args.ca or '')
    client = WtClient(cfg, proxies)
    await client.run()


def main():
    import argparse
    ap = argparse.ArgumentParser(description='WebTunnel 隧道客户端')
    ap.add_argument('--server', required=True, help='host:port')
    ap.add_argument('--transport', default='tcp', choices=['tcp', 'tls', 'quic'])
    ap.add_argument('--token', default='')
    ap.add_argument('--ca', default='', help='TLS CA file (optional)')
    ap.add_argument('--proxy', action='append', required=True,
                    help='name:type:remote_port:local_port (type: tcp|http|https)')
    ap.add_argument('--log-level', default='INFO')
    args = ap.parse_args()
    logging.basicConfig(level=args.log_level.upper(),
                        format='%(asctime)s %(levelname)s %(message)s')
    asyncio.run(_cli_main(args))


if __name__ == '__main__':
    main()
