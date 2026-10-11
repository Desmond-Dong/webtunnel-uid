"""Constants for the WebTunnel integration."""

DOMAIN = "webtunnel_uid"

# 与官方客户端保持一致的版本号（握手/心跳上报用，勿写死到其它文件）
OFFICIAL_VERSION = "vs.261010"

CONF_BASE_URL = "base_url"
CONF_MODE = "mode"
CONF_UID = "uid"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_CHANNEL_ID = "channel_id"
CONF_NAME = "name"
CONF_LOCAL_PORT = "local_port"
CONF_LOCAL_IP = "local_ip"
CONF_CONN_TYPE = "conn_type"
CONF_REMOTE_PORT = "remote_port"
CONF_WEB_PROTOCOL = "web_protocol"
CONF_WEB_DOMAIN = "web_domain"
CONF_WEB_SLD = "web_sld"

MODE_PASSWORD = "password"
MODE_UID = "uid"

# 配置条目下的子条目：一条通过 HA 创建的通道
SUBENTRY_TYPE_CHANNEL = "channel"
SUBENTRY_TYPE_BASIC = "basic"

# 通道创建：只做 web 通道，公网访问固定 https
CONF_PROXY_CHANNEL = "proxy_channel"
DEFAULT_WEB_DOMAIN = "pgrm.cc"
FALLBACK_WEB_DOMAINS = ["pgrm.cc", "pgrm.site", "pgrm.top", "pgrm.run"]
DEFAULT_LOCAL_PORT = 80

DEFAULT_BASE_URL = "https://w.pgrm.top"

# Aligned with the official client (HEARTBEAT_INTERVAL = 30s, not configurable).
CLOUD_HEARTBEAT_INTERVAL = 30
DEFAULT_SCAN_INTERVAL = CLOUD_HEARTBEAT_INTERVAL

ENDPOINT_LOGIN = "/service/login/login4client"
ENDPOINT_HEARTBEAT = "/service/client/heartbeat"
ENDPOINT_PROXY_DNS = "/service/client/proxy_channel_dns"

# 控制台登录（账号密码）：goCaptcha 图片点选验证码 + login4acct
ENDPOINT_CAPTCHA_GET = "/service/login/captcha/get"
ENDPOINT_CAPTCHA_CHECK = "/service/login/captcha/check"
ENDPOINT_LOGIN4ACCT = "/service/login/login4acct"
CONSOLE_FRONTEND_VERSION = "vj.261010"

# 控制台会话令牌（login4acct 返回，用于通道管理等控制台接口）
CONF_CONSOLE_TOKEN = "console_token"

# 控制台接口（通道管理/用户信息/流量）挂在云端的 /service 前缀下
CONSOLE_API_PREFIX = "/service"

# 隧道连接参数
TUNNEL_HEARTBEAT_INTERVAL = 30.0
TUNNEL_HEARTBEAT_TIMEOUT = 90.0

# channel states
STATE_OK = "ok"
STATE_STARTING = "starting"
STATE_ERROR = "error"
STATE_DISABLED = "disabled"      # disabled on the cloud side
STATE_PAUSED = "paused"          # paused locally via switch
STATE_UNSUPPORTED = "unsupported"
STATE_REMOTE = "remote"          # bound to another proxy host (monitor only)
