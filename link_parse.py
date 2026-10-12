"""分享链接 -> {engine, outbound}。engine=xray|sing-box；无法运行返回 None。"""
from __future__ import annotations

import base64
import json
import urllib.parse

# https:// 里常见噪声（仓库/电报链接），不是代理
_NOISE_HOST = (
    "github.com", "www.github.com", "raw.githubusercontent.com",
    "t.me", "telegram.me", "www.telegram.me",
)


def _b64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.b64decode(s + pad)


def _q(q: dict, *keys: str, default: str = "") -> str:
    for k in keys:
        v = q.get(k)
        if v and v[0] != "":
            return v[0]
    return default


def _truthy(s: str) -> bool:
    return s.lower() in ("1", "true", "yes", "on")


def _tls_sb(sni: str, insecure: bool = True, alpn: list[str] | None = None, fp: str = "") -> dict:
    t: dict = {
        "enabled": True,
        "server_name": sni,
        "insecure": insecure,
    }
    if alpn:
        t["alpn"] = alpn
    if fp:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    return t


def _vmess(link: str) -> dict | None:
    raw = link[8:]
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    cfg = json.loads(_b64(raw))
    host = cfg.get("add") or cfg.get("host")
    port = int(cfg.get("port", 0))
    uuid = cfg.get("id")
    if not host or not port or not uuid:
        return None
    net = cfg.get("net") or "tcp"
    tls = cfg.get("tls") or ""
    stream: dict = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {
            "path": cfg.get("path") or "/",
            "headers": {"Host": cfg.get("host") or host},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": cfg.get("path") or ""}
    if tls == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": cfg.get("sni") or cfg.get("host") or host,
            "allowInsecure": True,
        }
    else:
        stream["security"] = "none"
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host, "port": port,
                "users": [{
                    "id": uuid,
                    "alterId": int(cfg.get("aid") or 0),
                    "security": cfg.get("scy") or "auto",
                }],
            }]
        },
        "streamSettings": stream,
    }


def _vless(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    uuid = urllib.parse.unquote(u.username or "")
    host, port = u.hostname, u.port or 443
    q = urllib.parse.parse_qs(u.query)
    if not uuid or not host:
        return None
    net = _q(q, "type", default="tcp")
    security = _q(q, "security", default="none")
    stream: dict = {"network": net, "security": security}
    if net == "ws":
        stream["wsSettings"] = {
            "path": _q(q, "path", default="/"),
            "headers": {"Host": _q(q, "host", default=host)},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": _q(q, "serviceName", "path")}
    if security in ("tls", "reality"):
        key = "tlsSettings" if security == "tls" else "realitySettings"
        stream[key] = {
            "serverName": _q(q, "sni", default=host),
            "fingerprint": _q(q, "fp", default="chrome"),
        }
        if security == "reality":
            stream[key]["publicKey"] = _q(q, "pbk")
            stream[key]["shortId"] = _q(q, "sid")
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host, "port": port,
                "users": [{
                    "id": uuid, "encryption": "none",
                    "flow": _q(q, "flow"),
                }],
            }]
        },
        "streamSettings": stream,
    }


def _trojan(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    password = urllib.parse.unquote(u.username or "")
    host, port = u.hostname, u.port or 443
    q = urllib.parse.parse_qs(u.query)
    if not password or not host:
        return None
    net = _q(q, "type", default="tcp")
    stream: dict = {
        "network": net, "security": "tls",
        "tlsSettings": {
            "serverName": _q(q, "sni", default=host),
            "allowInsecure": True,
        },
    }
    if net == "ws":
        stream["wsSettings"] = {
            "path": _q(q, "path", default="/"),
            "headers": {"Host": _q(q, "host", default=host)},
        }
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": stream,
    }


def _ss(link: str) -> dict | None:
    rest = link[5:]
    if "#" in rest:
        rest = rest.split("#", 1)[0]
    if "@" not in rest:
        try:
            rest = _b64(rest).decode()
        except Exception:
            return None
        if "@" not in rest:
            return None
    userinfo, hostport = rest.rsplit("@", 1)
    if ":" not in hostport:
        return None
    host, port_s = hostport.rsplit(":", 1)
    port = int(port_s)
    if ":" in userinfo and not userinfo.startswith("ey"):
        method, password = userinfo.split(":", 1)
        password = urllib.parse.unquote(password)
    else:
        dec = _b64(userinfo).decode()
        method, password = dec.split(":", 1)
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host, "port": port,
                "method": method, "password": password,
            }]
        },
    }


def _socks(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    host, port = u.hostname, u.port or 1080
    if not host:
        return None
    users = []
    user = urllib.parse.unquote(u.username or "")
    pwd = urllib.parse.unquote(u.password or "")
    # 有的写成 socks://base64(user:pass)@host:port
    if user and not pwd and ":" not in user:
        try:
            dec = _b64(user).decode()
            if ":" in dec:
                user, pwd = dec.split(":", 1)
        except Exception:
            pass
    if user:
        users = [{"user": user, "pass": pwd}]
    return {
        "protocol": "socks",
        "settings": {
            "servers": [{
                "address": host, "port": port,
                **({"users": users} if users else {}),
            }]
        },
    }


def _http_xray(link: str) -> dict | None:
    """http:// 或 https:// 代理；噪声域名直接丢。"""
    u = urllib.parse.urlparse(link)
    host, port = u.hostname, u.port
    if not host or host.lower() in _NOISE_HOST:
        return None
    if port is None:
        port = 443 if u.scheme == "https" else 80
    users = []
    user = urllib.parse.unquote(u.username or "")
    pwd = urllib.parse.unquote(u.password or "")
    if user:
        users = [{"user": user, "pass": pwd}]
    ob: dict = {
        "protocol": "http",
        "settings": {
            "servers": [{
                "address": host, "port": int(port),
                **({"users": users} if users else {}),
            }]
        },
    }
    q = urllib.parse.parse_qs(u.query)
    if u.scheme == "https" or _truthy(_q(q, "tls")):
        ob["streamSettings"] = {
            "security": "tls",
            "tlsSettings": {
                "serverName": _q(q, "sni", default=host),
                "allowInsecure": True,
            },
        }
    return ob


def _wireguard(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    secret = urllib.parse.unquote(u.username or "")
    host, port = u.hostname, u.port or 51820
    q = urllib.parse.parse_qs(u.query)
    pub = _q(q, "publickey", "publicKey", "peer_public_key")
    if not secret or not host or not pub:
        return None
    addr = _q(q, "address", "local_address", default="172.16.0.2/32")
    addresses = [a.strip() for a in addr.split(",") if a.strip()]
    reserved_s = _q(q, "reserved")
    reserved = None
    if reserved_s:
        try:
            reserved = [int(x.strip()) for x in reserved_s.split(",")]
        except Exception:
            reserved = None
    settings: dict = {
        "secretKey": secret,
        "address": addresses,
        "peers": [{
            "publicKey": pub,
            "endpoint": f"{host}:{port}",
            "keepAlive": 25,
        }],
    }
    mtu = _q(q, "mtu")
    if mtu:
        settings["mtu"] = int(mtu)
    if reserved and len(reserved) == 3:
        settings["reserved"] = reserved
    return {"protocol": "wireguard", "settings": settings}


def _hy2(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    password = urllib.parse.unquote(u.username or "")
    host, port = u.hostname, u.port or 443
    q = urllib.parse.parse_qs(u.query)
    if not password or not host:
        return None
    ob: dict = {
        "type": "hysteria2",
        "server": host,
        "server_port": int(port),
        "password": password,
        "tls": _tls_sb(
            _q(q, "sni", default=host),
            insecure=_truthy(_q(q, "insecure", "allowInsecure", default="1")),
        ),
    }
    up, down = _q(q, "upmbps", "up"), _q(q, "downmbps", "down")
    if up:
        ob["up_mbps"] = int(float(up))
    if down:
        ob["down_mbps"] = int(float(down))
    obfs = _q(q, "obfs")
    op = _q(q, "obfs-password", "obfs_password")
    if obfs and op:
        ob["obfs"] = {"type": obfs, "password": op}
    return ob


def _hy1(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    host, port = u.hostname, u.port or 443
    q = urllib.parse.parse_qs(u.query)
    if not host:
        return None
    auth = _q(q, "auth", "auth_str")
    if not auth and u.username:
        auth = urllib.parse.unquote(u.username)
    ob: dict = {
        "type": "hysteria",
        "server": host,
        "server_port": int(port),
        "up_mbps": int(float(_q(q, "upmbps", "up", default="20"))),
        "down_mbps": int(float(_q(q, "downmbps", "down", default="100"))),
        "tls": _tls_sb(
            _q(q, "sni", "peer", default=host),
            insecure=_truthy(_q(q, "insecure", "allowInsecure", default="1")),
            alpn=[_q(q, "alpn", default="h3")] if _q(q, "alpn", default="h3") else None,
        ),
    }
    if auth:
        ob["auth_str"] = auth
    obfs = _q(q, "obfs")
    if obfs:
        ob["obfs"] = obfs
    mport = _q(q, "mport")
    if mport and ":" in mport:
        # sing-box server_ports 形如 ["6000:21000"]
        ob["server_ports"] = [mport.replace("-", ":")]
        ob.pop("server_port", None)
    return ob


def _tuic(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    uuid = urllib.parse.unquote(u.username or "")
    password = urllib.parse.unquote(u.password or "")
    host, port = u.hostname, u.port or 443
    q = urllib.parse.parse_qs(u.query)
    if not uuid or not host:
        return None
    alpn_s = _q(q, "alpn", default="h3")
    return {
        "type": "tuic",
        "server": host,
        "server_port": int(port),
        "uuid": uuid,
        "password": password,
        "congestion_control": _q(q, "congestion_control", default="bbr"),
        "udp_relay_mode": _q(q, "udp_relay_mode", default="native"),
        "tls": _tls_sb(
            _q(q, "sni", default=host),
            insecure=_truthy(_q(q, "insecure", "allowInsecure", default="1")),
            alpn=[x.strip() for x in alpn_s.split(",") if x.strip()],
        ),
    }


def _anytls(link: str) -> dict | None:
    u = urllib.parse.urlparse(link)
    password = urllib.parse.unquote(u.username or "")
    host, port = u.hostname, u.port or 443
    q = urllib.parse.parse_qs(u.query)
    if not password or not host:
        return None
    return {
        "type": "anytls",
        "server": host,
        "server_port": int(port),
        "password": password,
        "tls": _tls_sb(
            _q(q, "sni", default=host),
            insecure=_truthy(_q(q, "insecure", "allowInsecure", default="1")),
            fp=_q(q, "fp", default="chrome"),
        ),
    }


def parse_link(link: str) -> dict | None:
    """返回 {"engine": "xray"|"sing-box", "outbound": ...}；ssr/噪声等返回 None。"""
    try:
        s = link.strip()
        if "crypto.cloudflare.com" in s:
            return None
        if s.startswith("vmess://"):
            ob = _vmess(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith("vless://"):
            ob = _vless(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith("trojan://"):
            ob = _trojan(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith("ss://"):
            ob = _ss(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith(("socks://", "socks5://")):
            ob = _socks(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith(("http://", "https://")):
            ob = _http_xray(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith("wireguard://"):
            ob = _wireguard(s)
            return {"engine": "xray", "outbound": ob} if ob else None
        if s.startswith(("hysteria2://", "hy2://")):
            ob = _hy2(s)
            return {"engine": "sing-box", "outbound": ob} if ob else None
        if s.startswith("hysteria://"):
            ob = _hy1(s)
            return {"engine": "sing-box", "outbound": ob} if ob else None
        if s.startswith("tuic://"):
            ob = _tuic(s)
            return {"engine": "sing-box", "outbound": ob} if ob else None
        if s.startswith("anytls://"):
            ob = _anytls(s)
            return {"engine": "sing-box", "outbound": ob} if ob else None
        if s.startswith("ssr://"):
            # xray / sing-box 都无 SSR 出站，仅识别不运行
            return None
    except Exception:
        return None
    return None


def parse_outbound(link: str) -> dict | None:
    """兼容旧代码：只返回 xray outbound。"""
    r = parse_link(link)
    if r and r["engine"] == "xray":
        return r["outbound"]
    return None
