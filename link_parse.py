"""分享链接 -> xray outbound 配置。协议解析较啰嗦，单独放这里，主流程不掺和。"""
from __future__ import annotations
import base64
import json
import urllib.parse

def parse_outbound(link: str) -> dict | None:
    try:
        if link.startswith("vmess://"):
            raw = link[8:]
            pad = "=" * (-len(raw) % 4)
            cfg = json.loads(base64.b64decode(raw + pad))
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
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [
                                {
                                    "id": uuid,
                                    "alterId": int(cfg.get("aid") or 0),
                                    "security": cfg.get("scy") or "auto",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream,
            }
        if link.startswith("vless://"):
            u = urllib.parse.urlparse(link)
            uuid = urllib.parse.unquote(u.username or "")
            host = u.hostname
            port = u.port or 443
            q = urllib.parse.parse_qs(u.query)
            if not uuid or not host:
                return None
            net = (q.get("type") or ["tcp"])[0]
            security = (q.get("security") or ["none"])[0]
            stream = {"network": net, "security": security}
            if net == "ws":
                stream["wsSettings"] = {
                    "path": (q.get("path") or ["/"])[0],
                    "headers": {"Host": (q.get("host") or [host])[0]},
                }
            if security in ("tls", "reality"):
                key = "tlsSettings" if security == "tls" else "realitySettings"
                stream[key] = {
                    "serverName": (q.get("sni") or [host])[0],
                    "fingerprint": (q.get("fp") or ["chrome"])[0],
                }
                if security == "reality":
                    stream[key]["publicKey"] = (q.get("pbk") or [""])[0]
                    stream[key]["shortId"] = (q.get("sid") or [""])[0]
            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [
                                {
                                    "id": uuid,
                                    "encryption": "none",
                                    "flow": (q.get("flow") or [""])[0],
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream,
            }
        if link.startswith("trojan://"):
            u = urllib.parse.urlparse(link)
            password = urllib.parse.unquote(u.username or "")
            host = u.hostname
            port = u.port or 443
            q = urllib.parse.parse_qs(u.query)
            if not password or not host:
                return None
            net = (q.get("type") or ["tcp"])[0]
            stream = {"network": net, "security": "tls", "tlsSettings": {"serverName": (q.get("sni") or [host])[0], "allowInsecure": True}}
            if net == "ws":
                stream["wsSettings"] = {
                    "path": (q.get("path") or ["/"])[0],
                    "headers": {"Host": (q.get("host") or [host])[0]},
                }
            return {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": password}]},
                "streamSettings": stream,
            }
        if link.startswith("ss://"):
            rest = link[5:]
            if "#" in rest:
                rest = rest.split("#", 1)[0]
            if "@" not in rest:
                pad = "=" * (-len(rest) % 4)
                rest = base64.b64decode(rest + pad).decode() + "@IGNORE"
                # format method:pass@host:port after decode sometimes
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
                pad = "=" * (-len(userinfo) % 4)
                dec = base64.b64decode(userinfo + pad).decode()
                method, password = dec.split(":", 1)
            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": port,
                            "method": method,
                            "password": password,
                        }
                    ]
                },
            }
    except Exception:
        return None
    return None

