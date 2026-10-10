#!/usr/bin/env python3
"""Fetch share links, test via xray on Actions runner, persist good/failed sets."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB = DATA / "state.sqlite"
GOOD_TXT = DATA / "good_links.txt"
FAILED_TXT = DATA / "failed_links.txt"
TARGET = int(os.environ.get("TARGET_GOOD", "9999"))
PROBE_URL = os.environ.get("PROBE_URL", "http://43.130.11.12:917/917")
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "5"))
WORKERS_MAX = int(os.environ.get("WORKERS_MAX", "32"))
WORKERS_MIN = int(os.environ.get("WORKERS_MIN", "4"))

SUBSCRIBE_URLS = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/Special/Telegram.txt",
    "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/BeVpn.txt",
    "https://raw.githubusercontent.com/MrAbolfazlNorouzi/iran-configs/refs/heads/main/configs/working-configs.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/refs/heads/main/sub",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/v2",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
]

IP_URLS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ident.me",
]

LINK_RE = re.compile(r"(?:vmess|vless|trojan|ss)://[^\s<>\"']+")
_lock = threading.Lock()
_port_lock = threading.Lock()
_next_port = 20000


def log(msg: str) -> None:
    print(msg, flush=True)


def link_hash(link: str) -> str:
    return hashlib.sha256(link.strip().encode()).hexdigest()


def http_get(url: str, timeout: float = 20, proxy: str | None = None) -> bytes:
    # Direct fetches use urllib; proxied fetches must use curl (urllib needs PySocks for SOCKS).
    if not proxy:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    # proxy like socks5h://127.0.0.1:PORT
    hostport = proxy.split("://", 1)[-1]
    cmd = [
        "curl", "-fsS", "--max-time", str(int(timeout)),
        "--socks5-hostname", hostport,
        "-A", "curl/8.0", url,
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="ignore")[:200] or f"curl exit {r.returncode}")
    return r.stdout


def maybe_b64_decode(text: str) -> str:
    s = "".join(text.split())
    if not s:
        return text
    try:
        pad = "=" * (-len(s) % 4)
        return base64.b64decode(s + pad).decode("utf-8", "ignore")
    except Exception:
        return text


def fetch_candidates() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    log(f"fetching {len(SUBSCRIBE_URLS)} subscribe urls")
    for url in SUBSCRIBE_URLS:
        try:
            raw = http_get(url, timeout=25).decode("utf-8", "ignore")
        except Exception as e:
            log(f"fetch fail {url}: {e}")
            continue
        body = maybe_b64_decode(raw) if "://" not in raw[:200] else raw
        if "://" not in body[:500]:
            body = maybe_b64_decode(raw)
        for m in LINK_RE.findall(body):
            link = m.strip().rstrip("\",'")
            if link not in seen:
                seen.add(link)
                out.append(link)
        log(f"fetched {url} total_unique={len(out)}")
    random.shuffle(out)
    return out


def db_connect() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS links(
            h TEXT PRIMARY KEY,
            link TEXT NOT NULL,
            status TEXT NOT NULL,
            exit_ip TEXT,
            updated_at REAL NOT NULL
        )"""
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ip ON links(exit_ip) WHERE exit_ip IS NOT NULL AND status='good'"
    )
    conn.commit()
    return conn


def load_txt_into_db(conn: sqlite3.Connection) -> None:
    now = time.time()
    for path, status in ((GOOD_TXT, "good"), (FAILED_TXT, "failed")):
        if not path.exists():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            link = line.strip()
            if not link or link.startswith("#"):
                continue
            h = link_hash(link)
            conn.execute(
                "INSERT OR IGNORE INTO links(h,link,status,exit_ip,updated_at) VALUES(?,?,?,?,?)",
                (h, link, status, None, now),
            )
    conn.commit()


def export_txt(conn: sqlite3.Connection) -> None:
    goods = [
        r[0]
        for r in conn.execute(
            "SELECT link FROM links WHERE status='good' ORDER BY updated_at"
        )
    ]
    fails = [
        r[0]
        for r in conn.execute(
            "SELECT link FROM links WHERE status='failed' ORDER BY updated_at"
        )
    ]
    GOOD_TXT.write_text("\n".join(goods) + ("\n" if goods else ""))
    FAILED_TXT.write_text("\n".join(fails) + ("\n" if fails else ""))


def alloc_port() -> int:
    global _next_port
    with _port_lock:
        p = _next_port
        _next_port += 1
        if _next_port > 45000:
            _next_port = 20000
        return p


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


def write_xray_cfg(path: Path, outbound: dict, socks_port: int) -> None:
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [outbound],
    }
    path.write_text(json.dumps(cfg))


def cpu_busy() -> float:
    try:
        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
        cpus = os.cpu_count() or 2
        return load1 / cpus
    except Exception:
        return 0.5


def get_exit_ip(proxy: str) -> str | None:
    for url in IP_URLS:
        try:
            ip = http_get(url, timeout=TIMEOUT, proxy=proxy).decode().strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                return ip
        except Exception:
            continue
    return None


def probe(link: str) -> tuple[str, str | None, str]:
    """returns status, exit_ip, reason"""
    outbound = parse_outbound(link)
    if not outbound:
        return "failed", None, "parse"
    socks_port = alloc_port()
    cfg_path = Path(f"/tmp/xray_{socks_port}.json")
    write_xray_cfg(cfg_path, outbound, socks_port)
    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-config", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.35)
        proxy = f"socks5h://127.0.0.1:{socks_port}"
        try:
            http_get(PROBE_URL, timeout=TIMEOUT, proxy=proxy)
        except Exception:
            return "failed", None, "917"
        ip = get_exit_ip(proxy)
        if not ip:
            return "failed", None, "ip"
        return "good", ip, "ok"
    finally:
        if proc and proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        try:
            cfg_path.unlink(missing_ok=True)
        except Exception:
            pass


def mark(conn: sqlite3.Connection, link: str, status: str, exit_ip: str | None) -> bool:
    """Return True if newly recorded as good."""
    h = link_hash(link)
    now = time.time()
    with _lock:
        if status == "good":
            if exit_ip:
                row = conn.execute(
                    "SELECT 1 FROM links WHERE exit_ip=? AND status='good'",
                    (exit_ip,),
                ).fetchone()
                if row:
                    conn.execute(
                        "INSERT OR REPLACE INTO links(h,link,status,exit_ip,updated_at) VALUES(?,?,?,?,?)",
                        (h, link, "failed", None, now),
                    )
                    conn.commit()
                    return False
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO links(h,link,status,exit_ip,updated_at) VALUES(?,?,?,?,?)",
                    (h, link, "good", exit_ip, now),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.execute(
                    "INSERT OR REPLACE INTO links(h,link,status,exit_ip,updated_at) VALUES(?,?,?,?,?)",
                    (h, link, "failed", None, now),
                )
                conn.commit()
                return False
        else:
            conn.execute(
                "INSERT OR REPLACE INTO links(h,link,status,exit_ip,updated_at) VALUES(?,?,?,?,?)",
                (h, link, "failed", None, now),
            )
            conn.commit()
            return False


def good_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM links WHERE status='good'").fetchone()[0]


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = db_connect()
    load_txt_into_db(conn)
    start_good = good_count(conn)
    log(f"start good={start_good} target={TARGET}")
    log(f"xray_bin={XRAY_BIN} probe={PROBE_URL} workers={WORKERS_MIN}-{WORKERS_MAX}")
    if start_good >= TARGET:
        log("already enough")
        export_txt(conn)
        return 0

    candidates = fetch_candidates()
    skip = {
        r[0]
        for r in conn.execute("SELECT h FROM links WHERE status IN ('good','failed')")
    }
    todo = [c for c in candidates if link_hash(c) not in skip]
    log(f"candidates={len(candidates)} todo={len(todo)}")

    workers = WORKERS_MAX
    tested = 0
    added = 0
    flush_every = 50
    since_flush = 0

    i = 0
    while i < len(todo) and good_count(conn) < TARGET:
        # adaptive workers
        busy = cpu_busy()
        if busy > 0.85:
            workers = max(WORKERS_MIN, workers // 2)
        elif busy < 0.45:
            workers = min(WORKERS_MAX, workers + 4)
        batch = todo[i : i + workers * 2]
        i += len(batch)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(probe, link): link for link in batch}
            for fut in as_completed(futs):
                link = futs[fut]
                tested += 1
                try:
                    status, ip, reason = fut.result()
                except Exception:
                    status, ip, reason = "failed", None, "exc"
                if status == "good":
                    if mark(conn, link, "good", ip):
                        added += 1
                        since_flush += 1
                        log(f"GOOD ip={ip} good_total={good_count(conn)} (+{added})")
                    else:
                        log(f"DUP_IP ip={ip}")
                else:
                    mark(conn, link, "failed", None)
                if since_flush >= flush_every:
                    export_txt(conn)
                    since_flush = 0
                if good_count(conn) >= TARGET:
                    break
        log(
            f"progress tested={tested} added={added} good={good_count(conn)} workers={workers} load={busy:.2f}"
        )

    export_txt(conn)
    log(f"done good={good_count(conn)} tested={tested} added={added}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
