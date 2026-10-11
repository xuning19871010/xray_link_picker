#!/usr/bin/env python3
"""选可用 xray 分享链接（Actions runner 上跑）。

两份结果：
  data/good_links.txt   — 当次测通 + 出口 IP 不重复
  data/stable_links.txt — 跨天持续通：第N天要 ok_days≥N，满 STABLE_DAYS 后固定要满天数

调试时把 TARGET_GOOD / DEBUG_MAX_CANDIDATES 调小，几分钟就能跑完一轮。
"""
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
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path

from link_parse import parse_outbound

# ---------- 路径与参数（可用环境变量覆盖）----------
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB = DATA / "state.sqlite"
GOOD_TXT = DATA / "good_links.txt"       # 当次 good
FAILED_TXT = DATA / "failed_links.txt"
STABLE_TXT = DATA / "stable_links.txt"   # 持续可用
PROGRESS_FILE = Path(os.environ.get("PROGRESS_FILE", str(DATA / "progress.txt")))

TARGET = int(os.environ.get("TARGET_GOOD", "50"))          # 调试默认 50；正式可改 2000
STABLE_DAYS = int(os.environ.get("STABLE_DAYS", "30"))     # 满多少个成功跑日算 stable
WORKERS_MAX = int(os.environ.get("WORKERS_MAX", "384"))
WORKERS_MIN = int(os.environ.get("WORKERS_MIN", "256"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3"))
PROBE_URL = os.environ.get("PROBE_URL", "http://43.130.11.12:917/917")
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
# 调试：只测前 N 条候选（0=不限制）。快速验证流程用 300～1000。
DEBUG_MAX_CANDIDATES = int(os.environ.get("DEBUG_MAX_CANDIDATES", "800"))

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
    try:
        PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PROGRESS_FILE, "a") as f:
            f.write(time.strftime("%H:%M:%S ") + msg + "\n")
    except Exception:
        pass


def link_hash(link: str) -> str:
    return hashlib.sha256(link.strip().encode()).hexdigest()


# ---------- 拉订阅 ----------
def http_get(url: str, timeout: float = 20, proxy: str | None = None) -> bytes:
    """直连用 urllib；走 SOCKS 必须用 curl（系统 urllib 不带 SOCKS）。"""
    if not proxy:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    hostport = proxy.split("://", 1)[-1]
    cmd = [
        "curl", "-fsS", "--max-time", str(int(timeout)),
        "--socks5-hostname", hostport, "-A", "curl/8.0", url,
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="ignore")[:200] or f"curl {r.returncode}")
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
    if DEBUG_MAX_CANDIDATES > 0:
        out = out[:DEBUG_MAX_CANDIDATES]
        log(f"debug truncate candidates={len(out)}")
    return out


# ---------- 数据库 ----------
def db_connect() -> sqlite3.Connection:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB, check_same_thread=False)
    # status: good=当次可用 failed=当次失败
    # ok_days: 跨天累计成功跑日数；last_ok_day: 最近一次成功日期 YYYY-MM-DD
    conn.execute(
        """CREATE TABLE IF NOT EXISTS links(
            h TEXT PRIMARY KEY,
            link TEXT NOT NULL,
            status TEXT NOT NULL,
            exit_ip TEXT,
            ok_days INTEGER NOT NULL DEFAULT 0,
            last_ok_day TEXT,
            updated_at REAL NOT NULL
        )"""
    )
    # 旧库升级：缺列就补
    cols = {r[1] for r in conn.execute("PRAGMA table_info(links)")}
    if "ok_days" not in cols:
        conn.execute("ALTER TABLE links ADD COLUMN ok_days INTEGER NOT NULL DEFAULT 0")
    if "last_ok_day" not in cols:
        conn.execute("ALTER TABLE links ADD COLUMN last_ok_day TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ip ON links(exit_ip) WHERE exit_ip IS NOT NULL AND status='good'"
    )
    conn.commit()
    return conn


def stable_threshold(conn: sqlite3.Connection) -> int:
    """第 N 天门槛=N，直到 STABLE_DAYS；可调 STABLE_DAYS。"""
    row = conn.execute(
        "SELECT MIN(last_ok_day) FROM links WHERE last_ok_day IS NOT NULL"
    ).fetchone()
    if not row or not row[0]:
        return 1
    try:
        first = date.fromisoformat(row[0])
    except ValueError:
        return 1
    days = (date.today() - first).days + 1
    return max(1, min(STABLE_DAYS, days))


def export_txt(conn: sqlite3.Connection) -> None:
    goods = [r[0] for r in conn.execute(
        "SELECT link FROM links WHERE status='good' ORDER BY updated_at")]
    fails = [r[0] for r in conn.execute(
        "SELECT link FROM links WHERE status='failed' ORDER BY updated_at")]
    need = stable_threshold(conn)
    # 刚起步：第1天 ok_days>=1 即入 stable；逐渐升到 STABLE_DAYS
    stables = [r[0] for r in conn.execute(
        "SELECT link FROM links WHERE ok_days>=? ORDER BY ok_days DESC, updated_at",
        (need,),
    )]
    GOOD_TXT.write_text("\n".join(goods) + ("\n" if goods else ""))
    FAILED_TXT.write_text("\n".join(fails) + ("\n" if fails else ""))
    STABLE_TXT.write_text("\n".join(stables) + ("\n" if stables else ""))
    log(f"export good={len(goods)} failed={len(fails)} stable={len(stables)} (need ok_days>={need}, cap={STABLE_DAYS})")


def good_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM links WHERE status='good'").fetchone()[0]


def mark(conn: sqlite3.Connection, link: str, status: str, exit_ip: str | None) -> bool:
    """记当次结果。good 且 IP 未占用返回 True；IP 重复则记 failed 返回 False。"""
    h = link_hash(link)
    now = time.time()
    today = date.today().isoformat()
    with _lock:
        if status == "good":
            if exit_ip:
                row = conn.execute(
                    "SELECT 1 FROM links WHERE exit_ip=? AND status='good' AND h!=?",
                    (exit_ip, h),
                ).fetchone()
                if row:
                    prev = conn.execute(
                        "SELECT ok_days, last_ok_day FROM links WHERE h=?", (h,)
                    ).fetchone()
                    ok_days = (prev[0] if prev else 0) or 0
                    last = prev[1] if prev else None
                    conn.execute(
                        "INSERT OR REPLACE INTO links(h,link,status,exit_ip,ok_days,last_ok_day,updated_at) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (h, link, "failed", None, ok_days, last, now),
                    )
                    conn.commit()
                    return False
            # 跨天：同一天只加一次 ok_days
            prev = conn.execute(
                "SELECT ok_days, last_ok_day FROM links WHERE h=?", (h,)
            ).fetchone()
            ok_days = (prev[0] if prev else 0) or 0
            last = prev[1] if prev else None
            if last != today:
                ok_days += 1
                last = today
            conn.execute(
                "INSERT OR REPLACE INTO links(h,link,status,exit_ip,ok_days,last_ok_day,updated_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (h, link, "good", exit_ip, ok_days, last, now),
            )
            conn.commit()
            return True
        prev = conn.execute(
            "SELECT ok_days, last_ok_day FROM links WHERE h=?", (h,)
        ).fetchone()
        ok_days = (prev[0] if prev else 0) or 0
        last = prev[1] if prev else None
        conn.execute(
            "INSERT OR REPLACE INTO links(h,link,status,exit_ip,ok_days,last_ok_day,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (h, link, "failed", None, ok_days, last, now),
        )
        conn.commit()
        return False


# ---------- 探针 ----------
def alloc_port() -> int:
    global _next_port
    with _port_lock:
        p = _next_port
        _next_port += 1
        if _next_port > 45000:
            _next_port = 20000
        return p


def write_xray_cfg(path: Path, outbound: dict, socks_port: int) -> None:
    path.write_text(json.dumps({
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks", "settings": {"udp": False},
        }],
        "outbounds": [outbound],
    }))


def cpu_busy() -> float:
    try:
        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
        return load1 / (os.cpu_count() or 2)
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
    """测一条链接：通探针 + 能取到出口 IP 才算 good。"""
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
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(float(os.environ.get("XRAY_WARMUP", "0.15")))
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


def verify_goods(conn: sqlite3.Connection) -> None:
    """收尾复验：再测一遍 good，踢掉不通或 IP 撞车的。"""
    rows = conn.execute(
        "SELECT link, exit_ip FROM links WHERE status='good' ORDER BY updated_at"
    ).fetchall()
    log(f"verify start count={len(rows)}")
    seen: set[str] = set()
    keep = drop = 0
    with ThreadPoolExecutor(max_workers=min(64, max(8, WORKERS_MAX // 2))) as ex:
        futs = {ex.submit(probe, link): (link, old_ip) for link, old_ip in rows}
        for fut in as_completed(futs):
            link, old_ip = futs[fut]
            try:
                status, ip, reason = fut.result()
            except Exception:
                status, ip, reason = "failed", None, "exc"
            if status != "good" or not ip or ip in seen:
                mark(conn, link, "failed", None)
                drop += 1
                log(f"VERIFY_DROP reason={reason or 'dup'} old_ip={old_ip}")
                continue
            seen.add(ip)
            if ip != old_ip:
                mark(conn, link, "good", ip)
            keep += 1
    export_txt(conn)
    log(f"verify done keep={keep} drop={drop} unique_ip={len(seen)}")


# ---------- 主流程 ----------
def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = db_connect()
    start_good = good_count(conn)
    log(f"start good={start_good} target={TARGET} stable_days={STABLE_DAYS}")
    log(f"xray_bin={XRAY_BIN} probe={PROBE_URL} workers={WORKERS_MIN}-{WORKERS_MAX}")
    if start_good >= TARGET:
        log("already enough — still verify + export")
        verify_goods(conn)
        return 0

    candidates = fetch_candidates()
    skip = {r[0] for r in conn.execute(
        "SELECT h FROM links WHERE status IN ('good','failed')")}
    todo = [c for c in candidates if link_hash(c) not in skip]
    log(f"candidates={len(candidates)} todo={len(todo)}")

    workers = WORKERS_MAX
    tested = added = 0
    since_flush = 0
    i = 0
    while i < len(todo) and good_count(conn) < TARGET:
        busy = cpu_busy()
        if busy > 3.0:
            workers = max(WORKERS_MIN, workers - 8)
        elif busy < 1.0:
            workers = min(WORKERS_MAX, workers + 8)
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
                if since_flush >= 50:
                    export_txt(conn)
                    since_flush = 0
                if good_count(conn) >= TARGET:
                    break
        log(
            f"progress tested={tested} added={added} good={good_count(conn)} "
            f"workers={workers} load={busy:.2f}"
        )

    export_txt(conn)
    log(f"probe done good={good_count(conn)} tested={tested} added={added}")
    verify_goods(conn)
    log(f"done good={good_count(conn)} tested={tested} added={added}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
