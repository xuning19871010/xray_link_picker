#!/usr/bin/env python3
"""选可用 xray 分享链接（Actions runner 上跑）。

输出文件（data/ 目录）：
  data/good_links.txt          — 当次可用代表链接（每个出口 IP 选 1 条代表，出口 IP 不重复）
  data/failed_links.txt        — 当前状态为 failed 的链接
  data/stable_links.txt        — 连续成功跑日 streak 达标的代表链接（出口 IP 互不相同）
  data/stable_links_by_ip.txt  — 与 stable 同集，每行「出口IP 空格 xray_link」，按出口 IP 排序
  data/ip_day_counts.csv       — 每日每出口 IP（含 ip_source/ip_version）对应的真实 DISTINCT 成功链接数
  data/ip_summary.csv          — 每个出口 IP 序列跨日观测汇总（连续天数、累计不同链接数等）
  data/collection_days.csv     — 每日采集轮次与观测覆盖汇总
  data/ip_report.html          — 单文件静态交互报表（搜索/排序/分页，不含敏感链接）

出口 IP 测量说明：
  - 默认使用非 Cloudflare 前置的权威 HTTPS IPv4 端点 https://checkip.amazonaws.com（可通过 IP_CHECK_URL 配置）
  - 默认关闭跨源隐式回退（IP_FALLBACK_URLS 默认为空），避免 Cloudflare 前置端点（如 api.ipify.org 触发
    Cloudflare Workers 节点 proxyIP 回退中继）与非 CF 端点（观测到 Workers 原生出站）静默混入同一连续序列
  - 每条观测均记录 ip_source 与 ip_version（ipv4/ipv6），并严格校验返回值为单个合法公网 IP
"""
from __future__ import annotations

import base64
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
from pathlib import Path

from export import export_all, stable_threshold
from link_parse import parse_link
from storage import (
    ProbeRecord,
    begin_run,
    end_run,
    extract_ip_source,
    link_hash,
    normalize_link,
    open_db,
    parse_and_validate_exit_ip,
    purge_old_observations,
    record_probe_batch,
)

# ---------- 路径与参数（可用环境变量覆盖）----------
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB = DATA / "state.sqlite"
GOOD_TXT = DATA / "good_links.txt"
FAILED_TXT = DATA / "failed_links.txt"
STABLE_TXT = DATA / "stable_links.txt"
STABLE_BY_IP_TXT = DATA / "stable_links_by_ip.txt"
PROGRESS_FILE = Path(os.environ.get("PROGRESS_FILE", str(DATA / "progress.txt")))

TARGET = int(os.environ.get("TARGET_GOOD", "0"))           # 0=不设上限，测完为止（按唯一出口 IP 计）
STABLE_DAYS = int(os.environ.get("STABLE_DAYS", "30"))     # streak 满多少天算「满额」stable
WORKERS_MAX = int(os.environ.get("WORKERS_MAX", "384"))
WORKERS_MIN = int(os.environ.get("WORKERS_MIN", "256"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3"))
PROBE_URL = os.environ.get("PROBE_URL", "http://43.130.11.12:917/917")

# 出口 IP 测量配置：默认单一非 CF 权威端点 https://checkip.amazonaws.com，不做跨源隐式回退
IP_CHECK_URL = os.environ.get("IP_CHECK_URL", "https://checkip.amazonaws.com").strip()
IP_FALLBACK_URLS = [
    u.strip()
    for u in os.environ.get("IP_FALLBACK_URLS", "").split(",")
    if u.strip()
]
IP_FAMILY = os.environ.get("IP_FAMILY", "4").strip()  # "4" | "6" | "any"

XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")
DEBUG_MAX_CANDIDATES = int(os.environ.get("DEBUG_MAX_CANDIDATES", "0"))
COLLISION_RETRY_ENABLE = int(os.environ.get("COLLISION_RETRY_ENABLE", "1"))
COLLISION_RETRY_PER_IP = int(os.environ.get("COLLISION_RETRY_PER_IP", "2"))
RETRY_FAILED_ENABLE = int(os.environ.get("RETRY_FAILED_ENABLE", "1"))
RETRY_AFTER_DAYS = float(os.environ.get("RETRY_AFTER_DAYS", "7"))
RETRY_FAILED_MAX = int(os.environ.get("RETRY_FAILED_MAX", "2500"))
RETRY_PROBE_TIMEOUT = float(os.environ.get("RETRY_PROBE_TIMEOUT", "5"))

SUBSCRIBE_URLS = [
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
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/sub",
    "https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/v2ray.txt",
    "https://vless.svinakraft.workers.dev/fastest.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/ZywChannel/free/main/sub",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
]

LINK_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic|anytls|"
    r"wireguard|socks5|socks|https|http)://[^\s<>\"']+"
)

_port_lock = threading.Lock()
_next_port = 20000


def log(msg: str) -> None:
    print(msg, flush=True)
    try:
        PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PROGRESS_FILE, "a", encoding="utf-8") as f:
            f.write(time.strftime("%H:%M:%S ") + msg + "\n")
    except Exception:
        pass


# ---------- 拉订阅与代理请求 ----------
def http_get(
    url: str,
    timeout: float = 20,
    proxy: str | None = None,
    ip_family: str | None = None,
) -> bytes:
    """直连用 urllib；走 SOCKS 必须用 curl（系统 urllib 不带 SOCKS）。"""
    if not proxy:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    hostport = proxy.split("://", 1)[-1]
    cmd = [
        "curl", "-fsS", "--max-time", str(int(timeout)),
        "--socks5-hostname", hostport, "-A", "curl/8.0",
    ]
    if ip_family in ("4", "ipv4"):
        cmd.append("-4")
    elif ip_family in ("6", "ipv6"):
        cmd.append("-6")
    cmd.append(url)
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
            link = normalize_link(m)
            if link not in seen:
                seen.add(link)
                out.append(link)
        log(f"fetched {url} total_unique={len(out)}")
    random.shuffle(out)
    if DEBUG_MAX_CANDIDATES > 0:
        out = out[:DEBUG_MAX_CANDIDATES]
        log(f"debug truncate candidates={len(out)}")
    return out


# ---------- 数据库与导出辅助 ----------
def db_connect() -> sqlite3.Connection:
    return open_db(DB, readonly=False)


def export_txt(conn: sqlite3.Connection) -> None:
    stats = export_all(conn, DATA, stable_days=STABLE_DAYS)
    log(
        f"export good_rep={stats['good_representative']} good_total={stats['good_total']} "
        f"failed={stats['failed']} stable={stats['stable']} "
        f"stable_by_ip={stats['stable_by_ip']} ip_summary={stats['ip_summary_count']} "
        f"(need ok_days>={stats['need_days']}, cap={STABLE_DAYS})"
    )


def good_count(conn: sqlite3.Connection) -> int:
    """返回当前可用唯一出口 IP 数量（与 good_links.txt 代表数一致）。"""
    return conn.execute(
        "SELECT COUNT(DISTINCT exit_ip) FROM links WHERE status='good' AND exit_ip IS NOT NULL"
    ).fetchone()[0]


# ---------- 探针与出口 IP 观测 ----------
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


def write_singbox_cfg(path: Path, outbound: dict, socks_port: int) -> None:
    ob = dict(outbound)
    ob.setdefault("tag", "proxy")
    path.write_text(json.dumps({
        "log": {"level": "panic"},
        "inbounds": [{
            "type": "socks", "tag": "in",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [ob],
    }))


def cpu_busy() -> float:
    try:
        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
        return load1 / (os.cpu_count() or 2)
    except Exception:
        return 0.5


def discover_exit_ip(
    proxy: str,
    timeout: float | None = None,
    *,
    primary_url: str | None = None,
    fallback_urls: list[str] | None = None,
    ip_family: str | None = None,
) -> tuple[str | None, str, str | None, str]:
    """查询出口 IP 并严格校验单个公网 IP 与协议栈。

    返回: (exit_ip, ip_source, ip_version, reason)
    默认仅请求 primary_url (https://checkip.amazonaws.com)，不做静默跨源回退。
    """
    t = TIMEOUT if timeout is None else timeout
    p_url = primary_url if primary_url is not None else IP_CHECK_URL
    fb_urls = fallback_urls if fallback_urls is not None else IP_FALLBACK_URLS
    fam = ip_family if ip_family is not None else IP_FAMILY

    urls = [u for u in [p_url, *fb_urls] if u]
    if not urls:
        return None, "unknown", None, "ip_config"

    last_src = extract_ip_source(urls[0])
    last_reason = "ip_http"

    for url in urls:
        src = extract_ip_source(url)
        last_src = src
        try:
            raw = http_get(url, timeout=t, proxy=proxy, ip_family=fam).decode(
                "utf-8", "ignore"
            )
        except Exception:
            last_reason = "ip_http"
            continue

        ip, ver, v_reason = parse_and_validate_exit_ip(
            raw, allowed_family=fam, require_global=True
        )
        if ip and ver:
            return ip, src, ver, "ok"
        last_reason = v_reason

    return None, last_src, None, last_reason


def get_exit_ip(proxy: str, timeout: float | None = None) -> str | None:
    """兼容旧调用接口：仅返回出口 IP 字符串或 None。"""
    ip, _src, _ver, _reason = discover_exit_ip(proxy, timeout=timeout)
    return ip


def probe_detailed(
    link: str, timeout: float | None = None
) -> tuple[str, str | None, str, str | None, str | None, bool]:
    """测一条链接并返回完整观测元数据：
    (status, exit_ip, reason, ip_source, ip_version, probe_ok)
    """
    t = TIMEOUT if timeout is None else timeout
    parsed = parse_link(link)
    if not parsed:
        return "failed", None, "parse", None, None, False
    engine, outbound = parsed["engine"], parsed["outbound"]
    socks_port = alloc_port()
    cfg_path = Path(f"/tmp/probe_{engine}_{socks_port}.json")
    if engine == "xray":
        write_xray_cfg(cfg_path, outbound, socks_port)
        cmd = [XRAY_BIN, "run", "-config", str(cfg_path)]
    elif engine == "sing-box":
        write_singbox_cfg(cfg_path, outbound, socks_port)
        cmd = [SINGBOX_BIN, "run", "-c", str(cfg_path)]
    else:
        return "failed", None, "engine", None, None, False
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(float(os.environ.get("XRAY_WARMUP", "0.15")))
        proxy = f"socks5h://127.0.0.1:{socks_port}"
        try:
            http_get(PROBE_URL, timeout=t, proxy=proxy)
        except Exception:
            return "failed", None, "917", None, None, False

        ip, src, ver, ip_reason = discover_exit_ip(proxy, timeout=t)
        if not ip:
            return "failed", None, ip_reason, src, None, True
        return "good", ip, "ok", src, ver, True
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


def probe(link: str, timeout: float | None = None) -> tuple[str, str | None, str]:
    """兼容三元组接口：(status, exit_ip, reason)。"""
    status, ip, reason, _src, _ver, _probe_ok = probe_detailed(link, timeout=timeout)
    return status, ip, reason


def _invoke_probe(
    link: str, timeout: float | None
) -> tuple[str, str | None, str, str | None, str | None, bool]:
    """若测试 monkeypatch 了 select_links.probe，也能自动兼容。"""
    if probe is not _ORIG_PROBE:
        status, ip, reason = probe(link, timeout)
        if status == "good" and ip:
            c_ip, ver, v_reason = parse_and_validate_exit_ip(
                ip, allowed_family="any", require_global=True
            )
            if c_ip:
                return "good", c_ip, "ok", extract_ip_source(IP_CHECK_URL), ver, True
            return "failed", None, v_reason, extract_ip_source(IP_CHECK_URL), None, True
        probe_ok = (reason or "").startswith("ip")
        src = extract_ip_source(IP_CHECK_URL) if probe_ok else None
        return "failed", None, reason, src, None, probe_ok
    return probe_detailed(link, timeout)


_ORIG_PROBE = probe


def _run_probes_parallel(
    links: list[str],
    *,
    workers: int,
    timeout: float | None,
    stage: str,
    seq_tracker: dict[str, int],
) -> list[ProbeRecord]:
    records: list[ProbeRecord] = []
    if not links:
        return records
    with ThreadPoolExecutor(max_workers=workers) as ex:
        start_times = {link: time.time() for link in links}
        futs = {ex.submit(_invoke_probe, link, timeout): link for link in links}
        for fut in as_completed(futs):
            link = futs[fut]
            end_ts = time.time()
            dur_ms = int(max(0.0, (end_ts - start_times.get(link, end_ts)) * 1000))
            try:
                status, ip, reason, src, ver, probe_ok = fut.result()
            except Exception:
                status, ip, reason, src, ver, probe_ok = (
                    "failed",
                    None,
                    "exc",
                    None,
                    None,
                    False,
                )
            h = link_hash(link)
            seq_key = f"{stage}:{h}"
            seq = seq_tracker.get(seq_key, 0) + 1
            seq_tracker[seq_key] = seq
            records.append(
                ProbeRecord(
                    link=link,
                    status="good" if (status == "good" and ip) else "failed",
                    exit_ip=ip if status == "good" else None,
                    reason=reason,
                    ts=end_ts,
                    stage=stage,
                    seq=seq,
                    ip_source=src,
                    ip_version=ver,
                    probe_ok=probe_ok,
                    duration_ms=dur_ms,
                )
            )
    return records


def probe_batch(
    conn: sqlite3.Connection,
    run_key: str,
    links: list[str],
    *,
    workers: int | None = None,
    timeout: float | None = None,
    tag: str = "PROBE",
    seq_tracker: dict[str, int] | None = None,
) -> tuple[int, int]:
    """探测一批链接并单事务批量落库；返回 (tested, good_links_count)。"""
    if not links:
        return 0, 0
    w = workers if workers is not None else min(WORKERS_MAX, max(WORKERS_MIN, 64))
    tracker = seq_tracker if seq_tracker is not None else {}
    records = _run_probes_parallel(
        links, workers=w, timeout=timeout, stage=tag.lower(), seq_tracker=tracker
    )
    tested, added = record_probe_batch(
        conn, run_key, records, default_ip_source=extract_ip_source(IP_CHECK_URL)
    )
    cur_unique_ips = good_count(conn)
    for rec in records:
        if rec.status == "good":
            log(
                f"{tag}_GOOD ip={rec.exit_ip} src={rec.ip_source} "
                f"ver={rec.ip_version} unique_good_ips={cur_unique_ips}"
            )
        else:
            log(f"{tag}_FAIL reason={rec.reason} probe_ok={int(bool(rec.probe_ok))}")
    return tested, added


def pick_collision_reclaim(conn: sqlite3.Connection, vacated_ips: set[str]) -> list[str]:
    """兼容旧库遗留的同 IP 撞车 failed（status='failed' 且仍带 exit_ip）。"""
    out: list[str] = []
    seen: set[str] = set()
    for ip in sorted(vacated_ips):
        rows = conn.execute(
            "SELECT link FROM links WHERE status='failed' AND exit_ip=? "
            "ORDER BY ok_days DESC, updated_at DESC LIMIT ?",
            (ip, COLLISION_RETRY_PER_IP),
        ).fetchall()
        for (link,) in rows:
            if link in seen:
                continue
            seen.add(link)
            out.append(link)
    log(
        f"RECLAIM_IP vacated={len(vacated_ips)} candidates={len(out)} "
        f"per_ip={COLLISION_RETRY_PER_IP}"
    )
    return out


def pick_cooled_failed(
    conn: sqlite3.Connection, limit: int, exclude_hashes: set[str]
) -> list[str]:
    """冷却期满的普通 failed（无 exit_ip），最多 limit 条可解析链接。"""
    if limit <= 0:
        return []
    cutoff = time.time() - RETRY_AFTER_DAYS * 86400
    rows = conn.execute(
        "SELECT link, h FROM links WHERE status='failed' AND exit_ip IS NULL "
        "AND updated_at <= ? ORDER BY updated_at ASC LIMIT ?",
        (cutoff, max(limit * 2, limit)),
    ).fetchall()
    out: list[str] = []
    for link, h in rows:
        if h in exclude_hashes:
            continue
        if not parse_link(link):
            continue
        out.append(link)
        if len(out) >= limit:
            break
    log(
        f"RETRY_FAILED scanned={len(rows)} picked={len(out)} "
        f"after_days={RETRY_AFTER_DAYS} max={limit}"
    )
    return out


def retest_goods(
    conn: sqlite3.Connection, run_key: str, seq_tracker: dict[str, int]
) -> set[str]:
    """复测现有 good；返回本轮完全空出的出口 IP 集合。"""
    rows = conn.execute(
        "SELECT link, exit_ip FROM links WHERE status='good'"
    ).fetchall()
    if not rows:
        return set()
    old_ips = {ip for _, ip in rows if ip}
    links = [link for link, _ in rows]
    log(f"retest previous goods={len(links)}")
    probe_batch(
        conn,
        run_key,
        links,
        workers=min(64, WORKERS_MAX),
        tag="RETEST",
        seq_tracker=seq_tracker,
    )
    still = {
        r[0]
        for r in conn.execute(
            "SELECT exit_ip FROM links WHERE status='good' AND exit_ip IS NOT NULL"
        )
    }
    vacated = old_ips - still
    log(f"retest done vacated_ips={len(vacated)} still_good_ips={len(still)}")
    return vacated


def verify_goods(
    conn: sqlite3.Connection, run_key: str, seq_tracker: dict[str, int]
) -> None:
    """收尾复验：再测一遍当前 good，剔除掉线的链接（同 IP 多条均通时全部保留真实 good，导出时自动按 IP 去重）。"""
    rows = conn.execute(
        "SELECT link FROM links WHERE status='good' ORDER BY updated_at"
    ).fetchall()
    links = [r[0] for r in rows]
    log(f"verify start count={len(links)}")
    records = _run_probes_parallel(
        links,
        workers=min(64, max(8, WORKERS_MAX // 2)),
        timeout=None,
        stage="verify",
        seq_tracker=seq_tracker,
    )
    record_probe_batch(
        conn, run_key, records, default_ip_source=extract_ip_source(IP_CHECK_URL)
    )
    keep = sum(1 for r in records if r.status == "good")
    drop = len(records) - keep
    export_txt(conn)
    log(f"verify done keep={keep} drop={drop} unique_ip={good_count(conn)}")


# ---------- 主流程 ----------
def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = db_connect()
    run_key = begin_run(conn, ip_source=extract_ip_source(IP_CHECK_URL))
    seq_tracker: dict[str, int] = {}

    def _handle_signal(signum: int, _frame) -> None:
        log(f"received signal {signum}, marking run {run_key} interrupted and exporting")
        try:
            end_run(conn, run_key, status="interrupted")
            export_txt(conn)
        finally:
            conn.close()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        start_good = good_count(conn)
        log(
            f"start run_key={run_key} good_unique_ips={start_good} target={TARGET} "
            f"stable_days={STABLE_DAYS} ip_check_url={IP_CHECK_URL} ip_family={IP_FAMILY}"
        )
        log(f"xray_bin={XRAY_BIN} singbox_bin={SINGBOX_BIN} probe={PROBE_URL} workers={WORKERS_MIN}-{WORKERS_MAX}")
        log(
            f"reclaim enable={COLLISION_RETRY_ENABLE} per_ip={COLLISION_RETRY_PER_IP} "
            f"retry enable={RETRY_FAILED_ENABLE} after_days={RETRY_AFTER_DAYS} "
            f"max={RETRY_FAILED_MAX} retry_timeout={RETRY_PROBE_TIMEOUT}"
        )

        reclaim_added = 0
        retry_added = 0
        probed_hashes: set[str] = set()

        # 1) 复测现有 good，收集空出的出口 IP
        vacated_ips: set[str] = set()
        old_goods = conn.execute(
            "SELECT 1 FROM links WHERE status='good' LIMIT 1"
        ).fetchone()
        if old_goods:
            vacated_ips = retest_goods(conn, run_key, seq_tracker)
            export_txt(conn)
            for (h,) in conn.execute("SELECT h FROM links WHERE status='good'"):
                probed_hashes.add(h)

        # 2) 撞车顶替（兼容旧库中曾因同 IP 撞车被标 failed 但带 exit_ip 的候选）
        if COLLISION_RETRY_ENABLE and vacated_ips:
            reclaim_links = pick_collision_reclaim(conn, vacated_ips)
            tested_r, reclaim_added = probe_batch(
                conn,
                run_key,
                reclaim_links,
                workers=min(64, WORKERS_MAX),
                tag="RECLAIM",
                seq_tracker=seq_tracker,
            )
            probed_hashes.update(link_hash(x) for x in reclaim_links)
            log(f"RECLAIM done tested={tested_r} added={reclaim_added}")

        # 3) 已达 TARGET：复测+顶替后直接 verify
        if TARGET > 0 and good_count(conn) >= TARGET:
            log("already enough after retest/reclaim — verify + export")
            verify_goods(conn, run_key, seq_tracker)
            end_run(conn, run_key, status="completed")
            purge_old_observations(conn)
            log(
                f"done good={good_count(conn)} reclaim_added={reclaim_added} "
                f"retry_added={retry_added}"
            )
            return 0

        # 4) 订阅新候选（跳过库内已有 good/failed）
        candidates = fetch_candidates()
        skip = {
            r[0]
            for r in conn.execute(
                "SELECT h FROM links WHERE status IN ('good','failed')"
            )
        }
        todo = []
        skipped_unrun = 0
        for c in candidates:
            h = link_hash(c)
            if h in skip:
                continue
            if not parse_link(c):
                skipped_unrun += 1
                continue
            todo.append(c)
        log(f"candidates={len(candidates)} todo={len(todo)} skip_unrunnable={skipped_unrun}")

        # 5) 批量测全新候选
        workers = WORKERS_MAX
        tested = added = 0
        since_flush = 0
        i = 0
        while i < len(todo) and (TARGET <= 0 or good_count(conn) < TARGET):
            busy = cpu_busy()
            if busy > 3.0:
                workers = max(WORKERS_MIN, workers - 8)
            elif busy < 1.0:
                workers = min(WORKERS_MAX, workers + 8)
            batch = todo[i : i + workers * 2]
            i += len(batch)
            probed_hashes.update(link_hash(x) for x in batch)
            records = _run_probes_parallel(
                batch,
                workers=workers,
                timeout=None,
                stage="candidate",
                seq_tracker=seq_tracker,
            )
            b_tested, b_good = record_probe_batch(
                conn,
                run_key,
                records,
                default_ip_source=extract_ip_source(IP_CHECK_URL),
            )
            tested += b_tested
            added += b_good
            since_flush += b_good
            if since_flush >= 50:
                export_txt(conn)
                since_flush = 0
            log(
                f"progress tested={tested} added_links={added} unique_good_ips={good_count(conn)} "
                f"workers={workers} load={busy:.2f}"
            )

        # 6) 冷却重试普通 failed（仍缺额或无 TARGET 时）
        if RETRY_FAILED_ENABLE and (TARGET <= 0 or good_count(conn) < TARGET):
            exclude = set(probed_hashes)
            exclude.update(
                r[0] for r in conn.execute("SELECT h FROM links WHERE status='good'")
            )
            retry_links = pick_cooled_failed(conn, RETRY_FAILED_MAX, exclude)
            tested_t, retry_added = probe_batch(
                conn,
                run_key,
                retry_links,
                workers=min(64, WORKERS_MAX),
                timeout=RETRY_PROBE_TIMEOUT,
                tag="RETRY",
                seq_tracker=seq_tracker,
            )
            log(f"RETRY done tested={tested_t} added={retry_added}")

        export_txt(conn)
        log(
            f"probe done unique_good_ips={good_count(conn)} tested={tested} added={added} "
            f"reclaim_added={reclaim_added} retry_added={retry_added}"
        )
        verify_goods(conn, run_key, seq_tracker)
        end_run(conn, run_key, status="completed")
        purged = purge_old_observations(conn)
        if purged:
            log(f"purged old observations={purged}")
        export_txt(conn)
        log(
            f"done unique_good_ips={good_count(conn)} tested={tested} added={added} "
            f"reclaim_added={reclaim_added} retry_added={retry_added}"
        )
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
