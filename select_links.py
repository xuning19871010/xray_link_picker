#!/usr/bin/env python3
"""选可用 xray 分享链接（Actions runner 上跑）。

输出文件（data/ 目录）：
  data/good_links.txt          — 当次测通代表链接（每个出口 IP 选 1 条代表，出口 IP 不重复）
  data/stable_links.txt        — 连续成功跑日 streak 达标的代表链接（出口 IP 互不相同）
  data/stable_links_by_ip.txt  — 与 stable 同集，每行「出口IP 空格 xray_link」，按出口 IP 排序
  data/ip_day_counts.csv       — 每日每出口 IP（含 ip_source/ip_version）对应的真实 DISTINCT 成功链接数
  data/ip_summary.csv          — 每个出口 IP 序列跨日观测汇总（连续天数、累计不同链接数等）
  data/collection_days.csv     — 每日采集轮次与观测覆盖汇总
  data/ip_report.html          — 单文件静态交互报表（搜索/排序，不含敏感链接）

TARGET_GOOD=0 表示不设上限，把候选测完拿多少算多少。
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

from export import export_all
from link_parse import parse_link
from storage import (
    ProbeRecord,
    begin_run,
    end_run,
    link_hash,
    normalize_ip_source,
    normalize_link,
    open_db,
    parse_and_validate_exit_ip,
    purge_old_observations,
    record_probe_batch,
    remember_links,
)

# ---------- 路径与参数（可用环境变量覆盖）----------
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB = DATA / "state.sqlite"
GOOD_TXT = DATA / "good_links.txt"       # 当次 good
FAILED_TXT = DATA / "failed_links.txt"
STABLE_TXT = DATA / "stable_links.txt"   # 持续可用
STABLE_BY_IP_TXT = DATA / "stable_links_by_ip.txt"  # 出口IP + link，按 IP 排序
PROGRESS_FILE = Path(os.environ.get("PROGRESS_FILE", str(DATA / "progress.txt")))

TARGET = int(os.environ.get("TARGET_GOOD", "0"))           # 0=不设唯一出口 IP 上限
RUN_BUDGET_SEC = float(os.environ.get("RUN_BUDGET_SEC", "18000"))  # 到点停测并发布，未测保持 pending
STABLE_DAYS = int(os.environ.get("STABLE_DAYS", "30"))     # streak 满多少天算「满额」stable
WORKERS_MAX = int(os.environ.get("WORKERS_MAX", "384"))
WORKERS_MIN = int(os.environ.get("WORKERS_MIN", "256"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3"))
PROBE_URL = os.environ.get("PROBE_URL", "http://43.130.11.12:917/917")
IP_CHECK_URL = os.environ.get("IP_CHECK_URL", "https://checkip.amazonaws.com").strip()
IP_FAMILY = os.environ.get("IP_FAMILY", "4").strip()
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")
# 调试：只测前 N 条候选（0=不限制）。快速验证流程用 300～1000。
DEBUG_MAX_CANDIDATES = int(os.environ.get("DEBUG_MAX_CANDIDATES", "0"))  # 0=不截断
# 冷却重试：普通 failed（无 exit_ip）过期后再测一小批
RETRY_FAILED_ENABLE = int(os.environ.get("RETRY_FAILED_ENABLE", "1"))
RETRY_AFTER_DAYS = float(os.environ.get("RETRY_AFTER_DAYS", "7"))
RETRY_FAILED_MAX = int(os.environ.get("RETRY_FAILED_MAX", "2500"))
RETRY_PROBE_TIMEOUT = float(os.environ.get("RETRY_PROBE_TIMEOUT", "5"))  # 仅冷却重试

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
        with open(PROGRESS_FILE, "a") as f:
            f.write(time.strftime("%H:%M:%S ") + msg + "\n")
    except Exception:
        pass


# ---------- 拉订阅 ----------
def http_get(
    url: str, timeout: float = 20, proxy: str | None = None, ip_family: str | None = None
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


# ---------- 数据库与导出 ----------
def db_connect() -> sqlite3.Connection:
    return open_db(DB, readonly=False)


def export_txt(conn: sqlite3.Connection) -> None:
    stats = export_all(conn, DATA, stable_days=STABLE_DAYS)
    log(
        f"export good_rep={stats['good_representative']} good_total={stats['good_total']} "
        f"failed={stats['failed']} stable={stats['stable']} "
        f"stable_by_ip={stats['stable_by_ip']} (need ok_days>={stats['need_days']}, cap={STABLE_DAYS})"
    )


def good_count(conn: sqlite3.Connection) -> int:
    return conn.execute(
        "SELECT COUNT(DISTINCT exit_ip) FROM links WHERE status='good' AND exit_ip IS NOT NULL"
    ).fetchone()[0]


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
    proxy: str, timeout: float | None = None
) -> tuple[str | None, str, str | None, str]:
    """只请求配置的单一测量端点，不跨源回退。返回 (exit_ip, ip_source, ip_version, reason)。"""
    t = TIMEOUT if timeout is None else timeout
    src = normalize_ip_source(IP_CHECK_URL)
    if not IP_CHECK_URL:
        return None, "unknown", None, "ip_config"
    try:
        raw = http_get(IP_CHECK_URL, timeout=t, proxy=proxy, ip_family=IP_FAMILY).decode("utf-8", "ignore")
    except Exception:
        return None, src, None, "ip_http"
    ip, ver, v_reason = parse_and_validate_exit_ip(raw, allowed_family=IP_FAMILY, require_global=True)
    if ip and ver:
        return ip, src, ver, "ok"
    return None, src, None, v_reason


def get_exit_ip(proxy: str, timeout: float | None = None) -> str | None:
    ip, _src, _ver, _reason = discover_exit_ip(proxy, timeout=timeout)
    return ip


def probe_detailed(
    link: str, timeout: float | None = None
) -> tuple[str, str | None, str, str | None, str | None, bool]:
    """测一条链接：(status, exit_ip, reason, ip_source, ip_version, probe_ok)。"""
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
    status, ip, reason, _src, _ver, _ok = probe_detailed(link, timeout=timeout)
    return status, ip, reason


_ORIG_PROBE = probe


def _invoke_probe(
    link: str, timeout: float | None
) -> tuple[str, str | None, str, str | None, str | None, bool]:
    if probe is not _ORIG_PROBE:
        status, ip, reason = probe(link, timeout)
        src = normalize_ip_source(IP_CHECK_URL)
        if status == "good" and ip:
            c_ip, ver, v_reason = parse_and_validate_exit_ip(ip, allowed_family="any", require_global=True)
            if c_ip:
                return "good", c_ip, "ok", src, ver, True
            return "failed", None, v_reason, src, None, True
        probe_ok = (reason or "").startswith("ip")
        return "failed", None, reason, (src if probe_ok else None), None, probe_ok
    return probe_detailed(link, timeout)


def _run_probes_parallel(
    links: list[str], *, workers: int, timeout: float | None, stage: str, seq_tracker: dict[str, int]
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
                status, ip, reason, src, ver, probe_ok = "failed", None, "exc", None, None, False
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
    """探测一批链接并单事务落库；返回 (tested, added_good_count)。"""
    if not links:
        return 0, 0
    w = workers if workers is not None else min(WORKERS_MAX, max(WORKERS_MIN, 64))
    tracker = seq_tracker if seq_tracker is not None else {}
    records = _run_probes_parallel(links, workers=w, timeout=timeout, stage=tag.lower(), seq_tracker=tracker)
    tested, added = record_probe_batch(conn, run_key, records, default_ip_source=normalize_ip_source(IP_CHECK_URL))
    cur_unique_ips = good_count(conn)
    for rec in records:
        if rec.status == "good":
            log(f"{tag}_GOOD ip={rec.exit_ip} good_total={cur_unique_ips}")
        else:
            log(f"{tag}_FAIL reason={rec.reason}")
    return tested, added


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
    """复测现有 good；返回本轮空出的出口 IP 集合。"""
    rows = conn.execute(
        "SELECT link, exit_ip FROM links WHERE status='good'"
    ).fetchall()
    if not rows:
        return set()
    old_ips = {ip for _, ip in rows if ip}
    links = [link for link, _ in rows]
    log(f"retest previous goods={len(links)}")
    probe_batch(conn, run_key, links, workers=min(64, WORKERS_MAX), tag="RETEST", seq_tracker=seq_tracker)
    still = {
        r[0]
        for r in conn.execute(
            "SELECT exit_ip FROM links WHERE status='good' AND exit_ip IS NOT NULL"
        )
    }
    vacated = old_ips - still
    log(f"retest done vacated_ips={len(vacated)} still_good_ips={len(still)}")
    return vacated


# ---------- 主流程 ----------
def _budget_ok(started: float) -> bool:
    budget = float(os.environ.get("RUN_BUDGET_SEC", "18000"))
    return time.time() - started < budget


def _probe_list(
    conn: sqlite3.Connection,
    run_key: str,
    links: list[str],
    seq_tracker: dict[str, int],
    started: float,
    stage: str,
    timeout: float | None = None,
    stop_at_target: bool = False,
) -> tuple[int, int]:
    tested = added = 0
    i = 0
    workers = WORKERS_MAX
    since_flush = 0
    while i < len(links) and _budget_ok(started):
        if stop_at_target and TARGET > 0 and good_count(conn) >= TARGET:
            break
        busy = cpu_busy()
        if busy > 3.0:
            workers = max(WORKERS_MIN, workers - 8)
        elif busy < 1.0:
            workers = min(WORKERS_MAX, workers + 8)
        batch = links[i : i + workers * 2]
        i += len(batch)
        records = _run_probes_parallel(
            batch, workers=workers, timeout=timeout, stage=stage, seq_tracker=seq_tracker
        )
        b_tested, b_good = record_probe_batch(
            conn, run_key, records, default_ip_source=normalize_ip_source(IP_CHECK_URL)
        )
        tested += b_tested
        added += b_good
        since_flush += b_good
        if since_flush >= 50:
            export_txt(conn)
            since_flush = 0
        log(
            f"{stage} tested={tested} added={added} good_ips={good_count(conn)} "
            f"workers={workers} load={busy:.2f}"
        )
    return tested, added


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    conn = db_connect()
    run_key = begin_run(conn, ip_source=normalize_ip_source(IP_CHECK_URL))
    seq_tracker: dict[str, int] = {}
    started = time.time()

    def _on_signal(signum: int, _frame) -> None:
        try:
            end_run(conn, run_key, status="interrupted")
            export_txt(conn)
        finally:
            conn.close()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    pending_now = conn.execute("SELECT COUNT(*) FROM links WHERE status='pending'").fetchone()[0]
    log(
        f"start epoch run_key={run_key} good_ips={good_count(conn)} "
        f"pending={pending_now} "
        f"budget_sec={os.environ.get('RUN_BUDGET_SEC', '18000')} ip_check_url={IP_CHECK_URL}"
    )
    log(f"xray_bin={XRAY_BIN} singbox_bin={SINGBOX_BIN} probe={PROBE_URL} workers={WORKERS_MIN}-{WORKERS_MAX}")

    # 先入库新链接，未测保持 pending，即使后面预算用完也不会记成失败。
    candidates = fetch_candidates()
    runnable = []
    skipped_unrun = 0
    for c in candidates:
        if parse_link(c):
            runnable.append(c)
        else:
            skipped_unrun += 1
    added_pending = remember_links(conn, runnable)
    log(f"candidates={len(candidates)} runnable={len(runnable)} new_pending={added_pending} skip_unparseable={skipped_unrun}")

    if _budget_ok(started) and conn.execute("SELECT 1 FROM links WHERE status='good' LIMIT 1").fetchone():
        retest_goods(conn, run_key, seq_tracker)
        export_txt(conn)

    retry_added = 0
    if RETRY_FAILED_ENABLE and _budget_ok(started) and (TARGET <= 0 or good_count(conn) < TARGET):
        probed = {r[0] for r in conn.execute("SELECT h FROM links WHERE status='good'")}
        retry_links = pick_cooled_failed(conn, RETRY_FAILED_MAX, probed)
        _tested, retry_added = _probe_list(
            conn, run_key, retry_links, seq_tracker, started, "retry",
            timeout=RETRY_PROBE_TIMEOUT,
        )

    pending = [
        r[0] for r in conn.execute(
            "SELECT link FROM links WHERE status='pending' ORDER BY updated_at ASC, h ASC"
        )
    ]
    tested, added = _probe_list(
        conn, run_key, pending, seq_tracker, started, "pending", stop_at_target=True
    )
    pending_left = conn.execute("SELECT COUNT(*) FROM links WHERE status='pending'").fetchone()[0]
    if pending_left:
        log(f"budget stop pending_left={pending_left}（未测不是失败，也不是 0 条可用）")

    end_run(conn, run_key, status="completed")
    purge_old_observations(conn)
    export_txt(conn)
    log(
        f"done good_ips={good_count(conn)} pending_left={pending_left} "
        f"pending_tested={tested} pending_new_good={added} retry_added={retry_added}"
    )
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
