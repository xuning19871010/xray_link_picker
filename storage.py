"""数据库存储、版本迁移、出口 IP 观测来源建模、批量落库与过期清理。"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

EPOCH = "checkip-amazonaws-ipv4-1"
SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
RAW_RETENTION_DAYS = int(os.environ.get("RAW_RETENTION_DAYS", "30"))
DEFAULT_IP_SOURCE = "https://checkip.amazonaws.com"


def normalize_link(link: str) -> str:
    return link.strip().rstrip("\",'")


def link_hash(link: str) -> str:
    return hashlib.sha256(normalize_link(link).encode("utf-8")).hexdigest()


def shanghai_day(ts: float | None = None) -> str:
    t = time.time() if ts is None else ts
    return datetime.fromtimestamp(t, SHANGHAI_TZ).strftime("%Y-%m-%d")


def utc_day(ts: float | None = None) -> date:
    t = time.time() if ts is None else ts
    return datetime.fromtimestamp(t, timezone.utc).date()


def normalize_ip_source(url_or_source: str | None) -> str:
    """规范化观测端点 URI（保留 scheme/host/port/path/query，剥离 user:pass 凭据与 fragment）。"""
    if not url_or_source:
        return "unknown"
    s = url_or_source.strip()
    if s == "legacy_mixed":
        return s
    if "://" not in s:
        return s.lower()
    u = urllib.parse.urlsplit(s)
    scheme = u.scheme.lower()
    host = (u.hostname or "").lower()
    if not host:
        return "unknown"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = u.port
    except ValueError:
        port = None
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if (not port or default_port) else f"{host}:{port}"
    path = u.path if u.path and u.path != "/" else ""
    return urllib.parse.urlunsplit((scheme, netloc, path, u.query, ""))


def parse_and_validate_exit_ip(
    raw_text: str | None,
    allowed_family: str = "4",
    *,
    require_global: bool = True,
) -> tuple[str | None, str | None, str]:
    """严格校验出口 IP：必须为单个合法公网 IP，拒绝多值/XFF 列表/私网/HTML/错误协议栈。"""
    if raw_text is None:
        return None, None, "ip_empty"
    s = raw_text.strip()
    if not s:
        return None, None, "ip_empty"
    if "," in s or "\n" in s or "\r" in s or len(s.split()) != 1:
        return None, None, "ip_multi"
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None, None, "ip_invalid"
    if require_global and not addr.is_global:
        return None, None, "ip_non_global"
    fam = (allowed_family or "any").lower()
    if fam in ("4", "ipv4") and addr.version != 4:
        return None, None, "ip_family"
    if fam in ("6", "ipv6") and addr.version != 6:
        return None, None, "ip_family"
    return addr.compressed, f"ipv{addr.version}", "ok"


@dataclass
class ProbeRecord:
    link: str
    status: str                  # "good" | "failed"
    exit_ip: str | None          # 仅 status=="good" 且取到合法公网 IP 时非空
    reason: str                  # "ok" | "parse" | "engine" | "917" | "ip_http" | "ip_invalid" | ...
    ts: float
    stage: str                   # "retest" | "reclaim" | "candidate" | "retry" | "verify"
    seq: int                     # 同 run_key + stage + link 下的尝试序号（>=1）
    ip_source: str | None = None
    ip_version: str | None = None
    probe_ok: bool | None = None
    duration_ms: int = 0


def _ensure_v2_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS links(
            h TEXT PRIMARY KEY, link TEXT NOT NULL, status TEXT NOT NULL,
            exit_ip TEXT, ip_source TEXT, ip_version TEXT,
            ok_days INTEGER NOT NULL DEFAULT 0, last_ok_day TEXT, updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_links_status_ip ON links(status, exit_ip);
        CREATE INDEX IF NOT EXISTS idx_links_failed_updated ON links(status, updated_at) WHERE exit_ip IS NULL;

        CREATE TABLE IF NOT EXISTS runs(
            run_key TEXT PRIMARY KEY, run_id TEXT NOT NULL, run_attempt INTEGER NOT NULL DEFAULT 1,
            started_at REAL NOT NULL, ended_at REAL, start_day TEXT NOT NULL, end_day TEXT,
            status TEXT NOT NULL, ip_source TEXT,
            tested_count INTEGER NOT NULL DEFAULT 0, probe_ok_count INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0, fail_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS observations(
            obs_id TEXT PRIMARY KEY, run_key TEXT NOT NULL, ts REAL NOT NULL, day TEXT NOT NULL,
            h TEXT NOT NULL, status TEXT NOT NULL, probe_ok INTEGER NOT NULL DEFAULT 0,
            exit_ip TEXT, ip_source TEXT, ip_version TEXT, reason TEXT,
            stage TEXT NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_obs_day ON observations(day);

        CREATE TABLE IF NOT EXISTS daily_ip_links(
            day TEXT NOT NULL, exit_ip TEXT NOT NULL, ip_source TEXT NOT NULL, ip_version TEXT NOT NULL,
            h TEXT NOT NULL, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
            success_count INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(day, exit_ip, ip_source, ip_version, h)
        );
        CREATE INDEX IF NOT EXISTS idx_dil_ip_day ON daily_ip_links(exit_ip, ip_source, ip_version, day);

        CREATE TABLE IF NOT EXISTS daily_ip_runs(
            day TEXT NOT NULL, exit_ip TEXT NOT NULL, ip_source TEXT NOT NULL, ip_version TEXT NOT NULL,
            run_key TEXT NOT NULL,
            PRIMARY KEY(day, exit_ip, ip_source, ip_version, run_key)
        );
        CREATE TABLE IF NOT EXISTS daily_link_status(
            day TEXT NOT NULL, h TEXT NOT NULL, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
            tested_count INTEGER NOT NULL DEFAULT 0, probe_ok_count INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0, fail_count INTEGER NOT NULL DEFAULT 0,
            last_status TEXT NOT NULL, last_exit_ip TEXT, last_ip_source TEXT,
            last_ip_version TEXT, last_reason TEXT,
            PRIMARY KEY(day, h)
        );
        CREATE TABLE IF NOT EXISTS collection_days(
            day TEXT PRIMARY KEY, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
            run_count INTEGER NOT NULL DEFAULT 0, completed_runs INTEGER NOT NULL DEFAULT 0,
            interrupted_runs INTEGER NOT NULL DEFAULT 0, tested_observations INTEGER NOT NULL DEFAULT 0,
            probe_ok_observations INTEGER NOT NULL DEFAULT 0, success_observations INTEGER NOT NULL DEFAULT 0,
            fail_observations INTEGER NOT NULL DEFAULT 0
        );
        """
    )


def _ro_connect(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True, check_same_thread=False)


def read_epoch(db_path: Path) -> str | None:
    """只读查看纪元。文件不存在、不是本结构或没有 epoch 时返回 None，不创建、不修改文件。"""
    if not db_path.exists() or db_path.stat().st_size == 0:
        return None
    try:
        conn = _ro_connect(db_path)
    except sqlite3.Error:
        return None
    try:
        chk = conn.execute("PRAGMA quick_check").fetchone()
        if not chk or chk[0] != "ok":
            return None
        has_meta = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if not has_meta:
            return None
        row = conn.execute("SELECT v FROM meta WHERE k='epoch'").fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def db_is_current_epoch(db_path: Path) -> bool:
    return read_epoch(db_path) == EPOCH


def write_sqlite_sha256(sqlite_path: Path, checksum_path: Path) -> None:
    """校验和只写文件名，不写 data/ 前缀。下载目录里的文件名就是 state.sqlite。"""
    digest = hashlib.sha256(sqlite_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {sqlite_path.name}\n", encoding="utf-8")


def verify_sqlite_sha256(checksum_path: Path, directory: Path) -> tuple[bool, str]:
    """按下载目录里的文件名核对。清单写成 data/state.sqlite 时也只取最后一段文件名。"""
    if not checksum_path.is_file():
        return False, "missing_checksum"
    lines = [ln for ln in checksum_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return False, "empty_checksum"
    parts = lines[0].split()
    if len(parts) < 2:
        return False, "bad_checksum_line"
    digest, listed = parts[0], parts[-1]
    target = directory / Path(listed).name
    if not target.is_file():
        return False, f"missing_file:{listed}"
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    if actual.lower() != digest.lower():
        return False, "hash_mismatch"
    return True, "ok"


def classify_snapshot(directory: Path, *, is_draft: bool, is_prerelease: bool) -> str:
    """先看纪元，再看校验和。返回 restorable、archive 或 broken。

    archive：没有本纪元标记（旧 Release、ops 隧道发布、草稿）。不读校验和。
    broken：有本纪元标记，但校验和或库内容对不上。禁止当成“没有快照”去 bootstrap。
    restorable：纪元、校验和、库内容都通过。预发布只要这三项通过也可以恢复。
    """
    del is_prerelease  # 完整性通过即可恢复；半截上传会在校验和处变成 broken
    if is_draft:
        return "archive"
    epoch_file = directory / "epoch.txt"
    if not epoch_file.is_file():
        return "archive"
    if epoch_file.read_text(encoding="utf-8").strip() != EPOCH:
        return "archive"
    ok, _reason = verify_sqlite_sha256(directory / "state.sqlite.sha256", directory)
    if not ok:
        return "broken"
    if not db_is_current_epoch(directory / "state.sqlite"):
        return "broken"
    return "restorable"


def allow_empty_bootstrap(statuses: list[str]) -> bool:
    """只有全部都是 archive（或一个都没有）才允许空库。出现 broken 或 restorable 都不行。"""
    return not any(status in ("broken", "restorable") for status in statuses)


def ops_release_tag(run_id: str, run_attempt: int | str) -> str:
    rid = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in str(run_id)) or "local"
    return f"ops-{rid}-{int(run_attempt)}"


def release_restorable(*, epoch_text: str, checksum_ok: bool, is_prerelease: bool, is_draft: bool) -> bool:
    """草稿不能恢复。预发布只要纪元和校验和已经通过，就不是半截文件。"""
    del is_prerelease
    return (not is_draft) and bool(checksum_ok) and epoch_text.strip() == EPOCH


def release_tag(run_id: str, run_attempt: int | str, ts: float | None = None) -> str:
    t = time.time() if ts is None else ts
    stamp = datetime.fromtimestamp(t, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rid = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in str(run_id)) or "local"
    return f"run-{stamp}-{rid}-{int(run_attempt)}"


def open_db(db_path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    """打开本纪元数据库。已有文件但纪元不符时直接拒绝，不迁移、不改写。"""
    if readonly:
        if not db_is_current_epoch(db_path):
            raise RuntimeError(f"拒绝只读打开非本纪元数据库: {db_path}")
        return _ro_connect(db_path)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    if not db_path.exists() or db_path.stat().st_size == 0:
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        with conn:
            _ensure_v2_tables(conn)
            conn.execute("INSERT INTO meta(k, v) VALUES('epoch', ?)", (EPOCH,))
            conn.execute("INSERT INTO meta(k, v) VALUES('created_at', ?)", (str(time.time()),))
        return conn

    if not db_is_current_epoch(db_path):
        raise RuntimeError(
            f"拒绝打开纪元不是 {EPOCH} 的数据库 {db_path}。旧 Release/Artifact 只作归档，不能恢复进来。"
        )
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def remember_links(conn: sqlite3.Connection, links: list[str], seen_at: float | None = None) -> int:
    """把新链接记为 pending。已存在的不改状态；未探测不是失败。"""
    now = time.time() if seen_at is None else seen_at
    added = 0
    with conn:
        for link in links:
            norm = normalize_link(link)
            if not norm:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO links(h, link, status, ok_days, updated_at) VALUES(?, ?, 'pending', 0, ?)",
                (link_hash(norm), norm, now),
            )
            added += cur.rowcount
    return added


def make_run_key(run_id: str | None = None, run_attempt: int | str | None = None) -> tuple[str, str, int]:
    rid = str(run_id or os.environ.get("GITHUB_RUN_ID") or f"local-{int(time.time() * 1000)}")
    att = int(run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT") or 1)
    return f"{rid}:{att}", rid, att


def make_obs_id(run_key: str, stage: str, h: str, seq: int) -> str:
    return f"{run_key}:{stage}:{h}:{seq}"


def begin_run(
    conn: sqlite3.Connection,
    run_id: str | None = None,
    run_attempt: int | str | None = None,
    started_at: float | None = None,
    ip_source: str = DEFAULT_IP_SOURCE,
) -> str:
    now = time.time() if started_at is None else started_at
    day = shanghai_day(now)
    run_key, rid, att = make_run_key(run_id, run_attempt)
    src = normalize_ip_source(ip_source)

    with conn:
        for old_key, old_day in conn.execute(
            "SELECT run_key, start_day FROM runs WHERE status='running' AND run_key!=?", (run_key,)
        ).fetchall():
            conn.execute("UPDATE runs SET status='interrupted', ended_at=?, end_day=? WHERE run_key=?", (now, day, old_key))
            conn.execute(
                "INSERT INTO collection_days(day, first_ts, last_ts, run_count, interrupted_runs) VALUES(?,?,?,0,1) "
                "ON CONFLICT(day) DO UPDATE SET last_ts=MAX(collection_days.last_ts, excluded.last_ts), "
                "interrupted_runs=collection_days.interrupted_runs+1",
                (old_day, now, now),
            )

        if not conn.execute("SELECT 1 FROM runs WHERE run_key=?", (run_key,)).fetchone():
            conn.execute(
                "INSERT INTO runs(run_key, run_id, run_attempt, started_at, start_day, status, ip_source) "
                "VALUES(?,?,?,?,?,'running',?)",
                (run_key, rid, att, now, day, src),
            )
            conn.execute(
                "INSERT INTO collection_days(day, first_ts, last_ts, run_count) VALUES(?,?,?,1) "
                "ON CONFLICT(day) DO UPDATE SET first_ts=MIN(collection_days.first_ts, excluded.first_ts), "
                "last_ts=MAX(collection_days.last_ts, excluded.last_ts), run_count=collection_days.run_count+1",
                (day, now, now),
            )
        else:
            conn.execute("UPDATE runs SET status='running', ended_at=NULL, end_day=NULL WHERE run_key=?", (run_key,))
    return run_key


def end_run(conn: sqlite3.Connection, run_key: str, status: str = "completed", ended_at: float | None = None) -> None:
    now = time.time() if ended_at is None else ended_at
    day = shanghai_day(now)
    with conn:
        row = conn.execute("SELECT status, start_day FROM runs WHERE run_key=?", (run_key,)).fetchone()
        if not row:
            return
        prev_status, start_day = row
        conn.execute("UPDATE runs SET status=?, ended_at=?, end_day=? WHERE run_key=?", (status, now, day, run_key))
        if prev_status == "running":
            col = "completed_runs" if status == "completed" else "interrupted_runs"
            conn.execute(
                f"INSERT INTO collection_days(day, first_ts, last_ts, run_count, {col}) VALUES(?,?,?,1,1) "
                f"ON CONFLICT(day) DO UPDATE SET last_ts=MAX(collection_days.last_ts, excluded.last_ts), "
                f"{col}=collection_days.{col}+1",
                (start_day, now, now),
            )


def _bump_ok_days(prev_ok_days: int, prev_last_ok_day: str | None, ts: float) -> tuple[int, str]:
    """单链接连续成功天数，按 UTC 日期。只由实际探测更新。"""
    d = utc_day(ts)
    today_s = d.isoformat()
    yesterday_s = (d - timedelta(days=1)).isoformat()
    ok_days = prev_ok_days or 0
    if prev_last_ok_day == today_s:
        return max(1, ok_days), today_s
    if prev_last_ok_day == yesterday_s:
        return ok_days + 1, today_s
    return 1, today_s


def record_probe_batch(
    conn: sqlite3.Connection,
    run_key: str,
    records: list[ProbeRecord],
    *,
    default_ip_source: str = DEFAULT_IP_SOURCE,
) -> tuple[int, int]:
    """单事务原子批量写入观测、更新当前状态及按 (exit_ip, ip_source, ip_version) 区分的每日聚合。"""
    if not records:
        return 0, 0

    inserted = good_in_batch = 0
    with conn:
        for rec in records:
            norm_link = normalize_link(rec.link)
            h = link_hash(norm_link)

            valid_ip = None
            ip_ver = rec.ip_version
            reason = rec.reason
            if rec.status == "good":
                if rec.exit_ip:
                    valid_ip, detected_ver, v_reason = parse_and_validate_exit_ip(
                        rec.exit_ip, allowed_family="any", require_global=True
                    )
                    if valid_ip:
                        ip_ver = ip_ver or detected_ver
                    else:
                        reason = v_reason
                else:
                    reason = reason if (reason and reason != "ok") else "ip_empty"

            is_good = rec.status == "good" and bool(valid_ip)
            status = "good" if is_good else "failed"
            obs_ip = valid_ip if is_good else None
            has_ip_attempt = is_good or (reason or "").startswith("ip")
            obs_src = normalize_ip_source(rec.ip_source or default_ip_source) if has_ip_attempt else None
            obs_ver = ip_ver if is_good else None
            probe_ok_int = (
                (1 if rec.probe_ok else 0)
                if rec.probe_ok is not None
                else (1 if has_ip_attempt else 0)
            )
            day = shanghai_day(rec.ts)
            obs_id = make_obs_id(run_key, rec.stage, h, rec.seq)

            cur = conn.execute(
                "INSERT OR IGNORE INTO observations("
                "obs_id, run_key, ts, day, h, status, probe_ok, exit_ip, ip_source, ip_version, reason, stage, duration_ms"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (obs_id, run_key, rec.ts, day, h, status, probe_ok_int, obs_ip, obs_src, obs_ver, reason, rec.stage, rec.duration_ms),
            )
            if cur.rowcount == 0:
                continue

            inserted += 1
            good_in_batch += int(is_good)

            prev = conn.execute("SELECT ok_days, last_ok_day FROM links WHERE h=?", (h,)).fetchone()
            if is_good:
                ok_days, last_ok = _bump_ok_days(prev[0] if prev else 0, prev[1] if prev else None, rec.ts)
            else:
                ok_days, last_ok = 0, None

            conn.execute(
                """
                INSERT INTO links(h, link, status, exit_ip, ip_source, ip_version, ok_days, last_ok_day, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(h) DO UPDATE SET
                    link = excluded.link,
                    status = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.status ELSE links.status END,
                    exit_ip = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.exit_ip ELSE links.exit_ip END,
                    ip_source = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.ip_source ELSE links.ip_source END,
                    ip_version = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.ip_version ELSE links.ip_version END,
                    ok_days = CASE WHEN excluded.status='good' OR excluded.updated_at >= links.updated_at THEN excluded.ok_days ELSE links.ok_days END,
                    last_ok_day = CASE WHEN excluded.status='good' OR excluded.updated_at >= links.updated_at THEN excluded.last_ok_day ELSE links.last_ok_day END,
                    updated_at = MAX(links.updated_at, excluded.updated_at)
                """,
                (h, norm_link, status, obs_ip, obs_src if is_good else None, obs_ver, ok_days, last_ok, rec.ts),
            )

            if is_good and obs_ip and obs_src and obs_ver:
                conn.execute(
                    """
                    INSERT INTO daily_ip_links(day, exit_ip, ip_source, ip_version, h, first_ts, last_ts, success_count)
                    VALUES(?,?,?,?,?,?,?,1)
                    ON CONFLICT(day, exit_ip, ip_source, ip_version, h) DO UPDATE SET
                        first_ts = MIN(daily_ip_links.first_ts, excluded.first_ts),
                        last_ts = MAX(daily_ip_links.last_ts, excluded.last_ts),
                        success_count = daily_ip_links.success_count + 1
                    """,
                    (day, obs_ip, obs_src, obs_ver, h, rec.ts, rec.ts),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO daily_ip_runs(day, exit_ip, ip_source, ip_version, run_key) VALUES(?,?,?,?,?)",
                    (day, obs_ip, obs_src, obs_ver, run_key),
                )

            conn.execute(
                """
                INSERT INTO daily_link_status(
                    day, h, first_ts, last_ts, tested_count, probe_ok_count, success_count, fail_count,
                    last_status, last_exit_ip, last_ip_source, last_ip_version, last_reason
                ) VALUES(?,?,?,?,1,?,?,?,?,?,?,?,?)
                ON CONFLICT(day, h) DO UPDATE SET
                    first_ts = MIN(daily_link_status.first_ts, excluded.first_ts),
                    last_status = CASE WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_status ELSE daily_link_status.last_status END,
                    last_exit_ip = CASE WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_exit_ip ELSE daily_link_status.last_exit_ip END,
                    last_ip_source = CASE WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_ip_source ELSE daily_link_status.last_ip_source END,
                    last_ip_version = CASE WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_ip_version ELSE daily_link_status.last_ip_version END,
                    last_reason = CASE WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_reason ELSE daily_link_status.last_reason END,
                    last_ts = MAX(daily_link_status.last_ts, excluded.last_ts),
                    tested_count = daily_link_status.tested_count + 1,
                    probe_ok_count = daily_link_status.probe_ok_count + excluded.probe_ok_count,
                    success_count = daily_link_status.success_count + excluded.success_count,
                    fail_count = daily_link_status.fail_count + excluded.fail_count
                """,
                (day, h, rec.ts, rec.ts, probe_ok_int, int(is_good), int(not is_good), status, obs_ip, obs_src, obs_ver, reason),
            )
            conn.execute(
                "UPDATE runs SET tested_count=tested_count+1, probe_ok_count=probe_ok_count+?, "
                "success_count=success_count+?, fail_count=fail_count+? WHERE run_key=?",
                (probe_ok_int, int(is_good), int(not is_good), run_key),
            )
            conn.execute(
                """
                INSERT INTO collection_days(day, first_ts, last_ts, tested_observations, probe_ok_observations, success_observations, fail_observations)
                VALUES(?,?,?,1,?,?,?)
                ON CONFLICT(day) DO UPDATE SET
                    first_ts = MIN(collection_days.first_ts, excluded.first_ts),
                    last_ts = MAX(collection_days.last_ts, excluded.last_ts),
                    tested_observations = collection_days.tested_observations + 1,
                    probe_ok_observations = collection_days.probe_ok_observations + excluded.probe_ok_observations,
                    success_observations = collection_days.success_observations + excluded.success_observations,
                    fail_observations = collection_days.fail_observations + excluded.fail_observations
                """,
                (day, rec.ts, rec.ts, probe_ok_int, int(is_good), int(not is_good)),
            )

    return inserted, good_in_batch


def purge_old_observations(
    conn: sqlite3.Connection,
    retention_days: int = RAW_RETENTION_DAYS,
    now_ts: float | None = None,
    vacuum: bool = False,
) -> int:
    if retention_days <= 0:
        return 0
    t = time.time() if now_ts is None else now_ts
    cutoff_day = (datetime.fromtimestamp(t, SHANGHAI_TZ).date() - timedelta(days=retention_days)).isoformat()
    with conn:
        deleted = conn.execute("DELETE FROM observations WHERE day < ?", (cutoff_day,)).rowcount
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if vacuum and deleted > 0:
        conn.execute("VACUUM")
    return deleted
