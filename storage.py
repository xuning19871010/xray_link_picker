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

SCHEMA_VERSION = 2
SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
RAW_RETENTION_DAYS = int(os.environ.get("RAW_RETENTION_DAYS", "30"))
DEFAULT_IP_SOURCE = "checkip.amazonaws.com"


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


def extract_ip_source(url_or_source: str | None) -> str:
    """从测量 URL 或标识中提取稳定的 ip_source 名称（如 checkip.amazonaws.com）。"""
    if not url_or_source:
        return "unknown"
    s = url_or_source.strip()
    if "://" in s:
        u = urllib.parse.urlparse(s)
        host = (u.netloc or u.path).strip().lower()
        return host or "unknown"
    return s.lower()


def parse_and_validate_exit_ip(
    raw_text: str | None,
    allowed_family: str = "4",
    *,
    require_global: bool = True,
) -> tuple[str | None, str | None, str]:
    """严格校验出口 IP 响应文本，拒绝多 IP / X-Forwarded-For 列表 / HTML / 非法地址 / 非公网地址。

    返回: (canonical_ip, ip_version['ipv4'|'ipv6'], reason['ok'|'ip_empty'|'ip_multi'|'ip_invalid'|'ip_non_global'|'ip_family'])
    """
    if raw_text is None:
        return None, None, "ip_empty"
    s = raw_text.strip()
    if not s:
        return None, None, "ip_empty"
    # 拒绝多行、逗号分隔（常见于未校验 X-Forwarded-For 拼接）或空白分隔的多值输出
    if "," in s or "\n" in s or "\r" in s or len(s.split()) != 1:
        return None, None, "ip_multi"
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None, None, "ip_invalid"

    if require_global and not addr.is_global:
        return None, None, "ip_non_global"

    ver = f"ipv{addr.version}"
    fam = (allowed_family or "any").lower()
    if fam in ("4", "ipv4") and addr.version != 4:
        return None, None, "ip_family"
    if fam in ("6", "ipv6") and addr.version != 6:
        return None, None, "ip_family"

    return addr.compressed, ver, "ok"


@dataclass
class ProbeRecord:
    link: str
    status: str                  # "good" | "failed"
    exit_ip: str | None          # 仅 status=="good" 且取到合法出口 IP 时非空
    reason: str                  # "ok" | "parse" | "engine" | "917" | "ip_http" | "ip_invalid" | "ip_multi" | ...
    ts: float
    stage: str                   # "retest" | "reclaim" | "candidate" | "retry" | "verify"
    seq: int                     # 同 run_attempt + stage + link 下的尝试序号（从 1 开始）
    ip_source: str | None = None # 观测端点标识，如 "checkip.amazonaws.com"
    ip_version: str | None = None  # "ipv4" | "ipv6"
    probe_ok: bool | None = None   # 是否已通过连通性探针（区分连通成功但 IP 获取失败）
    duration_ms: int = 0


def _ensure_v2_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta(
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS links(
            h TEXT PRIMARY KEY,
            link TEXT NOT NULL,
            status TEXT NOT NULL,
            exit_ip TEXT,
            ip_source TEXT,
            ip_version TEXT,
            ok_days INTEGER NOT NULL DEFAULT 0,
            last_ok_day TEXT,
            updated_at REAL NOT NULL,
            first_seen_at REAL
        );

        CREATE INDEX IF NOT EXISTS idx_links_status_ip
            ON links(status, exit_ip);
        CREATE INDEX IF NOT EXISTS idx_links_failed_updated
            ON links(status, updated_at) WHERE exit_ip IS NULL;

        CREATE TABLE IF NOT EXISTS runs(
            run_key TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            run_attempt INTEGER NOT NULL DEFAULT 1,
            started_at REAL NOT NULL,
            ended_at REAL,
            start_day TEXT NOT NULL,
            end_day TEXT,
            status TEXT NOT NULL,
            ip_source TEXT,
            tested_count INTEGER NOT NULL DEFAULT 0,
            probe_ok_count INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0,
            fail_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS observations(
            obs_id TEXT PRIMARY KEY,
            run_key TEXT NOT NULL,
            ts REAL NOT NULL,
            day TEXT NOT NULL,
            h TEXT NOT NULL,
            status TEXT NOT NULL,
            probe_ok INTEGER NOT NULL DEFAULT 0,
            exit_ip TEXT,
            ip_source TEXT,
            ip_version TEXT,
            reason TEXT,
            stage TEXT NOT NULL,
            duration_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_obs_day ON observations(day);
        CREATE INDEX IF NOT EXISTS idx_obs_ip_day ON observations(exit_ip, ip_source, ip_version, day)
            WHERE status='good' AND exit_ip IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_obs_h_day ON observations(h, day);

        CREATE TABLE IF NOT EXISTS daily_ip_links(
            day TEXT NOT NULL,
            exit_ip TEXT NOT NULL,
            ip_source TEXT NOT NULL,
            ip_version TEXT NOT NULL,
            h TEXT NOT NULL,
            first_ts REAL NOT NULL,
            last_ts REAL NOT NULL,
            success_count INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(day, exit_ip, ip_source, ip_version, h)
        );
        CREATE INDEX IF NOT EXISTS idx_dil_ip_day
            ON daily_ip_links(exit_ip, ip_source, ip_version, day);

        CREATE TABLE IF NOT EXISTS daily_ip_runs(
            day TEXT NOT NULL,
            exit_ip TEXT NOT NULL,
            ip_source TEXT NOT NULL,
            ip_version TEXT NOT NULL,
            run_key TEXT NOT NULL,
            PRIMARY KEY(day, exit_ip, ip_source, ip_version, run_key)
        );

        CREATE TABLE IF NOT EXISTS daily_link_status(
            day TEXT NOT NULL,
            h TEXT NOT NULL,
            first_ts REAL NOT NULL,
            last_ts REAL NOT NULL,
            tested_count INTEGER NOT NULL DEFAULT 0,
            probe_ok_count INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0,
            fail_count INTEGER NOT NULL DEFAULT 0,
            last_status TEXT NOT NULL,
            last_exit_ip TEXT,
            last_ip_source TEXT,
            last_ip_version TEXT,
            last_reason TEXT,
            PRIMARY KEY(day, h)
        );

        CREATE TABLE IF NOT EXISTS collection_days(
            day TEXT PRIMARY KEY,
            first_ts REAL NOT NULL,
            last_ts REAL NOT NULL,
            run_count INTEGER NOT NULL DEFAULT 0,
            completed_runs INTEGER NOT NULL DEFAULT 0,
            interrupted_runs INTEGER NOT NULL DEFAULT 0,
            tested_observations INTEGER NOT NULL DEFAULT 0,
            probe_ok_observations INTEGER NOT NULL DEFAULT 0,
            success_observations INTEGER NOT NULL DEFAULT 0,
            fail_observations INTEGER NOT NULL DEFAULT 0
        );
        """
    )


def backup_sqlite(src_conn: sqlite3.Connection, backup_path: Path) -> None:
    """使用 SQLite 在线备份 API 安全拷贝（兼容活跃 WAL）。"""
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    if backup_path.exists():
        backup_path.unlink()
    dst_conn = sqlite3.connect(str(backup_path))
    try:
        with dst_conn:
            src_conn.backup(dst_conn)
    finally:
        dst_conn.close()


def get_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    if not row:
        has_links = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='links'"
        ).fetchone()
        return 1 if has_links else 0
    v_row = conn.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
    return int(v_row[0]) if v_row else 1


def _ensure_links_columns(conn: sqlite3.Connection) -> None:
    has_links = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='links'"
    ).fetchone()
    if not has_links:
        return
    cols = {r[1] for r in conn.execute("PRAGMA table_info(links)")}
    if "ok_days" not in cols:
        conn.execute(
            "ALTER TABLE links ADD COLUMN ok_days INTEGER NOT NULL DEFAULT 0"
        )
    if "last_ok_day" not in cols:
        conn.execute("ALTER TABLE links ADD COLUMN last_ok_day TEXT")
    if "first_seen_at" not in cols:
        conn.execute("ALTER TABLE links ADD COLUMN first_seen_at REAL")
        conn.execute(
            "UPDATE links SET first_seen_at = updated_at WHERE first_seen_at IS NULL"
        )
    if "ip_source" not in cols:
        conn.execute("ALTER TABLE links ADD COLUMN ip_source TEXT")
        conn.execute(
            "UPDATE links SET ip_source = 'legacy_mixed' WHERE exit_ip IS NOT NULL AND ip_source IS NULL"
        )
    if "ip_version" not in cols:
        conn.execute("ALTER TABLE links ADD COLUMN ip_version TEXT")
        conn.execute(
            """
            UPDATE links
            SET ip_version = CASE WHEN instr(exit_ip, ':') > 0 THEN 'ipv6' ELSE 'ipv4' END
            WHERE exit_ip IS NOT NULL AND ip_version IS NULL
            """
        )


def open_db(db_path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    """打开数据库连接；可写模式下自动执行幂等迁移（失败自动回滚备份）。"""
    if readonly:
        if not db_path.exists():
            raise FileNotFoundError(f"数据库文件不存在: {db_path}")
        uri = f"file:{db_path.resolve()}?mode=ro"
        return sqlite3.connect(uri, uri=True, check_same_thread=False)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    existed_before = db_path.exists() and db_path.stat().st_size > 0
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    ver = get_schema_version(conn)
    if ver >= SCHEMA_VERSION:
        _ensure_links_columns(conn)
        _ensure_v2_tables(conn)
        conn.commit()
        return conn

    backup_path = db_path.with_suffix(".sqlite.v1.bak")
    if existed_before and ver == 1:
        backup_sqlite(conn, backup_path)

    try:
        with conn:
            _ensure_links_columns(conn)
            # 移除 v1 的 idx_ip 唯一索引：允许多条同出口 IP 的链接同时保持 status='good'
            conn.execute("DROP INDEX IF EXISTS idx_ip")
            _ensure_v2_tables(conn)
            now_s = str(time.time())
            conn.execute(
                "INSERT OR IGNORE INTO meta(k, v) VALUES('migrated_at', ?)",
                (now_s,),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(k, v) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
    except Exception:
        conn.close()
        if existed_before and backup_path.exists():
            restore_src = sqlite3.connect(str(backup_path))
            restore_dst = sqlite3.connect(str(db_path))
            try:
                with restore_dst:
                    restore_src.backup(restore_dst)
            finally:
                restore_src.close()
                restore_dst.close()
        raise

    return conn


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
    """开启一轮探测，并将遗留未完结的旧 run 标记为 interrupted。"""
    now = time.time() if started_at is None else started_at
    day = shanghai_day(now)
    run_key, rid, att = make_run_key(run_id, run_attempt)
    src = extract_ip_source(ip_source)

    with conn:
        stale = conn.execute(
            "SELECT run_key, start_day FROM runs WHERE status='running' AND run_key!=?",
            (run_key,),
        ).fetchall()
        for old_key, old_day in stale:
            conn.execute(
                "UPDATE runs SET status='interrupted', ended_at=?, end_day=? WHERE run_key=?",
                (now, day, old_key),
            )
            conn.execute(
                """
                INSERT INTO collection_days(day, first_ts, last_ts, run_count, interrupted_runs)
                VALUES(?, ?, ?, 0, 1)
                ON CONFLICT(day) DO UPDATE SET
                    last_ts = MAX(collection_days.last_ts, excluded.last_ts),
                    interrupted_runs = collection_days.interrupted_runs + 1
                """,
                (old_day, now, now),
            )

        existing = conn.execute(
            "SELECT status FROM runs WHERE run_key=?", (run_key,)
        ).fetchone()
        if not existing:
            conn.execute(
                """
                INSERT INTO runs(run_key, run_id, run_attempt, started_at, start_day, status, ip_source)
                VALUES(?, ?, ?, ?, ?, 'running', ?)
                """,
                (run_key, rid, att, now, day, src),
            )
            conn.execute(
                """
                INSERT INTO collection_days(day, first_ts, last_ts, run_count)
                VALUES(?, ?, ?, 1)
                ON CONFLICT(day) DO UPDATE SET
                    first_ts = MIN(collection_days.first_ts, excluded.first_ts),
                    last_ts = MAX(collection_days.last_ts, excluded.last_ts),
                    run_count = collection_days.run_count + 1
                """,
                (day, now, now),
            )
        else:
            conn.execute(
                "UPDATE runs SET status='running', ended_at=NULL, end_day=NULL WHERE run_key=?",
                (run_key,),
            )

    return run_key


def end_run(
    conn: sqlite3.Connection,
    run_key: str,
    status: str = "completed",
    ended_at: float | None = None,
) -> None:
    now = time.time() if ended_at is None else ended_at
    day = shanghai_day(now)
    with conn:
        row = conn.execute(
            "SELECT status, start_day FROM runs WHERE run_key=?", (run_key,)
        ).fetchone()
        if not row:
            return
        prev_status, start_day = row
        conn.execute(
            "UPDATE runs SET status=?, ended_at=?, end_day=? WHERE run_key=?",
            (status, now, day, run_key),
        )
        if prev_status == "running":
            col = "completed_runs" if status == "completed" else "interrupted_runs"
            conn.execute(
                f"""
                INSERT INTO collection_days(day, first_ts, last_ts, run_count, {col})
                VALUES(?, ?, ?, 1, 1)
                ON CONFLICT(day) DO UPDATE SET
                    last_ts = MAX(collection_days.last_ts, excluded.last_ts),
                    {col} = collection_days.{col} + 1
                """,
                (start_day, now, now),
            )


def _bump_ok_days_legacy_utc(
    prev_ok_days: int, prev_last_ok_day: str | None, ts: float
) -> tuple[int, str]:
    """保持与旧版一致的 UTC 口径单链接连续天数累加。"""
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
    """单事务原子批量写入观测、更新当前状态及按 (exit_ip, ip_source, ip_version) 区分的每日聚合。

    返回 (inserted_count, newly_good_link_count)。
    """
    if not records:
        return 0, 0

    inserted = 0
    good_in_batch = 0

    with conn:
        for rec in records:
            norm_link = normalize_link(rec.link)
            h = link_hash(norm_link)

            # 校验并规范化出口 IP 与版本；非法/多值 IP 直接视作失败
            valid_ip = None
            ip_ver = rec.ip_version
            reason = rec.reason
            if rec.status == "good" and rec.exit_ip:
                valid_ip, detected_ver, v_reason = parse_and_validate_exit_ip(
                    rec.exit_ip, allowed_family="any", require_global=True
                )
                if valid_ip:
                    ip_ver = ip_ver or detected_ver
                else:
                    reason = v_reason

            is_good = rec.status == "good" and bool(valid_ip)
            status = "good" if is_good else "failed"
            # 失败观测绝不绑定旧 exit_ip
            obs_ip = valid_ip if is_good else None
            obs_src = extract_ip_source(rec.ip_source or default_ip_source) if (is_good or (rec.reason or "").startswith("ip")) else None
            obs_ver = ip_ver if is_good else None

            if rec.probe_ok is not None:
                probe_ok_int = 1 if rec.probe_ok else 0
            else:
                probe_ok_int = 1 if (is_good or (reason or "").startswith("ip")) else 0

            day = shanghai_day(rec.ts)
            obs_id = make_obs_id(run_key, rec.stage, h, rec.seq)

            cur = conn.execute(
                """
                INSERT OR IGNORE INTO observations(
                    obs_id, run_key, ts, day, h, status, probe_ok,
                    exit_ip, ip_source, ip_version, reason, stage, duration_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs_id,
                    run_key,
                    rec.ts,
                    day,
                    h,
                    status,
                    probe_ok_int,
                    obs_ip,
                    obs_src,
                    obs_ver,
                    reason,
                    rec.stage,
                    rec.duration_ms,
                ),
            )
            if cur.rowcount == 0:
                continue

            inserted += 1
            if is_good:
                good_in_batch += 1

            # 1) 更新 links 当前状态（仅当观测时间戳 >= 已有 updated_at 时覆盖当前状态）
            prev = conn.execute(
                "SELECT ok_days, last_ok_day, first_seen_at, updated_at FROM links WHERE h=?",
                (h,),
            ).fetchone()
            first_seen = prev[2] if (prev and prev[2] is not None) else rec.ts

            if is_good:
                ok_days, last_ok = _bump_ok_days_legacy_utc(
                    prev[0] if prev else 0,
                    prev[1] if prev else None,
                    rec.ts,
                )
                conn.execute(
                    """
                    INSERT INTO links(
                        h, link, status, exit_ip, ip_source, ip_version,
                        ok_days, last_ok_day, updated_at, first_seen_at
                    )
                    VALUES(?, ?, 'good', ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(h) DO UPDATE SET
                        link = excluded.link,
                        status = CASE WHEN excluded.updated_at >= links.updated_at THEN 'good' ELSE links.status END,
                        exit_ip = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.exit_ip ELSE links.exit_ip END,
                        ip_source = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.ip_source ELSE links.ip_source END,
                        ip_version = CASE WHEN excluded.updated_at >= links.updated_at THEN excluded.ip_version ELSE links.ip_version END,
                        ok_days = excluded.ok_days,
                        last_ok_day = excluded.last_ok_day,
                        updated_at = MAX(links.updated_at, excluded.updated_at)
                    """,
                    (h, norm_link, obs_ip, obs_src, obs_ver, ok_days, last_ok, rec.ts, first_seen),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO links(
                        h, link, status, exit_ip, ip_source, ip_version,
                        ok_days, last_ok_day, updated_at, first_seen_at
                    )
                    VALUES(?, ?, 'failed', NULL, NULL, NULL, 0, NULL, ?, ?)
                    ON CONFLICT(h) DO UPDATE SET
                        link = excluded.link,
                        status = CASE WHEN excluded.updated_at >= links.updated_at THEN 'failed' ELSE links.status END,
                        exit_ip = CASE WHEN excluded.updated_at >= links.updated_at THEN NULL ELSE links.exit_ip END,
                        ip_source = CASE WHEN excluded.updated_at >= links.updated_at THEN NULL ELSE links.ip_source END,
                        ip_version = CASE WHEN excluded.updated_at >= links.updated_at THEN NULL ELSE links.ip_version END,
                        ok_days = CASE WHEN excluded.updated_at >= links.updated_at THEN 0 ELSE links.ok_days END,
                        last_ok_day = CASE WHEN excluded.updated_at >= links.updated_at THEN NULL ELSE links.last_ok_day END,
                        updated_at = MAX(links.updated_at, excluded.updated_at)
                    """,
                    (h, norm_link, rec.ts, first_seen),
                )

            # 2) 更新每日 (day, exit_ip, ip_source, ip_version, h) 聚合
            if is_good and obs_ip and obs_src and obs_ver:
                conn.execute(
                    """
                    INSERT INTO daily_ip_links(
                        day, exit_ip, ip_source, ip_version, h, first_ts, last_ts, success_count
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(day, exit_ip, ip_source, ip_version, h) DO UPDATE SET
                        first_ts = MIN(daily_ip_links.first_ts, excluded.first_ts),
                        last_ts = MAX(daily_ip_links.last_ts, excluded.last_ts),
                        success_count = daily_ip_links.success_count + 1
                    """,
                    (day, obs_ip, obs_src, obs_ver, h, rec.ts, rec.ts),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO daily_ip_runs(day, exit_ip, ip_source, ip_version, run_key)
                    VALUES(?, ?, ?, ?, ?)
                    """,
                    (day, obs_ip, obs_src, obs_ver, run_key),
                )

            # 3) 更新每日单链接状态聚合
            conn.execute(
                """
                INSERT INTO daily_link_status(
                    day, h, first_ts, last_ts,
                    tested_count, probe_ok_count, success_count, fail_count,
                    last_status, last_exit_ip, last_ip_source, last_ip_version, last_reason
                ) VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(day, h) DO UPDATE SET
                    first_ts = MIN(daily_link_status.first_ts, excluded.first_ts),
                    last_status = CASE
                        WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_status
                        ELSE daily_link_status.last_status
                    END,
                    last_exit_ip = CASE
                        WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_exit_ip
                        ELSE daily_link_status.last_exit_ip
                    END,
                    last_ip_source = CASE
                        WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_ip_source
                        ELSE daily_link_status.last_ip_source
                    END,
                    last_ip_version = CASE
                        WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_ip_version
                        ELSE daily_link_status.last_ip_version
                    END,
                    last_reason = CASE
                        WHEN excluded.last_ts >= daily_link_status.last_ts THEN excluded.last_reason
                        ELSE daily_link_status.last_reason
                    END,
                    last_ts = MAX(daily_link_status.last_ts, excluded.last_ts),
                    tested_count = daily_link_status.tested_count + 1,
                    probe_ok_count = daily_link_status.probe_ok_count + excluded.probe_ok_count,
                    success_count = daily_link_status.success_count + excluded.success_count,
                    fail_count = daily_link_status.fail_count + excluded.fail_count
                """,
                (
                    day,
                    h,
                    rec.ts,
                    rec.ts,
                    probe_ok_int,
                    1 if is_good else 0,
                    0 if is_good else 1,
                    status,
                    obs_ip,
                    obs_src,
                    obs_ver,
                    reason,
                ),
            )

            # 4) 更新 runs 与 collection_days 计数
            conn.execute(
                """
                UPDATE runs SET
                    tested_count = tested_count + 1,
                    probe_ok_count = probe_ok_count + ?,
                    success_count = success_count + ?,
                    fail_count = fail_count + ?
                WHERE run_key = ?
                """,
                (probe_ok_int, 1 if is_good else 0, 0 if is_good else 1, run_key),
            )
            conn.execute(
                """
                INSERT INTO collection_days(
                    day, first_ts, last_ts,
                    tested_observations, probe_ok_observations,
                    success_observations, fail_observations
                ) VALUES(?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(day) DO UPDATE SET
                    first_ts = MIN(collection_days.first_ts, excluded.first_ts),
                    last_ts = MAX(collection_days.last_ts, excluded.last_ts),
                    tested_observations = collection_days.tested_observations + 1,
                    probe_ok_observations = collection_days.probe_ok_observations + excluded.probe_ok_observations,
                    success_observations = collection_days.success_observations + excluded.success_observations,
                    fail_observations = collection_days.fail_observations + excluded.fail_observations
                """,
                (
                    day,
                    rec.ts,
                    rec.ts,
                    probe_ok_int,
                    1 if is_good else 0,
                    0 if is_good else 1,
                ),
            )

    return inserted, good_in_batch


def purge_old_observations(
    conn: sqlite3.Connection,
    retention_days: int = RAW_RETENTION_DAYS,
    now_ts: float | None = None,
    vacuum: bool = False,
) -> int:
    """清理超过 retention_days（按 Asia/Shanghai 自然日）的原始 observations，保留所有每日聚合表。"""
    if retention_days <= 0:
        return 0
    t = time.time() if now_ts is None else now_ts
    today_sh = datetime.fromtimestamp(t, SHANGHAI_TZ).date()
    cutoff_day = (today_sh - timedelta(days=retention_days)).isoformat()
    with conn:
        cur = conn.execute("DELETE FROM observations WHERE day < ?", (cutoff_day,))
        deleted = cur.rowcount
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if vacuum and deleted > 0:
        conn.execute("VACUUM")
    return deleted
