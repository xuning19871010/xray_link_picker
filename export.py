#!/usr/bin/env python3
"""导出兼容文件、CSV/HTML 统计报表，以及只读命令行查询工具。"""
from __future__ import annotations

import argparse
import csv
import html
import io
import ipaddress
import json
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path

from storage import (
    DEFAULT_IP_SOURCE,
    normalize_ip_source,
    open_db,
    shanghai_day,
    utc_day,
)


def ip_sort_key(ip: str) -> tuple[int, bytes]:
    try:
        return (0, ipaddress.ip_address(ip).packed)
    except ValueError:
        return (1, ip.encode("utf-8"))


# 正式 Release 附件。空文件不上传。good_links_by_ip.tsv 至少有表头，因此总会上传。
RELEASE_ASSETS = (
    "good_links.txt",
    "good_links_by_ip.tsv",
    "stable_links.txt",
    "stable_links_by_ip.txt",
    "ip_day_counts.csv",
    "ip_summary.csv",
    "collection_days.csv",
    "ip_report.html",
    "state.sqlite",
    "state.sqlite.sha256",
    "epoch.txt",
)


def _measured_exit_ip(raw: str | None) -> tuple[int, int, str]:
    """库内实测出口。返回 (家族, 地址整数, 写出的文本)。

    家族顺序：IPv4=0，IPv6=1，缺失或无法解析成单个地址=2。
    只接受 links.exit_ip 里的一个 IP，不读链接 host。缺失、空白、多值或解析失败时文本为空。
    """
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text) or "," in text:
        return 2, 0, ""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return 2, 0, ""
    family = 0 if addr.version == 4 else 1
    return family, int(addr), addr.compressed


def good_links_by_ip_rows(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """全部 status=good，不按 IP 去重。同地址按解码后的 link 排序。"""
    ranked: list[tuple[int, int, str, str, str]] = []
    for exit_ip, link in conn.execute("SELECT exit_ip, link FROM links WHERE status='good'"):
        family, number, ip_text = _measured_exit_ip(exit_ip)
        raw = link or ""
        shown = html.unescape(raw)
        ranked.append((family, number, shown, raw, ip_text))
    ranked.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
    return [(ip_text, shown) for _family, _number, shown, _raw, ip_text in ranked]


def render_good_links_by_ip(conn: sqlite3.Connection) -> str:
    """TSV：表头 exit_ip、link。link 做一次 HTML 实体解码，不再编码。"""
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(("exit_ip", "link"))
    writer.writerows(good_links_by_ip_rows(conn))
    return buf.getvalue()


def validate_good_links_tsv(conn: sqlite3.Connection, path: Path) -> None:
    actual = path.read_text(encoding="utf-8")
    expected = render_good_links_by_ip(conn)
    if actual != expected:
        raise ValueError("good_links_by_ip.tsv 与当前 good 链接不一致")


def partition_release_assets(data_dir: Path) -> tuple[list[Path], list[Path]]:
    """返回 (上传, 跳过)。跳过的是缺失或空文件。"""
    upload: list[Path] = []
    skip: list[Path] = []
    for name in RELEASE_ASSETS:
        path = data_dir / name
        if path.is_file() and path.stat().st_size > 0:
            upload.append(path)
        else:
            skip.append(path)
    return upload, skip


def missing_release_assets(data_dir: Path, uploaded_names: list[str]) -> list[str]:
    """本地应上传、但 Release 上还没有的文件名。"""
    upload, _skip = partition_release_assets(data_dir)
    have = set(uploaded_names)
    return [path.name for path in upload if path.name not in have]


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
    )


def stable_threshold(
    conn: sqlite3.Connection, stable_days: int = 30, now_ts: float | None = None
) -> int:
    """保持旧版兼容：第 N 天门槛=N，直到 STABLE_DAYS（基于 links.last_ok_day 的 UTC 日期）。"""
    row = conn.execute(
        "SELECT MIN(last_ok_day) FROM links WHERE last_ok_day IS NOT NULL"
    ).fetchone()
    if not row or not row[0]:
        return 1
    try:
        first = date.fromisoformat(row[0])
    except ValueError:
        return 1
    days = (utc_day(now_ts) - first).days + 1
    return max(1, min(stable_days, days))


def select_representative_goods(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """导出策略：对当前 status='good' 的链接按出口 IP 去重（每 IP 选 ok_days 高、updated_at 新的 1 条代表）。"""
    rows = conn.execute(
        """
        SELECT link, exit_ip, updated_at, h
        FROM links
        WHERE status='good' AND exit_ip IS NOT NULL AND exit_ip != ''
        ORDER BY ok_days DESC, updated_at DESC, h ASC
        """
    ).fetchall()
    seen_ip: set[str] = set()
    picked: list[tuple[float, str, str, str]] = []
    for link, ip, updated_at, h in rows:
        if ip not in seen_ip:
            seen_ip.add(ip)
            picked.append((updated_at, h, link, ip))
    picked.sort(key=lambda t: (t[0], t[1]))
    return [(link, ip) for _u, _h, link, ip in picked]


def select_representative_stables(
    conn: sqlite3.Connection, need_days: int
) -> list[tuple[str, str]]:
    """导出策略：ok_days >= need_days 且有出口 IP，同 IP 留 ok_days 高、updated_at 新、h 字典序小。"""
    rows = conn.execute(
        """
        SELECT link, exit_ip
        FROM links
        WHERE ok_days >= ? AND exit_ip IS NOT NULL AND exit_ip != ''
        ORDER BY ok_days DESC, updated_at DESC, h ASC
        """,
        (need_days,),
    ).fetchall()
    seen_ip: set[str] = set()
    out: list[tuple[str, str]] = []
    for link, ip in rows:
        if ip not in seen_ip:
            seen_ip.add(ip)
            out.append((ip, link))
    return out


def compute_ip_consecutive_stats(
    days_sorted: list[str], anchor_day: str
) -> tuple[int, int]:
    """返回 (max_consecutive_days, current_consecutive_days_ending_at_anchor)。"""
    if not days_sorted:
        return 0, 0
    dates = [date.fromisoformat(d) for d in days_sorted]
    max_streak = cur = 1
    for i in range(1, len(dates)):
        diff = (dates[i] - dates[i - 1]).days
        if diff == 1:
            cur += 1
            if cur > max_streak:
                max_streak = cur
        elif diff > 1:
            cur = 1

    day_set = set(days_sorted)
    cur_streak = 0
    d = date.fromisoformat(anchor_day)
    while d.isoformat() in day_set:
        cur_streak += 1
        d -= timedelta(days=1)
    return max_streak, cur_streak


def _write_csv(path: Path, header: list[str], rows: list[tuple]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def export_all(
    conn: sqlite3.Connection,
    data_dir: Path,
    *,
    stable_days: int = 30,
    now_ts: float | None = None,
) -> dict[str, int]:
    """导出兼容 txt 文件与按 (exit_ip, ip_source, ip_version) 区分的 CSV/HTML 统计报表。"""
    data_dir.mkdir(parents=True, exist_ok=True)
    today_sh = shanghai_day(now_ts)
    yesterday_sh = (date.fromisoformat(today_sh) - timedelta(days=1)).isoformat()

    goods = [link for link, _ip in select_representative_goods(conn)]
    fails = [
        r[0]
        for r in conn.execute(
            "SELECT link FROM links WHERE status='failed' ORDER BY updated_at ASC, h ASC"
        )
    ]
    need = stable_threshold(conn, stable_days=stable_days, now_ts=now_ts)
    stable_pairs = select_representative_stables(conn, need)
    stables = [link for _ip, link in stable_pairs]
    stable_by_ip = sorted(stable_pairs, key=lambda t: (ip_sort_key(t[0]), t[1]))
    good_by_ip = render_good_links_by_ip(conn)

    (data_dir / "good_links.txt").write_text(
        "\n".join(goods) + ("\n" if goods else ""), encoding="utf-8"
    )
    (data_dir / "good_links_by_ip.tsv").write_text(good_by_ip, encoding="utf-8")
    (data_dir / "failed_links.txt").write_text(
        "\n".join(fails) + ("\n" if fails else ""), encoding="utf-8"
    )
    (data_dir / "stable_links.txt").write_text(
        "\n".join(stables) + ("\n" if stables else ""), encoding="utf-8"
    )
    (data_dir / "stable_links_by_ip.txt").write_text(
        "\n".join(f"{ip} {link}" for ip, link in stable_by_ip)
        + ("\n" if stable_by_ip else ""),
        encoding="utf-8",
    )

    col_days_rows: list[tuple] = []
    ip_day_rows: list[tuple] = []
    ip_summary_rows: list[tuple] = []

    if _has_table(conn, "collection_days") and _has_table(conn, "daily_ip_links"):
        for r in conn.execute(
            """
            SELECT
                cd.day, cd.run_count, cd.completed_runs, cd.interrupted_runs,
                cd.tested_observations, cd.probe_ok_observations,
                cd.success_observations, cd.fail_observations,
                (SELECT COUNT(DISTINCT dil.exit_ip) FROM daily_ip_links dil WHERE dil.day = cd.day),
                (SELECT COUNT(DISTINCT dil.h) FROM daily_ip_links dil WHERE dil.day = cd.day)
            FROM collection_days cd ORDER BY cd.day ASC
            """
        ):
            col_days_rows.append((*r, 0 if r[0] >= today_sh else 1))

        raw_idc = conn.execute(
            """
            SELECT
                dil.day, dil.exit_ip, dil.ip_source, dil.ip_version,
                COUNT(DISTINCT dil.h) AS distinct_link_count,
                SUM(dil.success_count) AS success_observations,
                (
                    SELECT COUNT(DISTINCT dir.run_key) FROM daily_ip_runs dir
                    WHERE dir.day = dil.day AND dir.exit_ip = dil.exit_ip
                      AND dir.ip_source = dil.ip_source AND dir.ip_version = dil.ip_version
                ) AS observed_runs
            FROM daily_ip_links dil
            GROUP BY dil.day, dil.exit_ip, dil.ip_source, dil.ip_version
            """
        ).fetchall()
        raw_idc.sort(key=lambda r: (r[0], r[2], r[3], ip_sort_key(r[1])))
        for r in raw_idc:
            ip_day_rows.append((*r, 0 if r[0] >= today_sh else 1))

        cur_good_by_series = {
            (r[0], r[1] or "legacy_mixed", r[2] or "ipv4"): r[3]
            for r in conn.execute(
                """
                SELECT exit_ip, ip_source, ip_version, COUNT(*)
                FROM links WHERE status='good' AND exit_ip IS NOT NULL AND exit_ip != ''
                GROUP BY exit_ip, ip_source, ip_version
                """
            )
        }

        s_days: dict[tuple[str, str, str], list[str]] = {}
        s_comp_days: dict[tuple[str, str, str], list[str]] = {}
        s_today_links: dict[tuple[str, str, str], int] = {}
        for day_s, ip_s, src_s, ver_s, d_links, *_ in ip_day_rows:
            k = (ip_s, src_s, ver_s)
            s_days.setdefault(k, []).append(day_s)
            if day_s < today_sh:
                s_comp_days.setdefault(k, []).append(day_s)
            elif day_s == today_sh:
                s_today_links[k] = d_links

        comp_col_days = [r[0] for r in col_days_rows if r[0] < today_sh]
        anchor_day = comp_col_days[-1] if comp_col_days else yesterday_sh

        for ip_s, src_s, ver_s, first_d, last_d, obs_days, total_links, total_obs in conn.execute(
            """
            SELECT exit_ip, ip_source, ip_version, MIN(day), MAX(day),
                   COUNT(DISTINCT day), COUNT(DISTINCT h), SUM(success_count)
            FROM daily_ip_links GROUP BY exit_ip, ip_source, ip_version
            """
        ):
            k = (ip_s, src_s, ver_s)
            all_d = sorted(set(s_days.get(k, [])))
            comp_d = sorted(set(s_comp_days.get(k, [])))
            max_all, _ = compute_ip_consecutive_stats(all_d, last_d)
            max_comp, cur_comp = compute_ip_consecutive_stats(comp_d, anchor_day)
            ip_summary_rows.append(
                (
                    ip_s, src_s, ver_s, first_d, last_d, obs_days, len(comp_d),
                    max_all, max_comp, cur_comp, total_links,
                    s_today_links.get(k, 0), cur_good_by_series.get(k, 0), total_obs,
                )
            )
        ip_summary_rows.sort(
            key=lambda r: (-r[5], -r[7], -r[10], r[1], r[2], ip_sort_key(r[0]))
        )

    _write_csv(
        data_dir / "collection_days.csv",
        [
            "day", "run_count", "completed_runs", "interrupted_runs",
            "tested_observations", "probe_ok_observations",
            "success_observations", "fail_observations",
            "distinct_exit_ips", "distinct_success_links", "is_complete_day",
        ],
        col_days_rows,
    )
    _write_csv(
        data_dir / "ip_day_counts.csv",
        [
            "day", "exit_ip", "ip_source", "ip_version",
            "distinct_link_count", "success_observations",
            "observed_runs", "is_complete_day",
        ],
        ip_day_rows,
    )
    _write_csv(
        data_dir / "ip_summary.csv",
        [
            "exit_ip", "ip_source", "ip_version", "first_day", "last_day",
            "observed_days", "completed_observed_days", "max_consecutive_days",
            "max_completed_consecutive_days", "current_completed_streak",
            "distinct_links_total", "today_distinct_links",
            "current_good_links", "total_success_observations",
        ],
        ip_summary_rows,
    )
    _write_html_report(
        data_dir / "ip_report.html", today_sh, col_days_rows, ip_day_rows, ip_summary_rows
    )

    total_good = conn.execute("SELECT COUNT(*) FROM links WHERE status='good'").fetchone()[0]
    return {
        "good_representative": len(goods),
        "good_total": total_good,
        "good_by_ip": good_by_ip.count("\n") - 1,
        "failed": len(fails),
        "stable": len(stables),
        "stable_by_ip": len(stable_by_ip),
        "need_days": need,
        "ip_summary_count": len(ip_summary_rows),
    }


def _write_html_report(
    out_path: Path,
    today_sh: str,
    col_days_rows: list[tuple],
    ip_day_rows: list[tuple],
    ip_summary_rows: list[tuple],
    max_rows: int = 300,
    max_days: int = 14,
) -> None:
    """生成轻量单文件 HTML 报表（支持搜索与排序，无外部依赖）。"""
    days = sorted({r[0] for r in col_days_rows} | {r[0] for r in ip_day_rows})[-max_days:]
    counts = {(r[0], r[1], r[2], r[3]): r[4] for r in ip_day_rows}
    data = json.dumps(
        {
            "today": today_sh,
            "days": days,
            "rows": [
                [
                    r[0], r[1], r[2], r[3], r[4], r[5], r[7], r[9], r[10], r[11],
                    [counts.get((d, r[0], r[1], r[2]), 0) for d in days],
                ]
                for r in ip_summary_rows[:max_rows]
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    out_path.write_text(
        f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>出口 IP 每日观测报表</title>
<style>
body{{font:13px sans-serif;margin:16px;color:#222}}
input,select{{padding:4px 6px;margin-right:8px}}
table{{border-collapse:collapse;width:100%;margin-top:10px;font-size:12px}}
th,td{{border:1px solid #ddd;padding:4px 6px;text-align:right;white-space:nowrap}}
th{{background:#f4f6f8}} .l{{text-align:left;font-family:monospace}}
.ok{{background:#e6f4ea;color:#137333;font-weight:600}}
</style></head><body>
<h3>出口 IP 每日 DISTINCT xray_link 统计（Asia/Shanghai，今日 {html.escape(today_sh)} 进行中）</h3>
<div>
  搜索 IP/观测源: <input id="q" placeholder="过滤 IP 或 source">
  最少观测天数: <input id="m" type="number" value="1" min="1" style="width:50px">
  排序: <select id="s"><option value="5">观测天数↓</option><option value="6">最大连续↓</option><option value="7">当前连续↓</option><option value="8">累计Links↓</option></select>
  <span>（展示前 {min(len(ip_summary_rows), max_rows)} / 共 {len(ip_summary_rows)} 条序列，完整数据见 CSV）</span>
</div>
<table><thead id="th"></thead><tbody id="tb"></tbody></table>
<script>
const D={data};
const hdr=['出口IP','观测源','协议','首见日','末见日','观测天','最大连续','当前连续','累计Links','今日Links',...D.days.map(d=>d.slice(5)+(d===D.today?'*':''))];
document.getElementById('th').innerHTML='<tr>'+hdr.map((h,i)=>`<th class="${{i<2?'l':''}}">${{h}}</th>`).join('')+'</tr>';
function draw(){{
  const q=document.getElementById('q').value.toLowerCase(), m=+document.getElementById('m').value||1, s=+document.getElementById('s').value;
  const rows=D.rows.filter(r=>(!q||r[0].toLowerCase().includes(q)||r[1].toLowerCase().includes(q))&&r[5]>=m).sort((a,b)=>b[s]-a[s]||b[8]-a[8]);
  document.getElementById('tb').innerHTML=rows.map(r=>'<tr>'+r.slice(0,10).map((v,i)=>`<td class="${{i<2?'l':''}}">${{v}}</td>`).join('')+r[10].map(c=>`<td class="${{c?'ok':''}}">${{c}}</td>`).join('')+'</tr>').join('');
}}
['q','m','s'].forEach(id=>document.getElementById(id).oninput=draw); draw();
</script></body></html>
""",
        encoding="utf-8",
    )


def query_day_links_and_ips(
    conn: sqlite3.Connection,
    target_day: str | None = None,
    *,
    ip_source: str | None = None,
    ip_version: str | None = None,
    now_ts: float | None = None,
) -> dict:
    """需求 1：查询指定上海日期有多少 DISTINCT xray_link 成功工作及对应出口 IP（区分当日至少一次成功 vs 当日最新仍成功）。"""
    today_sh = shanghai_day(now_ts)
    day = target_day or today_sh
    is_incomplete = day >= today_sh
    src_filter = normalize_ip_source(ip_source) if ip_source else None
    ver_filter = ip_version.lower() if ip_version else None

    if not _has_table(conn, "daily_ip_links"):
        return {
            "day": day,
            "ip_source_filter": src_filter,
            "ip_version_filter": ver_filter,
            "is_incomplete_day": is_incomplete,
            "has_collection": False,
            "warning": "当前数据库尚未采集任何按日观测记录。",
            "ever_good_link_count": 0,
            "latest_good_on_day_link_count": 0,
            "global_current_good_link_count": 0,
            "distinct_exit_ip_count": 0,
            "by_ip": [],
            "links": [],
        }

    col_row = conn.execute(
        "SELECT run_count, completed_runs, interrupted_runs, tested_observations, "
        "probe_ok_observations, success_observations, fail_observations "
        "FROM collection_days WHERE day=?",
        (day,),
    ).fetchone()

    where, params = ["dil.day = ?"], [day]
    if src_filter:
        where.append("dil.ip_source = ?")
        params.append(src_filter)
    if ver_filter:
        where.append("dil.ip_version = ?")
        params.append(ver_filter)

    mapping_rows = conn.execute(
        f"""
        SELECT dil.h, l.link, dil.exit_ip, dil.ip_source, dil.ip_version, dil.success_count
        FROM daily_ip_links dil JOIN links l ON l.h = dil.h
        WHERE {' AND '.join(where)}
        ORDER BY dil.h ASC, dil.ip_source ASC, dil.ip_version ASC, dil.exit_ip ASC
        """,
        params,
    ).fetchall()

    dls_map = {
        r[0]: r[1:]
        for r in conn.execute(
            "SELECT h, last_status, last_exit_ip, last_ip_source, last_ip_version, success_count, fail_count "
            "FROM daily_link_status WHERE day=?",
            (day,),
        )
    }
    global_map = {
        r[0]: r[1:]
        for r in conn.execute("SELECT h, status, exit_ip, ip_source FROM links")
    }

    links_by_h: dict[str, dict] = {}
    ips_by_key: dict[tuple[str, str, str], dict] = {}

    for h, link_str, ip, src_s, ver_s, s_cnt in mapping_rows:
        day_st, day_ip, day_src, day_ver, day_s, day_f = dls_map.get(
            h, ("good", ip, src_s, ver_s, s_cnt, 0)
        )
        g_st, g_ip, g_src = global_map.get(h, ("unknown", None, None))

        entry = links_by_h.setdefault(
            h,
            {
                "h": h,
                "link": link_str,
                "exit_ips": [],
                "day_success_count": day_s,
                "day_fail_count": day_f,
                "day_latest_status": day_st,
                "day_latest_exit_ip": day_ip,
                "day_latest_ip_source": day_src,
                "day_latest_ip_version": day_ver,
                "current_global_status": g_st,
                "current_global_exit_ip": g_ip,
            },
        )
        if ip not in entry["exit_ips"]:
            entry["exit_ips"].append(ip)

        ie = ips_by_key.setdefault(
            (ip, src_s, ver_s),
            {
                "exit_ip": ip,
                "ip_source": src_s,
                "ip_version": ver_s,
                "ever_hashes": set(),
                "links": set(),
                "latest_hashes": set(),
                "global_hashes": set(),
                "success_observations": 0,
            },
        )
        ie["ever_hashes"].add(h)
        ie["links"].add(link_str)
        ie["success_observations"] += s_cnt
        if day_st == "good" and day_ip == ip and (day_src is None or day_src == src_s):
            ie["latest_hashes"].add(h)
        if g_st == "good" and g_ip == ip and (g_src is None or g_src == src_s):
            ie["global_hashes"].add(h)

    by_ip_list = [
        {
            "exit_ip": ie["exit_ip"],
            "ip_source": ie["ip_source"],
            "ip_version": ie["ip_version"],
            "distinct_link_count": len(ie["ever_hashes"]),
            "day_latest_good_link_count": len(ie["latest_hashes"]),
            "current_global_good_link_count": len(ie["global_hashes"]),
            "success_observations": ie["success_observations"],
            "links": sorted(ie["links"]),
        }
        for _k, ie in sorted(
            ips_by_key.items(), key=lambda kv: (kv[0][1], kv[0][2], ip_sort_key(kv[0][0]))
        )
    ]

    ever_good_count = len(links_by_h)
    latest_good_count = sum(
        1
        for v in links_by_h.values()
        if v["day_latest_status"] == "good"
        and (not src_filter or v["day_latest_ip_source"] == src_filter)
        and (not ver_filter or v["day_latest_ip_version"] == ver_filter)
    )
    global_good_count = conn.execute(
        "SELECT COUNT(*) FROM links WHERE status='good'"
    ).fetchone()[0]

    warning = None
    if not col_row and ever_good_count == 0:
        warning = f"日期 {day} 无任何采集记录（未知/未采集，不代表 0 条可用）。"
    elif is_incomplete:
        warning = f"日期 {day} 为当日（Asia/Shanghai），采集仍在进行中（incomplete）。"

    return {
        "day": day,
        "ip_source_filter": src_filter,
        "ip_version_filter": ver_filter,
        "is_incomplete_day": is_incomplete,
        "has_collection": bool(col_row or ever_good_count > 0),
        "collection": {
            "run_count": col_row[0] if col_row else 0,
            "completed_runs": col_row[1] if col_row else 0,
            "interrupted_runs": col_row[2] if col_row else 0,
            "tested_observations": col_row[3] if col_row else 0,
            "probe_ok_observations": col_row[4] if col_row else 0,
            "success_observations": col_row[5] if col_row else 0,
            "fail_observations": col_row[6] if col_row else 0,
        },
        "warning": warning,
        "ever_good_link_count": ever_good_count,
        "latest_good_on_day_link_count": latest_good_count,
        "global_current_good_link_count": global_good_count,
        "distinct_exit_ip_count": len({item["exit_ip"] for item in by_ip_list}),
        "by_ip": by_ip_list,
        "links": list(links_by_h.values()),
    }


def query_continuous_ips(
    conn: sqlite3.Connection,
    days: int,
    *,
    end_day: str | None = None,
    include_today: bool = False,
    ip_source: str | None = None,
    ip_version: str | None = None,
    now_ts: float | None = None,
) -> dict:
    """需求 2：查询连续 X 个日历天内每天至少有 1 次对同一 (ip_source, ip_version) 成功观测的出口 IP。"""
    if days <= 0:
        raise ValueError("连续天数 days 必须 >= 1")

    today_sh = shanghai_day(now_ts)
    today_d = date.fromisoformat(today_sh)
    end_d = (
        date.fromisoformat(end_day)
        if end_day
        else (today_d if include_today else today_d - timedelta(days=1))
    )
    start_d = end_d - timedelta(days=days - 1)
    window_days = [(start_d + timedelta(days=i)).isoformat() for i in range(days)]
    includes_incomplete_today = any(d >= today_sh for d in window_days)
    src_filter = normalize_ip_source(ip_source) if ip_source else None
    ver_filter = ip_version.lower() if ip_version else None

    if not _has_table(conn, "daily_ip_links"):
        return {
            "requested_days": days,
            "start_day": window_days[0],
            "end_day": window_days[-1],
            "window_days": window_days,
            "ip_source_filter": src_filter,
            "ip_version_filter": ver_filter,
            "includes_incomplete_today": includes_incomplete_today,
            "observed_collection_days_in_window": [],
            "missing_collection_days_in_window": window_days,
            "history_sufficient": False,
            "warnings": ["当前数据库尚未建立 daily_ip_links 历史表，无法查询连续多日统计。"],
            "continuous_ip_count": 0,
            "ips": [],
        }

    all_collected = {
        r[0]
        for r in conn.execute(
            "SELECT day FROM collection_days WHERE tested_observations > 0 "
            "UNION SELECT DISTINCT day FROM daily_ip_links"
        )
    }
    observed_in_win = [d for d in window_days if d in all_collected]
    missing_in_win = [d for d in window_days if d not in all_collected]

    warnings: list[str] = []
    if len(all_collected) < days:
        warnings.append(
            f"历史采集天数不足：请求连续 {days} 天，但数据库目前仅有 {len(all_collected)} 个采集日"
            f"（历史自迁移/采集之日起算，不可从旧版计数器回填）。"
        )
    if missing_in_win:
        warnings.append(
            f"窗口 {window_days[0]} ~ {window_days[-1]} 内存在未采集日期: {', '.join(missing_in_win)} "
            f"（未采集=未知，并非 0）。"
        )
    if includes_incomplete_today:
        warnings.append(f"窗口包含今日 ({today_sh})，今日尚未结束（incomplete）。")

    where = [f"dil.day IN ({','.join('?' for _ in window_days)})"]
    params: list = list(window_days)
    if src_filter:
        where.append("dil.ip_source = ?")
        params.append(src_filter)
    if ver_filter:
        where.append("dil.ip_version = ?")
        params.append(ver_filter)

    by_series: dict[tuple[str, str, str], dict[str, dict[str, str]]] = {}
    obs_cnt: dict[tuple[str, str, str, str], int] = {}
    for ip_s, src_s, ver_s, day_s, h, link_str, s_cnt in conn.execute(
        f"""
        SELECT dil.exit_ip, dil.ip_source, dil.ip_version, dil.day, dil.h, l.link, dil.success_count
        FROM daily_ip_links dil JOIN links l ON l.h = dil.h
        WHERE {' AND '.join(where)}
        ORDER BY dil.ip_source ASC, dil.ip_version ASC, dil.exit_ip ASC, dil.day ASC, dil.h ASC
        """,
        params,
    ):
        by_series.setdefault((ip_s, src_s, ver_s), {}).setdefault(day_s, {})[h] = link_str
        obs_cnt[(ip_s, src_s, ver_s, day_s)] = obs_cnt.get((ip_s, src_s, ver_s, day_s), 0) + s_cnt

    continuous_ips = []
    for s_key in sorted(by_series.keys(), key=lambda k: (k[1], k[2], ip_sort_key(k[0]))):
        ip_s, src_s, ver_s = s_key
        day_map = by_series[s_key]
        if not all(d in day_map for d in window_days):
            continue
        all_hashes: dict[str, str] = {}
        daily = []
        for d in window_days:
            h_map = day_map[d]
            all_hashes.update(h_map)
            daily.append(
                {
                    "day": d,
                    "is_incomplete_day": d >= today_sh,
                    "distinct_link_count": len(h_map),
                    "success_observations": obs_cnt.get((ip_s, src_s, ver_s, d), 0),
                    "links": sorted(set(h_map.values())),
                }
            )
        continuous_ips.append(
            {
                "exit_ip": ip_s,
                "ip_source": src_s,
                "ip_version": ver_s,
                "consecutive_days": days,
                "distinct_links_total_in_window": len(all_hashes),
                "all_links_in_window": sorted(set(all_hashes.values())),
                "daily": daily,
            }
        )

    return {
        "requested_days": days,
        "start_day": window_days[0],
        "end_day": window_days[-1],
        "window_days": window_days,
        "ip_source_filter": src_filter,
        "ip_version_filter": ver_filter,
        "includes_incomplete_today": includes_incomplete_today,
        "observed_collection_days_in_window": observed_in_win,
        "missing_collection_days_in_window": missing_in_win,
        "history_sufficient": len(missing_in_win) == 0,
        "warnings": warnings,
        "continuous_ip_count": len(continuous_ips),
        "ips": continuous_ips,
    }


def _print_today(res: dict, show_links: bool) -> None:
    print(f"=== 日期: {res['day']} (Asia/Shanghai) ===")
    if res["warning"]:
        print(f"[提示] {res['warning']}")
    c = res.get("collection") or {}
    print(
        f"轮次: 总 {c.get('run_count', 0)} (完成 {c.get('completed_runs', 0)}, 中断 {c.get('interrupted_runs', 0)}) | "
        f"探测: {c.get('tested_observations', 0)} (连通 {c.get('probe_ok_observations', 0)}, "
        f"成功拿IP {c.get('success_observations', 0)}, 失败 {c.get('fail_observations', 0)})"
    )
    print(f"1) 当日至少成功 1 次的 DISTINCT xray_link 数: {res['ever_good_link_count']}")
    print(f"2) 当日测过且最新一次仍成功的 DISTINCT xray_link 数: {res['latest_good_on_day_link_count']}")
    print(f"3) 当日成功链接涉及的 DISTINCT 出口 IP 数: {res['distinct_exit_ip_count']}")
    print(f"4) 全局当前 status='good' 链接总数: {res['global_current_good_link_count']}")
    if res["by_ip"]:
        print("\nexit_ip\tip_source\tip_version\t当日成功distinct_links\t当日最新仍成功links\t成功探测次数")
        for item in res["by_ip"]:
            print(
                f"{item['exit_ip']}\t{item['ip_source']}\t{item['ip_version']}\t"
                f"{item['distinct_link_count']}\t{item['day_latest_good_link_count']}\t{item['success_observations']}"
            )
            if show_links:
                for lk in item.get("links", []):
                    print(f"    {lk}")


def _print_continuous(res: dict, show_links: bool) -> None:
    print(f"=== 连续 {res['requested_days']} 天存在出口 IP ({res['start_day']} ~ {res['end_day']}, Asia/Shanghai) ===")
    for w in res["warnings"]:
        print(f"[告警] {w}")
    print(f"每天均至少 1 次成功观测的出口 IP 序列数: {res['continuous_ip_count']}")
    if res["ips"]:
        hdr = "\t".join(res["window_days"])
        print(f"\nexit_ip\tip_source\tip_version\t窗口总distinct_links\t{hdr}")
        for item in res["ips"]:
            counts = "\t".join(str(d["distinct_link_count"]) for d in item["daily"])
            print(
                f"{item['exit_ip']}\t{item['ip_source']}\t{item['ip_version']}\t"
                f"{item['distinct_links_total_in_window']}\t{counts}"
            )
            if show_links:
                for d in item["daily"]:
                    print(f"  [{d['day']}] ({d['distinct_link_count']}):")
                    for lk in d.get("links", []):
                        print(f"    {lk}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Xray 出口 IP 与每日成功链接统计/导出工具（查询默认只读）。")
    parser.add_argument("--db", default="data/state.sqlite", help="SQLite 数据库路径")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("today", help="查询指定日期成功工作的 DISTINCT xray_link 及对应出口 IP")
    p1.add_argument("--day", default=None, help="YYYY-MM-DD（Asia/Shanghai，默认今天）")
    p1.add_argument("--ip-source", default=None, help=f"按观测源 URI 过滤（如 {DEFAULT_IP_SOURCE}）")
    p1.add_argument("--ip-version", choices=["ipv4", "ipv6"], default=None)
    p1.add_argument("--show-links", action="store_true", help="输出敏感 xray_link 明文")
    p1.add_argument("--json", action="store_true")

    p2 = sub.add_parser("continuous", help="查询连续 X 天存在的出口 IP 及每日 DISTINCT link 数")
    p2.add_argument("--days", "-x", type=int, required=True, help="连续天数 X")
    p2.add_argument("--end-day", default=None, help="结束日期 YYYY-MM-DD（默认昨天）")
    p2.add_argument("--include-today", action="store_true", help="默认结束日包含今天")
    p2.add_argument("--ip-source", default=None, help=f"按观测源 URI 过滤（如 {DEFAULT_IP_SOURCE}）")
    p2.add_argument("--ip-version", choices=["ipv4", "ipv6"], default=None)
    p2.add_argument("--show-links", action="store_true", help="输出敏感 xray_link 明文")
    p2.add_argument("--json", action="store_true")

    p3 = sub.add_parser("export", help="导出 txt 与 CSV/HTML 统计报表")
    p3.add_argument("--out-dir", default="data")
    p3.add_argument("--stable-days", type=int, default=30)

    args = parser.parse_args(argv)
    conn = open_db(Path(args.db), readonly=True)
    try:
        if args.cmd == "today":
            res = query_day_links_and_ips(
                conn, args.day, ip_source=args.ip_source, ip_version=args.ip_version
            )
            if not args.show_links:
                for item in res["by_ip"]:
                    item.pop("links", None)
                res.pop("links", None)
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                _print_today(res, args.show_links)
        elif args.cmd == "continuous":
            res = query_continuous_ips(
                conn,
                args.days,
                end_day=args.end_day,
                include_today=args.include_today,
                ip_source=args.ip_source,
                ip_version=args.ip_version,
            )
            if not args.show_links:
                for item in res["ips"]:
                    item.pop("all_links_in_window", None)
                    for d in item["daily"]:
                        d.pop("links", None)
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                _print_continuous(res, args.show_links)
        elif args.cmd == "export":
            print(json.dumps(export_all(conn, Path(args.out_dir), stable_days=args.stable_days)))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
