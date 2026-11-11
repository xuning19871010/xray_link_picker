#!/usr/bin/env python3
"""导出兼容文件、CSV/HTML 统计报表，以及只读命令行查询工具。"""
from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import json
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path

from storage import (
    DEFAULT_IP_SOURCE,
    extract_ip_source,
    open_db,
    shanghai_day,
    utc_day,
)


def ip_sort_key(ip: str) -> tuple[int, bytes]:
    """IPv4/IPv6 数值排序；解析失败落到字符串兜底。"""
    try:
        return (0, ipaddress.ip_address(ip).packed)
    except ValueError:
        return (1, ip.encode("utf-8"))


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return bool(row)


def _has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    if not _has_table(conn, table):
        return False
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    return col in cols


def stable_threshold(
    conn: sqlite3.Connection,
    stable_days: int = 30,
    now_ts: float | None = None,
) -> int:
    """第 N 天门槛=N，直到 STABLE_DAYS（优先按新权威观测源起算，避免旧 legacy_mixed 历史把新源首日门槛直接拉满）。"""
    has_src = _has_column(conn, "links", "ip_source")
    row = None
    if has_src:
        row = conn.execute(
            "SELECT MIN(last_ok_day) FROM links WHERE last_ok_day IS NOT NULL AND (ip_source IS NULL OR ip_source != 'legacy_mixed')"
        ).fetchone()
    if not row or not row[0]:
        row = conn.execute(
            "SELECT MIN(last_ok_day) FROM links WHERE last_ok_day IS NOT NULL"
        ).fetchone()
    if not row or not row[0]:
        return 1
    try:
        first = date.fromisoformat(row[0])
    except ValueError:
        return 1
    today_d = utc_day(now_ts)
    days = (today_d - first).days + 1
    return max(1, min(stable_days, days))


def select_representative_goods(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """导出策略：对当前 status='good' 的链接按出口 IP 去重（每个出口 IP 选 1 条代表链接）。

    同出口 IP 优先选 ok_days 更高、updated_at 更新、h 字典序更小的链接（确定性排序）；
    最终返回按代表链接 updated_at 升序排列的 [(link, exit_ip), ...]。
    """
    rows = conn.execute(
        """
        SELECT link, exit_ip, ok_days, updated_at, h
        FROM links
        WHERE status='good' AND exit_ip IS NOT NULL AND exit_ip!=''
        ORDER BY ok_days DESC, updated_at DESC, h ASC
        """
    ).fetchall()
    seen_ip: set[str] = set()
    picked: list[tuple[float, str, str, str]] = []
    for link, ip, _ok_days, updated_at, h in rows:
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        picked.append((updated_at, h, link, ip))
    picked.sort(key=lambda t: (t[0], t[1]))
    return [(link, ip) for _u, _h, link, ip in picked]


def select_representative_stables(
    conn: sqlite3.Connection, need_days: int
) -> list[tuple[str, str]]:
    """导出策略：ok_days >= need_days 且有出口 IP，优先选非 legacy_mixed 的当前权威观测源链接。"""
    has_src = _has_column(conn, "links", "ip_source")
    has_canonical = False
    if has_src:
        has_canonical = bool(
            conn.execute(
                "SELECT 1 FROM links WHERE status='good' AND ip_source IS NOT NULL AND ip_source != 'legacy_mixed' LIMIT 1"
            ).fetchone()
        )
    if has_src and has_canonical:
        rows = conn.execute(
            """
            SELECT link, exit_ip
            FROM links
            WHERE ok_days >= ? AND exit_ip IS NOT NULL AND exit_ip != ''
              AND (ip_source IS NULL OR ip_source != 'legacy_mixed')
            ORDER BY ok_days DESC, updated_at DESC, h ASC
            """,
            (need_days,),
        ).fetchall()
    else:
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
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        out.append((ip, link))
    return out


def compute_ip_consecutive_stats(
    days_sorted: list[str], latest_complete_day: str
) -> tuple[int, int]:
    """返回 (max_consecutive_days, current_consecutive_days_through_latest_complete)。"""
    if not days_sorted:
        return 0, 0
    dates = [date.fromisoformat(d) for d in days_sorted]
    max_streak = cur = 1
    for i in range(1, len(dates)):
        if (dates[i] - dates[i - 1]).days == 1:
            cur += 1
            if cur > max_streak:
                max_streak = cur
        elif dates[i] != dates[i - 1]:
            cur = 1

    day_set = set(days_sorted)
    try:
        anchor = date.fromisoformat(latest_complete_day)
    except ValueError:
        return max_streak, 0

    cur_streak = 0
    d = anchor
    while d.isoformat() in day_set:
        cur_streak += 1
        d -= timedelta(days=1)
    return max_streak, cur_streak


def export_all(
    conn: sqlite3.Connection,
    data_dir: Path,
    *,
    stable_days: int = 30,
    now_ts: float | None = None,
) -> dict[str, int]:
    """导出全部 txt 兼容文件与按 (exit_ip, ip_source, ip_version) 区分的 CSV/HTML 统计报表。"""
    data_dir.mkdir(parents=True, exist_ok=True)
    today_sh = shanghai_day(now_ts)
    yesterday_sh = (date.fromisoformat(today_sh) - timedelta(days=1)).isoformat()

    # 1) 兼容 txt 文件
    rep_goods = select_representative_goods(conn)
    goods = [link for link, _ip in rep_goods]
    fails = [
        r[0]
        for r in conn.execute(
            "SELECT link FROM links WHERE status='failed' ORDER BY updated_at ASC, h ASC"
        )
    ]
    need = stable_threshold(conn, stable_days=stable_days, now_ts=now_ts)
    stable_pairs = select_representative_stables(conn, need)
    stables = [link for _ip, link in stable_pairs]
    stable_pairs_sorted = sorted(stable_pairs, key=lambda t: (ip_sort_key(t[0]), t[1]))

    (data_dir / "good_links.txt").write_text(
        "\n".join(goods) + ("\n" if goods else ""), encoding="utf-8"
    )
    (data_dir / "failed_links.txt").write_text(
        "\n".join(fails) + ("\n" if fails else ""), encoding="utf-8"
    )
    (data_dir / "stable_links.txt").write_text(
        "\n".join(stables) + ("\n" if stables else ""), encoding="utf-8"
    )
    (data_dir / "stable_links_by_ip.txt").write_text(
        "\n".join(f"{ip} {link}" for ip, link in stable_pairs_sorted)
        + ("\n" if stable_pairs_sorted else ""),
        encoding="utf-8",
    )

    # 2) collection_days.csv
    col_days_rows = []
    if _has_table(conn, "collection_days"):
        has_probe_ok_col = _has_column(conn, "collection_days", "probe_ok_observations")
        probe_ok_expr = "cd.probe_ok_observations" if has_probe_ok_col else "cd.success_observations"
        raw_cd = conn.execute(
            f"""
            SELECT
                cd.day,
                cd.run_count,
                cd.completed_runs,
                cd.interrupted_runs,
                cd.tested_observations,
                {probe_ok_expr},
                cd.success_observations,
                cd.fail_observations,
                (SELECT COUNT(DISTINCT dil.exit_ip) FROM daily_ip_links dil WHERE dil.day = cd.day),
                (SELECT COUNT(DISTINCT dil.h) FROM daily_ip_links dil WHERE dil.day = cd.day)
            FROM collection_days cd
            ORDER BY cd.day ASC
            """
        ).fetchall()
        for r in raw_cd:
            d_str = r[0]
            is_complete = 0 if d_str >= today_sh else 1
            col_days_rows.append((*r, is_complete))

    with open(data_dir / "collection_days.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "day",
                "run_count",
                "completed_runs",
                "interrupted_runs",
                "tested_observations",
                "probe_ok_observations",
                "success_observations",
                "fail_observations",
                "distinct_exit_ips",
                "distinct_success_links",
                "is_complete_day",
            ]
        )
        w.writerows(col_days_rows)

    # 3) ip_day_counts.csv（按 day, exit_ip, ip_source, ip_version 统计去重前真实 distinct link 数）
    ip_day_rows = []
    if _has_table(conn, "daily_ip_links"):
        raw_idc = conn.execute(
            """
            SELECT
                dil.day,
                dil.exit_ip,
                dil.ip_source,
                dil.ip_version,
                COUNT(DISTINCT dil.h) AS distinct_link_count,
                SUM(dil.success_count) AS success_observations,
                (
                    SELECT COUNT(DISTINCT dir.run_key)
                    FROM daily_ip_runs dir
                    WHERE dir.day = dil.day
                      AND dir.exit_ip = dil.exit_ip
                      AND dir.ip_source = dil.ip_source
                      AND dir.ip_version = dil.ip_version
                ) AS observed_runs
            FROM daily_ip_links dil
            GROUP BY dil.day, dil.exit_ip, dil.ip_source, dil.ip_version
            """
        ).fetchall()
        raw_idc.sort(key=lambda r: (r[0], r[2], r[3], ip_sort_key(r[1])))
        for day_s, ip_s, src_s, ver_s, d_links, s_obs, o_runs in raw_idc:
            is_complete = 0 if day_s >= today_sh else 1
            ip_day_rows.append(
                (day_s, ip_s, src_s, ver_s, d_links, s_obs, o_runs, is_complete)
            )

    with open(data_dir / "ip_day_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "day",
                "exit_ip",
                "ip_source",
                "ip_version",
                "distinct_link_count",
                "success_observations",
                "observed_runs",
                "is_complete_day",
            ]
        )
        w.writerows(ip_day_rows)

    # 4) ip_summary.csv（按 exit_ip + ip_source + ip_version 独立序列汇总，不跨源混算）
    ip_summary_rows = []
    if _has_table(conn, "daily_ip_links"):
        has_link_src = _has_column(conn, "links", "ip_source")
        if has_link_src:
            current_good_by_series: dict[tuple[str, str, str], int] = {
                (r[0], r[1] or "legacy_mixed", r[2] or "ipv4"): r[3]
                for r in conn.execute(
                    """
                    SELECT exit_ip, ip_source, ip_version, COUNT(*)
                    FROM links
                    WHERE status='good' AND exit_ip IS NOT NULL AND exit_ip != ''
                    GROUP BY exit_ip, ip_source, ip_version
                    """
                ).fetchall()
            }
        else:
            current_good_by_series = {}

        series_days_map: dict[tuple[str, str, str], list[str]] = {}
        series_comp_days_map: dict[tuple[str, str, str], list[str]] = {}
        series_today_links: dict[tuple[str, str, str], int] = {}
        for day_s, ip_s, src_s, ver_s, d_links, _s_obs, _o_runs, _comp in ip_day_rows:
            key = (ip_s, src_s, ver_s)
            series_days_map.setdefault(key, []).append(day_s)
            if day_s < today_sh:
                series_comp_days_map.setdefault(key, []).append(day_s)
            if day_s == today_sh:
                series_today_links[key] = d_links

        series_totals = conn.execute(
            """
            SELECT
                exit_ip,
                ip_source,
                ip_version,
                MIN(day) AS first_day,
                MAX(day) AS last_day,
                COUNT(DISTINCT day) AS observed_days,
                COUNT(DISTINCT h) AS distinct_links_total,
                SUM(success_count) AS total_success_observations
            FROM daily_ip_links
            GROUP BY exit_ip, ip_source, ip_version
            """
        ).fetchall()

        completed_col_days = [r[0] for r in col_days_rows if r[0] < today_sh]
        anchor_day = completed_col_days[-1] if completed_col_days else yesterday_sh

        for ip_s, src_s, ver_s, first_d, last_d, obs_days, total_links, total_obs in series_totals:
            key = (ip_s, src_s, ver_s)
            all_d = sorted(set(series_days_map.get(key, [])))
            comp_d = sorted(set(series_comp_days_map.get(key, [])))
            max_consec_all, _ = compute_ip_consecutive_stats(all_d, last_d)
            max_consec_comp, cur_consec_comp = compute_ip_consecutive_stats(
                comp_d, anchor_day
            )
            ip_summary_rows.append(
                (
                    ip_s,
                    src_s,
                    ver_s,
                    first_d,
                    last_d,
                    obs_days,
                    len(comp_d),
                    max_consec_all,
                    max_consec_comp,
                    cur_consec_comp,
                    total_links,
                    series_today_links.get(key, 0),
                    current_good_by_series.get(key, 0),
                    total_obs,
                )
            )

        ip_summary_rows.sort(
            key=lambda r: (-r[5], -r[7], -r[10], r[1], r[2], ip_sort_key(r[0]))
        )

    with open(data_dir / "ip_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "exit_ip",
                "ip_source",
                "ip_version",
                "first_day",
                "last_day",
                "observed_days",
                "completed_observed_days",
                "max_consecutive_days",
                "max_completed_consecutive_days",
                "current_completed_streak",
                "distinct_links_total",
                "today_distinct_links",
                "current_good_links",
                "total_success_observations",
            ]
        )
        w.writerows(ip_summary_rows)

    # 5) 静态单文件 ip_report.html（只含 IP、来源、版本和计数，不含任何敏感链接）
    _write_html_report(
        data_dir / "ip_report.html",
        today_sh=today_sh,
        col_days_rows=col_days_rows,
        ip_day_rows=ip_day_rows,
        ip_summary_rows=ip_summary_rows,
    )

    total_good_all = conn.execute(
        "SELECT COUNT(*) FROM links WHERE status='good'"
    ).fetchone()[0]
    return {
        "good_representative": len(goods),
        "good_total": total_good_all,
        "failed": len(fails),
        "stable": len(stables),
        "stable_by_ip": len(stable_pairs_sorted),
        "need_days": need,
        "ip_summary_count": len(ip_summary_rows),
    }


def _write_html_report(
    out_path: Path,
    *,
    today_sh: str,
    col_days_rows: list[tuple],
    ip_day_rows: list[tuple],
    ip_summary_rows: list[tuple],
    max_ips_in_html: int = 500,
    recent_days_limit: int = 30,
) -> None:
    """生成无外部依赖的紧凑单文件 HTML 报表（支持按 IP/测量源搜索、排序与分页）。"""
    all_days = sorted({r[0] for r in col_days_rows} | {r[0] for r in ip_day_rows})
    recent_days = all_days[-recent_days_limit:]
    day_series_count: dict[tuple[str, str, str, str], int] = {
        (r[0], r[1], r[2], r[3]): r[4] for r in ip_day_rows
    }

    bounded_summary = ip_summary_rows[:max_ips_in_html]
    js_rows = []
    for r in bounded_summary:
        ip_s, src_s, ver_s = r[0], r[1], r[2]
        daily_counts = [
            day_series_count.get((d, ip_s, src_s, ver_s), 0) for d in recent_days
        ]
        js_rows.append(
            {
                "ip": ip_s,
                "src": src_s,
                "ver": ver_s,
                "first": r[3],
                "last": r[4],
                "obs_days": r[5],
                "comp_days": r[6],
                "max_streak": r[7],
                "cur_streak": r[9],
                "total_links": r[10],
                "today_links": r[11],
                "cur_good": r[12],
                "daily": daily_counts,
            }
        )

    payload_json = json.dumps(
        {
            "today": today_sh,
            "total_ips": len(ip_summary_rows),
            "shown_ips": len(bounded_summary),
            "days": recent_days,
            "rows": js_rows,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Xray 出口 IP 每日观测报表</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; color: #222; background: #fafafa; }}
  h1 {{ font-size: 20px; margin-bottom: 6px; }}
  .meta {{ color: #555; font-size: 13px; margin-bottom: 14px; line-height: 1.5; }}
  .controls {{ display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }}
  input, select, button {{ padding: 5px 8px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; font-size: 12px; }}
  th, td {{ border: 1px solid #e0e0e0; padding: 5px 7px; text-align: right; white-space: nowrap; }}
  th {{ background: #f2f4f7; cursor: pointer; user-select: none; }}
  th.left, td.left {{ text-align: left; font-family: monospace; }}
  .c0 {{ color: #bbb; background: #fcfcfc; }}
  .c1 {{ background: #e6f4ea; color: #137333; font-weight: 600; }}
  .c2 {{ background: #ceead6; color: #0d652d; font-weight: 700; }}
  .inc {{ color: #b06000; font-style: italic; }}
</style>
</head>
<body>
<h1>出口 IP 每日 DISTINCT xray_link 观测报表（按观测源与协议栈区分）</h1>
<div class="meta">
  时区：Asia/Shanghai ｜ 今日（进行中/incomplete）：<b>{html.escape(today_sh)}</b> ｜
  总观测序列数 (exit_ip + ip_source + ip_version)：<b>{len(ip_summary_rows)}</b>（表格展示前 {len(bounded_summary)} 个，完整数据见 <code>ip_summary.csv</code> / <code>ip_day_counts.csv</code>）<br>
  口径说明：出口 IP 为<b>对目标测量端点（如 <code>checkip.amazonaws.com</code>）观测到的出口 IP</b>，并非全网绝对唯一出口；不同测量源或协议栈（ipv4/ipv6）严格分列，不混算连续性。单元格数值为当天至少成功测通一次的 <b>DISTINCT xray_link 数量（去重前真实映射）</b>。
</div>
<div class="controls">
  <label>搜索 IP/测量源: <input type="text" id="q" placeholder="如 1.2.3. 或 amazonaws"></label>
  <label>最少观测天数: <input type="number" id="minDays" value="1" min="1" style="width:60px"></label>
  <label>排序:
    <select id="sortBy">
      <option value="obs_days">观测天数 ↓</option>
      <option value="max_streak">最大连续天数 ↓</option>
      <option value="cur_streak">当前已完成连续天数 ↓</option>
      <option value="total_links">累计不同链接数 ↓</option>
      <option value="today_links">今日不同链接数 ↓</option>
    </select>
  </label>
  <button id="prevBtn">上一页</button>
  <span id="pageInfo"></span>
  <button id="nextBtn">下一页</button>
</div>
<div style="overflow-x:auto">
  <table id="tbl">
    <thead id="thead"></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<script>
const DATA = {payload_json};
let page = 1;
const pageSize = 50;

function renderHeader() {{
  const tr = document.createElement('tr');
  const fixed = [
    ['出口 IP', 'left'], ['观测源', 'left'], ['协议', ''],
    ['首见日', ''], ['末见日', ''],
    ['观测天数', ''], ['最大连续', ''], ['当前连续(完结日)', ''],
    ['累计Links', ''], ['今日Links', ''], ['当前Good', '']
  ];
  fixed.forEach(([t, cls]) => {{
    const th = document.createElement('th');
    th.textContent = t;
    if (cls) th.className = cls;
    tr.appendChild(th);
  }});
  DATA.days.forEach(d => {{
    const th = document.createElement('th');
    th.textContent = d.slice(5) + (d === DATA.today ? '*' : '');
    if (d === DATA.today) th.className = 'inc';
    tr.appendChild(th);
  }});
  const thead = document.getElementById('thead');
  thead.innerHTML = '';
  thead.appendChild(tr);
}}

function renderBody() {{
  const q = document.getElementById('q').value.trim().toLowerCase();
  const minD = parseInt(document.getElementById('minDays').value || '1', 10);
  const sortKey = document.getElementById('sortBy').value;

  let filtered = DATA.rows.filter(r => (!q || r.ip.toLowerCase().includes(q) || r.src.toLowerCase().includes(q)) && r.obs_days >= minD);
  filtered.sort((a, b) => (b[sortKey] - a[sortKey]) || (b.total_links - a.total_links));

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  if (page > totalPages) page = totalPages;
  const slice = filtered.slice((page - 1) * pageSize, page * pageSize);

  document.getElementById('pageInfo').textContent = `第 ${{page}} / ${{totalPages}} 页（匹配 ${{filtered.length}} 条序列）`;

  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  slice.forEach(r => {{
    const tr = document.createElement('tr');
    const cells = [
      [r.ip, 'left'], [r.src, 'left'], [r.ver, ''],
      [r.first, ''], [r.last, ''],
      [r.obs_days, ''], [r.max_streak, ''], [r.cur_streak, ''],
      [r.total_links, ''], [r.today_links, ''], [r.cur_good, '']
    ];
    cells.forEach(([val, cls]) => {{
      const td = document.createElement('td');
      td.textContent = val;
      if (cls) td.className = cls;
      tr.appendChild(td);
    }});
    r.daily.forEach(cnt => {{
      const td = document.createElement('td');
      td.textContent = cnt;
      td.className = cnt === 0 ? 'c0' : (cnt === 1 ? 'c1' : 'c2');
      tr.appendChild(td);
    }});
    tbody.appendChild(tr);
  }});
}}

['q', 'minDays', 'sortBy'].forEach(id => {{
  document.getElementById(id).addEventListener('input', () => {{ page = 1; renderBody(); }});
}});
document.getElementById('prevBtn').addEventListener('click', () => {{ if (page > 1) {{ page--; renderBody(); }} }});
document.getElementById('nextBtn').addEventListener('click', () => {{ page++; renderBody(); }});

renderHeader();
renderBody();
</script>
</body>
</html>
"""
    out_path.write_text(html_doc, encoding="utf-8")


# ---------- 只读查询逻辑（需求 1 & 需求 2）----------


def query_day_links_and_ips(
    conn: sqlite3.Connection,
    target_day: str | None = None,
    *,
    ip_source: str | None = None,
    ip_version: str | None = None,
    now_ts: float | None = None,
) -> dict:
    """需求 1：查询某天（默认今天 Asia/Shanghai）有多少 DISTINCT xray_link 成功工作及对应出口 IP。

    严格区分：
      - ever_good_link_count: 当天至少有 1 次成功探测的 DISTINCT 链接数
      - latest_good_on_day_link_count: 当天测过且「当天最新一次探测仍为成功」的 DISTINCT 链接数
      - global_current_good_link_count: 当前全局 status='good' 的链接数
      - 按 (exit_ip, ip_source, ip_version) 区分观测源与地址族
    """
    today_sh = shanghai_day(now_ts)
    day = target_day or today_sh
    is_incomplete = day >= today_sh
    src_filter = extract_ip_source(ip_source) if ip_source else None
    ver_filter = ip_version.lower() if ip_version else None

    if not _has_table(conn, "daily_ip_links"):
        return {
            "day": day,
            "ip_source_filter": src_filter,
            "ip_version_filter": ver_filter,
            "is_incomplete_day": is_incomplete,
            "has_collection": False,
            "warning": "当前数据库为旧版 schema 或尚未采集任何按日观测记录。",
            "ever_good_link_count": 0,
            "latest_good_on_day_link_count": 0,
            "global_current_good_link_count": 0,
            "distinct_exit_ip_count": 0,
            "by_ip": [],
            "links": [],
        }

    has_probe_ok_col = _has_column(conn, "collection_days", "probe_ok_observations")
    probe_ok_expr = "probe_ok_observations" if has_probe_ok_col else "success_observations"
    col_row = conn.execute(
        f"SELECT run_count, completed_runs, interrupted_runs, tested_observations, {probe_ok_expr}, success_observations, fail_observations "
        "FROM collection_days WHERE day=?",
        (day,),
    ).fetchone()

    where_clauses = ["dil.day = ?"]
    params: list = [day]
    if src_filter:
        where_clauses.append("dil.ip_source = ?")
        params.append(src_filter)
    if ver_filter:
        where_clauses.append("dil.ip_version = ?")
        params.append(ver_filter)

    mapping_rows = conn.execute(
        f"""
        SELECT dil.h, l.link, dil.exit_ip, dil.ip_source, dil.ip_version, dil.success_count
        FROM daily_ip_links dil
        JOIN links l ON l.h = dil.h
        WHERE {' AND '.join(where_clauses)}
        ORDER BY dil.h ASC, dil.ip_source ASC, dil.ip_version ASC, dil.exit_ip ASC
        """,
        params,
    ).fetchall()

    dls_map: dict[str, tuple[str, str | None, str | None, str | None, int, int]] = {}
    if _has_table(conn, "daily_link_status"):
        has_dls_src = _has_column(conn, "daily_link_status", "last_ip_source")
        if has_dls_src:
            for h, last_st, last_ip, last_src, last_ver, s_cnt, f_cnt in conn.execute(
                "SELECT h, last_status, last_exit_ip, last_ip_source, last_ip_version, success_count, fail_count "
                "FROM daily_link_status WHERE day=?",
                (day,),
            ):
                dls_map[h] = (last_st, last_ip, last_src, last_ver, s_cnt, f_cnt)
        else:
            for h, last_st, last_ip, s_cnt, f_cnt in conn.execute(
                "SELECT h, last_status, last_exit_ip, success_count, fail_count FROM daily_link_status WHERE day=?",
                (day,),
            ):
                dls_map[h] = (last_st, last_ip, None, None, s_cnt, f_cnt)

    has_link_src = _has_column(conn, "links", "ip_source")
    global_status_map: dict[str, tuple[str, str | None, str | None, str | None]] = {}
    if has_link_src:
        for h, st, ip, src, ver in conn.execute(
            "SELECT h, status, exit_ip, ip_source, ip_version FROM links"
        ):
            global_status_map[h] = (st, ip, src, ver)
    else:
        for h, st, ip in conn.execute("SELECT h, status, exit_ip FROM links"):
            global_status_map[h] = (st, ip, None, None)

    links_by_h: dict[str, dict] = {}
    ips_by_key: dict[tuple[str, str, str], dict] = {}

    for h, link_str, ip, src_s, ver_s, s_cnt in mapping_rows:
        day_last_st, day_last_ip, day_last_src, day_last_ver, day_s_cnt, day_f_cnt = dls_map.get(
            h, ("good", ip, src_s, ver_s, s_cnt, 0)
        )
        g_st, g_ip, g_src, g_ver = global_status_map.get(h, ("unknown", None, None, None))

        entry = links_by_h.get(h)
        if not entry:
            entry = {
                "h": h,
                "link": link_str,
                "exit_ips": [],
                "day_success_count": day_s_cnt,
                "day_fail_count": day_f_cnt,
                "day_latest_status": day_last_st,
                "day_latest_exit_ip": day_last_ip,
                "day_latest_ip_source": day_last_src,
                "day_latest_ip_version": day_last_ver,
                "current_global_status": g_st,
                "current_global_exit_ip": g_ip,
            }
            links_by_h[h] = entry
        if ip not in entry["exit_ips"]:
            entry["exit_ips"].append(ip)

        s_key = (ip, src_s, ver_s)
        ip_entry = ips_by_key.get(s_key)
        if not ip_entry:
            ip_entry = {
                "exit_ip": ip,
                "ip_source": src_s,
                "ip_version": ver_s,
                "ever_good_link_hashes": set(),
                "ever_good_links": [],
                "day_latest_good_link_hashes": set(),
                "current_global_good_link_hashes": set(),
                "success_observations": 0,
            }
            ips_by_key[s_key] = ip_entry
        ip_entry["ever_good_link_hashes"].add(h)
        ip_entry["ever_good_links"].append(link_str)
        ip_entry["success_observations"] += s_cnt
        if (
            day_last_st == "good"
            and day_last_ip == ip
            and (day_last_src is None or day_last_src == src_s)
        ):
            ip_entry["day_latest_good_link_hashes"].add(h)
        if g_st == "good" and g_ip == ip and (g_src is None or g_src == src_s):
            ip_entry["current_global_good_link_hashes"].add(h)

    by_ip_list = []
    for s_key in sorted(
        ips_by_key.keys(), key=lambda k: (k[1], k[2], ip_sort_key(k[0]))
    ):
        ie = ips_by_key[s_key]
        by_ip_list.append(
            {
                "exit_ip": ie["exit_ip"],
                "ip_source": ie["ip_source"],
                "ip_version": ie["ip_version"],
                "distinct_link_count": len(ie["ever_good_link_hashes"]),
                "day_latest_good_link_count": len(ie["day_latest_good_link_hashes"]),
                "current_global_good_link_count": len(
                    ie["current_global_good_link_hashes"]
                ),
                "success_observations": ie["success_observations"],
                "links": sorted(set(ie["ever_good_links"])),
            }
        )

    ever_good_count = len(links_by_h)
    latest_good_on_day_count = sum(
        1
        for v in links_by_h.values()
        if v["day_latest_status"] == "good"
        and (not src_filter or v["day_latest_ip_source"] == src_filter)
        and (not ver_filter or v["day_latest_ip_version"] == ver_filter)
    )
    global_current_good_count = conn.execute(
        "SELECT COUNT(*) FROM links WHERE status='good'"
    ).fetchone()[0]
    distinct_ips = len({item["exit_ip"] for item in by_ip_list})

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
        "latest_good_on_day_link_count": latest_good_on_day_count,
        "global_current_good_link_count": global_current_good_count,
        "distinct_exit_ip_count": distinct_ips,
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
    """需求 2：查询在连续 X 个日历天内「每天都至少有 1 次对同一测量源/协议栈成功观测」的出口 IP，
    并返回每个 IP 每天对应的 DISTINCT xray_link 数量、窗口内累计去重链接数及按需对应的具体链接。
    """
    if days <= 0:
        raise ValueError("连续天数 days 必须 >= 1")

    today_sh = shanghai_day(now_ts)
    today_d = date.fromisoformat(today_sh)

    if end_day:
        end_d = date.fromisoformat(end_day)
    else:
        end_d = today_d if include_today else (today_d - timedelta(days=1))

    start_d = end_d - timedelta(days=days - 1)
    window_days = [
        (start_d + timedelta(days=i)).isoformat() for i in range(days)
    ]
    includes_incomplete_today = any(d >= today_sh for d in window_days)
    src_filter = extract_ip_source(ip_source) if ip_source else None
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

    all_collected_days = {
        r[0]
        for r in conn.execute(
            "SELECT day FROM collection_days WHERE tested_observations > 0 "
            "UNION SELECT DISTINCT day FROM daily_ip_links"
        ).fetchall()
    }
    observed_in_window = [d for d in window_days if d in all_collected_days]
    missing_in_window = [d for d in window_days if d not in all_collected_days]

    warnings: list[str] = []
    if len(all_collected_days) < days:
        warnings.append(
            f"历史采集天数不足：请求连续 {days} 天，但数据库目前仅有 {len(all_collected_days)} 个采集日"
            f"（历史自迁移/采集之日起算，不可从旧版计数器回填）。"
        )
    if missing_in_window:
        warnings.append(
            f"窗口 {window_days[0]} ~ {window_days[-1]} 内存在未采集日期: {', '.join(missing_in_window)} "
            f"（未采集=未知，并非 0，导致无法满足严格连续 {days} 天每天都有成功观测）。"
        )
    if includes_incomplete_today:
        warnings.append(
            f"窗口包含今日 ({today_sh})，今日尚未结束（incomplete）。"
        )

    history_sufficient = len(missing_in_window) == 0

    placeholders = ",".join("?" for _ in window_days)
    where_clauses = [f"dil.day IN ({placeholders})"]
    params: list = list(window_days)
    if src_filter:
        where_clauses.append("dil.ip_source = ?")
        params.append(src_filter)
    if ver_filter:
        where_clauses.append("dil.ip_version = ?")
        params.append(ver_filter)

    rows = conn.execute(
        f"""
        SELECT dil.exit_ip, dil.ip_source, dil.ip_version, dil.day, dil.h, l.link, dil.success_count
        FROM daily_ip_links dil
        JOIN links l ON l.h = dil.h
        WHERE {' AND '.join(where_clauses)}
        ORDER BY dil.ip_source ASC, dil.ip_version ASC, dil.exit_ip ASC, dil.day ASC, dil.h ASC
        """,
        params,
    ).fetchall()

    # 按 (exit_ip, ip_source, ip_version) 分组，防止不同测量源或不同 IP 版本混进同一连续序列
    by_series: dict[tuple[str, str, str], dict[str, dict[str, str]]] = {}
    obs_cnt_by_series_day: dict[tuple[str, str, str, str], int] = {}
    for ip_s, src_s, ver_s, day_s, h, link_str, s_cnt in rows:
        s_key = (ip_s, src_s, ver_s)
        by_series.setdefault(s_key, {}).setdefault(day_s, {})[h] = link_str
        obs_cnt_by_series_day[(ip_s, src_s, ver_s, day_s)] = (
            obs_cnt_by_series_day.get((ip_s, src_s, ver_s, day_s), 0) + s_cnt
        )

    continuous_ips = []
    for s_key in sorted(
        by_series.keys(), key=lambda k: (k[1], k[2], ip_sort_key(k[0]))
    ):
        ip_s, src_s, ver_s = s_key
        day_map = by_series[s_key]
        if len(day_map) < days:
            continue
        if not all(d in day_map for d in window_days):
            continue

        all_hashes_in_window: dict[str, str] = {}
        daily_breakdown = []
        for d in window_days:
            h_to_link = day_map[d]
            all_hashes_in_window.update(h_to_link)
            links_sorted = sorted(set(h_to_link.values()))
            daily_breakdown.append(
                {
                    "day": d,
                    "is_incomplete_day": d >= today_sh,
                    "distinct_link_count": len(h_to_link),
                    "success_observations": obs_cnt_by_series_day.get(
                        (ip_s, src_s, ver_s, d), 0
                    ),
                    "links": links_sorted,
                }
            )

        continuous_ips.append(
            {
                "exit_ip": ip_s,
                "ip_source": src_s,
                "ip_version": ver_s,
                "consecutive_days": days,
                "distinct_links_total_in_window": len(all_hashes_in_window),
                "all_links_in_window": sorted(set(all_hashes_in_window.values())),
                "daily": daily_breakdown,
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
        "observed_collection_days_in_window": observed_in_window,
        "missing_collection_days_in_window": missing_in_window,
        "history_sufficient": history_sufficient,
        "warnings": warnings,
        "continuous_ip_count": len(continuous_ips),
        "ips": continuous_ips,
    }


def _print_today_report(res: dict, *, show_links: bool = False) -> None:
    print(f"=== 日期: {res['day']} (Asia/Shanghai) ===")
    if res.get("ip_source_filter") or res.get("ip_version_filter"):
        print(
            f"过滤条件: ip_source={res.get('ip_source_filter') or '全部'} "
            f"ip_version={res.get('ip_version_filter') or '全部'}"
        )
    if res["warning"]:
        print(f"[提示] {res['warning']}")
    col = res.get("collection") or {}
    print(
        f"采集轮次: 总 {col.get('run_count', 0)} 轮 "
        f"(完成 {col.get('completed_runs', 0)}, 中断 {col.get('interrupted_runs', 0)}) | "
        f"探测总次数: {col.get('tested_observations', 0)} "
        f"(连通探针通过 {col.get('probe_ok_observations', 0)}, "
        f"取到出口IP成功 {col.get('success_observations', 0)}, "
        f"失败 {col.get('fail_observations', 0)})"
    )
    print(
        f"1) 当日至少成功过 1 次的 DISTINCT xray_link 总数: {res['ever_good_link_count']}"
    )
    print(
        f"2) 当日测过且最新一次仍为成功的 DISTINCT xray_link 总数: {res['latest_good_on_day_link_count']}"
        f"  (注：历史探测状态，不代表实时在线承诺)"
    )
    print(
        f"3) 当日成功链接涉及的 DISTINCT 出口 IP 总数: {res['distinct_exit_ip_count']}"
    )
    print(
        f"4) 全局当前 status='good' 链接总数: {res['global_current_good_link_count']}"
    )
    if not res["by_ip"]:
        return

    print("\n--- 按出口 IP + 测量源 + 协议栈统计 (撞车去重前真实映射) ---")
    print("exit_ip\tip_source\tip_version\t当日成功distinct_links\t当日最新仍成功links\t当日成功探测次数")
    for item in res["by_ip"]:
        print(
            f"{item['exit_ip']}\t{item['ip_source']}\t{item['ip_version']}\t"
            f"{item['distinct_link_count']}\t{item['day_latest_good_link_count']}\t"
            f"{item['success_observations']}"
        )
        if show_links:
            for lk in item["links"]:
                print(f"    {lk}")


def _print_continuous_report(res: dict, *, show_links: bool = False) -> None:
    print(
        f"=== 连续 {res['requested_days']} 天存在出口 IP 查询 "
        f"({res['start_day']} ~ {res['end_day']}, Asia/Shanghai) ==="
    )
    if res.get("ip_source_filter") or res.get("ip_version_filter"):
        print(
            f"过滤条件: ip_source={res.get('ip_source_filter') or '全部'} "
            f"ip_version={res.get('ip_version_filter') or '全部'}"
        )
    for w in res["warnings"]:
        print(f"[告警] {w}")
    print(
        f"窗口内每天均至少 1 次成功观测的出口 IP 序列数量: {res['continuous_ip_count']}"
    )
    if not res["ips"]:
        return

    day_headers = "\t".join(res["window_days"])
    print(f"\nexit_ip\tip_source\tip_version\t窗口总distinct_links\t{day_headers}")
    for item in res["ips"]:
        per_day_str = "\t".join(
            str(d["distinct_link_count"]) for d in item["daily"]
        )
        print(
            f"{item['exit_ip']}\t{item['ip_source']}\t{item['ip_version']}\t"
            f"{item['distinct_links_total_in_window']}\t{per_day_str}"
        )
        if show_links:
            for d in item["daily"]:
                print(
                    f"  [{d['day']}] distinct_links={d['distinct_link_count']}:"
                )
                for lk in d["links"]:
                    print(f"    {lk}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Xray 出口 IP 与每日成功链接统计/导出工具（查询默认只读打开数据库，不改动任何数据）。"
    )
    parser.add_argument(
        "--db",
        default="data/state.sqlite",
        help="SQLite 数据库文件路径（默认: data/state.sqlite）",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 子命令 1: today
    p_today = sub.add_parser(
        "today",
        help="查询某天（默认今天 Asia/Shanghai）有多少 DISTINCT xray_link 成功工作及对应出口 IP",
    )
    p_today.add_argument(
        "--day",
        default=None,
        help="指定查询日期 YYYY-MM-DD（Asia/Shanghai，默认今天）",
    )
    p_today.add_argument(
        "--ip-source",
        default=None,
        help=f"按出口 IP 观测源过滤（如 {DEFAULT_IP_SOURCE}）",
    )
    p_today.add_argument(
        "--ip-version",
        choices=["ipv4", "ipv6"],
        default=None,
        help="按 IP 协议栈过滤（ipv4 或 ipv6）",
    )
    p_today.add_argument(
        "--show-links",
        action="store_true",
        help="按需输出每个出口 IP 对应的具体 xray_link 明文（含敏感凭据，默认关闭）",
    )
    p_today.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出",
    )

    # 子命令 2: continuous
    p_cont = sub.add_parser(
        "continuous",
        help="查询连续 X 天每天都至少有 1 次成功观测的出口 IP 及每日 DISTINCT link 数",
    )
    p_cont.add_argument(
        "--days",
        "-x",
        type=int,
        required=True,
        help="连续日历天数 X（如 3, 7, 14）",
    )
    p_cont.add_argument(
        "--end-day",
        default=None,
        help="窗口结束日期 YYYY-MM-DD（默认：昨天已完成日；配合 --include-today 则为今天）",
    )
    p_cont.add_argument(
        "--include-today",
        action="store_true",
        help="默认结束日未指定时将今天（incomplete）纳入窗口结束日",
    )
    p_cont.add_argument(
        "--ip-source",
        default=None,
        help=f"按出口 IP 观测源过滤（如 {DEFAULT_IP_SOURCE}）",
    )
    p_cont.add_argument(
        "--ip-version",
        choices=["ipv4", "ipv6"],
        default=None,
        help="按 IP 协议栈过滤（ipv4 或 ipv6）",
    )
    p_cont.add_argument(
        "--show-links",
        action="store_true",
        help="按需输出每个出口 IP 每天对应的具体 xray_link 明文（含敏感凭据，默认关闭）",
    )
    p_cont.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出",
    )

    # 子命令 3: export
    p_exp = sub.add_parser(
        "export",
        help="从数据库导出 good/failed/stable txt 与 ip_day_counts.csv / ip_summary.csv / ip_report.html",
    )
    p_exp.add_argument(
        "--out-dir",
        default="data",
        help="导出目录（默认: data）",
    )
    p_exp.add_argument(
        "--stable-days",
        type=int,
        default=30,
        help="stable 门槛最大天数（默认: 30）",
    )

    args = parser.parse_args(argv)
    db_path = Path(args.db)

    conn = open_db(db_path, readonly=True)
    try:
        if args.cmd == "today":
            res = query_day_links_and_ips(
                conn,
                target_day=args.day,
                ip_source=args.ip_source,
                ip_version=args.ip_version,
            )
            if not args.show_links:
                for item in res["by_ip"]:
                    item.pop("links", None)
                res.pop("links", None)
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                _print_today_report(res, show_links=args.show_links)
            return 0

        if args.cmd == "continuous":
            res = query_continuous_ips(
                conn,
                days=args.days,
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
                _print_continuous_report(res, show_links=args.show_links)
            return 0

        if args.cmd == "export":
            summary = export_all(
                conn,
                Path(args.out_dir),
                stable_days=args.stable_days,
            )
            print(json.dumps(summary, ensure_ascii=False))
            return 0
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
