from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import export
import select_links
import storage

SH_TZ = ZoneInfo("Asia/Shanghai")


def ts_shanghai(year: int, month: int, day: int, hour: int = 12, minute: int = 0) -> float:
    return datetime(year, month, day, hour, minute, tzinfo=SH_TZ).timestamp()


class TestIpTrackingAndQueries(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db_path = self.dir / "state.sqlite"
        self.out_dir = self.dir / "out"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_01_v1_migration_and_repeat_idempotency(self) -> None:
        """测试旧版 v1 数据库迁移：保留身份/状态/streak、标记 legacy_mixed、不伪造历史，且重复迁移幂等。"""
        raw_conn = sqlite3.connect(str(self.db_path))
        raw_conn.execute(
            """
            CREATE TABLE links(
                h TEXT PRIMARY KEY,
                link TEXT NOT NULL,
                status TEXT NOT NULL,
                exit_ip TEXT,
                ok_days INTEGER NOT NULL DEFAULT 0,
                last_ok_day TEXT,
                updated_at REAL NOT NULL
            )
            """
        )
        raw_conn.execute(
            "CREATE UNIQUE INDEX idx_ip ON links(exit_ip) WHERE exit_ip IS NOT NULL AND status='good'"
        )
        t0 = ts_shanghai(2026, 11, 1, 10, 0)
        l1 = "vless://u1@example.com:443?security=tls#n1"
        l2 = "vless://u2@example.com:443?security=tls#n2"
        raw_conn.execute(
            "INSERT INTO links VALUES(?,?,?,?,?,?,?)",
            (storage.link_hash(l1), l1, "good", "54.230.1.10", 5, "2026-11-01", t0),
        )
        raw_conn.execute(
            "INSERT INTO links VALUES(?,?,?,?,?,?,?)",
            (storage.link_hash(l2), l2, "failed", "54.230.1.10", 3, "2026-10-30", t0 - 3600),
        )
        raw_conn.commit()
        raw_conn.close()

        # 第一次迁移
        conn = storage.open_db(self.db_path, readonly=False)
        self.assertEqual(storage.get_schema_version(conn), 2)
        self.assertTrue(self.db_path.with_suffix(".sqlite.v1.bak").exists())

        rows = conn.execute(
            "SELECT link, status, exit_ip, ip_source, ip_version, ok_days, last_ok_day FROM links ORDER BY link"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], (l1, "good", "54.230.1.10", "legacy_mixed", "ipv4", 5, "2026-11-01"))
        self.assertEqual(rows[1], (l2, "failed", "54.230.1.10", "legacy_mixed", "ipv4", 3, "2026-10-30"))

        # 不从旧计数器伪造历史每日记录
        hist_cnt = conn.execute("SELECT COUNT(*) FROM daily_ip_links").fetchone()[0]
        self.assertEqual(hist_cnt, 0)

        # 当旧 legacy_mixed 链接在新权威源 checkip.amazonaws.com 下复测成功时，ok_days 从 1 重新起算，不混入旧源 streak
        t_next = ts_shanghai(2026, 11, 2, 10, 0)
        rk = storage.begin_run(conn, run_id="101", started_at=t_next)
        storage.record_probe_batch(
            conn,
            rk,
            [storage.ProbeRecord(l1, "good", "54.230.1.99", "ok", t_next + 1, "retest", 1)],
        )
        storage.end_run(conn, rk, "completed", ended_at=t_next + 5)
        new_row = conn.execute(
            "SELECT exit_ip, ip_source, ok_days, last_ok_day FROM links WHERE h=?",
            (storage.link_hash(l1),),
        ).fetchone()
        self.assertEqual(new_row, ("54.230.1.99", "checkip.amazonaws.com", 1, "2026-11-02"))
        self.assertEqual(export.stable_threshold(conn, now_ts=t_next + 5), 1)
        conn.close()

        # 第二次打开幂等无异常
        conn2 = storage.open_db(self.db_path, readonly=False)
        self.assertEqual(storage.get_schema_version(conn2), 2)
        conn2.close()

    def test_02_ip_collision_keeps_both_good_and_dedups_only_on_export(self) -> None:
        """同出口 IP 的多条成功链接均保持真实 good，每日统计计为 2，仅导出代表文件时选 1 条。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 9, 0)
        rk = storage.begin_run(conn, run_id="100", run_attempt=1, started_at=t1)

        l1 = "vless://a1@host1.example:443?security=tls#a1"
        l2 = "vless://a2@host2.example:443?security=tls#a2"
        ip = "3.112.45.67"

        ins, good_cnt = storage.record_probe_batch(
            conn,
            rk,
            [
                storage.ProbeRecord(l1, "good", ip, "ok", t1 + 1, "candidate", 1),
                storage.ProbeRecord(l2, "good", ip, "ok", t1 + 2, "candidate", 1),
            ],
        )
        storage.end_run(conn, rk, "completed", ended_at=t1 + 10)
        self.assertEqual((ins, good_cnt), (2, 2))

        # 两条链接在 links 表中状态都必须是 good
        statuses = conn.execute("SELECT status FROM links ORDER BY h").fetchall()
        self.assertEqual(statuses, [("good",), ("good",)])

        # 查询当天：distinct_link_count 为 2
        q = export.query_day_links_and_ips(conn, "2026-11-10", now_ts=t1 + 20)
        self.assertEqual(q["ever_good_link_count"], 2)
        self.assertEqual(q["distinct_exit_ip_count"], 1)
        self.assertEqual(q["by_ip"][0]["exit_ip"], ip)
        self.assertEqual(q["by_ip"][0]["distinct_link_count"], 2)
        self.assertEqual(sorted(q["by_ip"][0]["links"]), sorted([l1, l2]))

        # 导出：good_links.txt 和 stable_links_by_ip.txt 按出口 IP 去重只留 1 条代表
        stats = export.export_all(conn, self.out_dir, now_ts=t1 + 20)
        self.assertEqual(stats["good_total"], 2)
        self.assertEqual(stats["good_representative"], 1)
        good_lines = (self.out_dir / "good_links.txt").read_text().splitlines()
        self.assertEqual(len(good_lines), 1)
        stable_by_ip_lines = (self.out_dir / "stable_links_by_ip.txt").read_text().splitlines()
        self.assertEqual(len(stable_by_ip_lines), 1)
        self.assertTrue(stable_by_ip_lines[0].startswith(f"{ip} "))

        # ip_day_counts.csv 中记录的去重前真实数量为 2
        with open(self.out_dir / "ip_day_counts.csv", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)
        self.assertEqual(int(rows[0]["distinct_link_count"]), 2)
        conn.close()

    def test_03_same_link_rotates_ip_and_repeated_probes_dedup(self) -> None:
        """同一链接同日切换出口 IP 时两个 IP 均保留；同日重复测通同一 IP 时 distinct 不重复计数。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 10, 0)
        rk1 = storage.begin_run(conn, run_id="201", run_attempt=1, started_at=t1)
        lk = "vless://rot@host.example:443?security=tls#rot"
        ip1 = "13.230.10.1"
        ip2 = "13.230.10.2"

        storage.record_probe_batch(
            conn,
            rk1,
            [
                storage.ProbeRecord(lk, "good", ip1, "ok", t1 + 1, "candidate", 1),
                storage.ProbeRecord(lk, "good", ip1, "ok", t1 + 5, "verify", 1),
            ],
        )
        storage.end_run(conn, rk1, "completed", ended_at=t1 + 10)

        t2 = ts_shanghai(2026, 11, 10, 14, 0)
        rk2 = storage.begin_run(conn, run_id="202", run_attempt=1, started_at=t2)
        storage.record_probe_batch(
            conn,
            rk2,
            [storage.ProbeRecord(lk, "good", ip2, "ok", t2 + 1, "retest", 1)],
        )
        storage.end_run(conn, rk2, "completed", ended_at=t2 + 10)

        q = export.query_day_links_and_ips(conn, "2026-11-10", now_ts=t2 + 20)
        self.assertEqual(q["ever_good_link_count"], 1)
        self.assertEqual(q["distinct_exit_ip_count"], 2)
        by_ip = {item["exit_ip"]: item for item in q["by_ip"]}
        self.assertEqual(by_ip[ip1]["distinct_link_count"], 1)
        self.assertEqual(by_ip[ip1]["success_observations"], 2)
        self.assertEqual(by_ip[ip2]["distinct_link_count"], 1)
        self.assertEqual(by_ip[ip2]["success_observations"], 1)
        self.assertEqual(sorted(q["links"][0]["exit_ips"]), sorted([ip1, ip2]))
        conn.close()

    def test_04_fail_then_success_vs_success_then_fail_and_no_stale_ip_on_fail(self) -> None:
        """区分当日至少成功一次 vs 最新状态仍为成功，且失败观测绝不绑定陈旧 exit_ip。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 11, 8, 0)
        rk1 = storage.begin_run(conn, run_id="301", run_attempt=1, started_at=t1)

        link_a = "vless://a@example.com:443#fail_then_ok"
        link_b = "vless://b@example.com:443#ok_then_fail"
        ip_a = "18.180.1.1"
        ip_b = "18.180.1.2"

        # 第一轮：A 失败，B 成功
        storage.record_probe_batch(
            conn,
            rk1,
            [
                storage.ProbeRecord(link_a, "failed", None, "917", t1 + 1, "candidate", 1),
                storage.ProbeRecord(link_b, "good", ip_b, "ok", t1 + 2, "candidate", 1),
            ],
        )
        storage.end_run(conn, rk1, "completed", ended_at=t1 + 10)

        # 第二轮：A 成功，B 失败（即使调用方误传了旧 ip_b，失败记录也绝不能把 exit_ip 写进去）
        t2 = ts_shanghai(2026, 11, 11, 9, 0)
        rk2 = storage.begin_run(conn, run_id="302", run_attempt=1, started_at=t2)
        storage.record_probe_batch(
            conn,
            rk2,
            [
                storage.ProbeRecord(link_a, "good", ip_a, "ok", t2 + 1, "retry", 1),
                storage.ProbeRecord(link_b, "failed", ip_b, "917", t2 + 2, "retest", 1),
            ],
        )
        storage.end_run(conn, rk2, "completed", ended_at=t2 + 10)

        # 验证失败观测的 exit_ip 一定为 NULL
        fail_obs_ips = conn.execute(
            "SELECT exit_ip FROM observations WHERE status='failed'"
        ).fetchall()
        self.assertEqual(fail_obs_ips, [(None,), (None,)])

        # 验证今日查询：A 与 B 今日都曾成功过（ever_good=2），但仅 A 今日最新仍成功（latest_good=1）
        q = export.query_day_links_and_ips(conn, "2026-11-11", now_ts=t2 + 30)
        self.assertEqual(q["ever_good_link_count"], 2)
        self.assertEqual(q["latest_good_on_day_link_count"], 1)
        self.assertEqual(q["global_current_good_link_count"], 1)

        by_ip = {item["exit_ip"]: item for item in q["by_ip"]}
        self.assertEqual(by_ip[ip_a]["distinct_link_count"], 1)
        self.assertEqual(by_ip[ip_a]["day_latest_good_link_count"], 1)
        self.assertEqual(by_ip[ip_b]["distinct_link_count"], 1)
        self.assertEqual(by_ip[ip_b]["day_latest_good_link_count"], 0)
        conn.close()

    def test_05_replay_idempotency_and_run_attempts(self) -> None:
        """相同观测重放完全幂等，不同 run_attempt 则独立记录。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 10, 0)
        rk_att1 = storage.begin_run(conn, run_id="400", run_attempt=1, started_at=t1)
        lk = "vless://idem@example.com:443#1"
        rec = storage.ProbeRecord(lk, "good", "52.192.1.1", "ok", t1 + 1, "candidate", 1)

        ins1, _ = storage.record_probe_batch(conn, rk_att1, [rec])
        ins2, _ = storage.record_probe_batch(conn, rk_att1, [rec])
        self.assertEqual(ins1, 1)
        self.assertEqual(ins2, 0)

        cnt = conn.execute("SELECT success_count FROM daily_ip_links").fetchone()[0]
        self.assertEqual(cnt, 1)

        # 同一 run_id 的 attempt=2 应正常写入
        rk_att2 = storage.begin_run(conn, run_id="400", run_attempt=2, started_at=t1 + 60)
        ins3, _ = storage.record_probe_batch(conn, rk_att2, [rec])
        self.assertEqual(ins3, 1)
        cnt2 = conn.execute("SELECT success_count FROM daily_ip_links").fetchone()[0]
        self.assertEqual(cnt2, 2)
        conn.close()

    def test_06_continuous_ips_across_days_with_different_links_and_missing_day_warnings(self) -> None:
        """测试连续 X 天存在 IP 查询（支持不同链接接力）、缺失采集日告警与今日 incomplete 标记。"""
        conn = storage.open_db(self.db_path)
        l1 = "vless://d1@example.com:443#1"
        l2 = "vless://d2@example.com:443#2"
        l3 = "vless://d3@example.com:443#3"
        ip_steady = "35.72.10.1"
        ip_gap = "35.72.10.2"

        # 构造 2026-11-08, 2026-11-09, 2026-11-10 三天已完成数据，以及 2026-11-11 今日数据
        days_data = [
            ((2026, 11, 8), [(l1, ip_steady), (l1, ip_gap)]),
            ((2026, 11, 9), [(l2, ip_steady), (l3, ip_steady)]),  # ip_steady 换成了 l2+l3，ip_gap 断更
            ((2026, 11, 10), [(l3, ip_steady), (l2, ip_gap)]),
            ((2026, 11, 11), [(l1, ip_steady)]),
        ]
        for idx, (ymd, pairs) in enumerate(days_data, start=1):
            t = ts_shanghai(*ymd, 12, 0)
            rk = storage.begin_run(conn, run_id=f"50{idx}", run_attempt=1, started_at=t)
            recs = [
                storage.ProbeRecord(lk, "good", ip, "ok", t + i, "candidate", 1)
                for i, (lk, ip) in enumerate(pairs, start=1)
            ]
            storage.record_probe_batch(conn, rk, recs)
            storage.end_run(conn, rk, "completed", ended_at=t + 30)

        now_sh = ts_shanghai(2026, 11, 11, 15, 0)

        # 1) 默认查询截至昨天（2026-11-08 ~ 2026-11-10）连续 3 天
        res3 = export.query_continuous_ips(conn, days=3, now_ts=now_sh)
        self.assertEqual(res3["window_days"], ["2026-11-08", "2026-11-09", "2026-11-10"])
        self.assertFalse(res3["includes_incomplete_today"])
        self.assertTrue(res3["history_sufficient"])
        self.assertEqual(res3["continuous_ip_count"], 1)

        ip_info = res3["ips"][0]
        self.assertEqual(ip_info["exit_ip"], ip_steady)
        self.assertEqual(ip_info["distinct_links_total_in_window"], 3)  # l1, l2, l3
        self.assertEqual(
            [d["distinct_link_count"] for d in ip_info["daily"]],
            [1, 2, 1],
        )

        # 2) 包含今日查询连续 4 天（2026-11-08 ~ 2026-11-11）
        res4_today = export.query_continuous_ips(
            conn, days=4, include_today=True, now_ts=now_sh
        )
        self.assertTrue(res4_today["includes_incomplete_today"])
        self.assertEqual(res4_today["continuous_ip_count"], 1)
        self.assertTrue(any("incomplete" in w for w in res4_today["warnings"]))

        # 3) 请求连续 7 天（数据库只有 4 个采集日）：必须返回明确告警且结果为 0
        res7 = export.query_continuous_ips(conn, days=7, now_ts=now_sh)
        self.assertFalse(res7["history_sufficient"])
        self.assertEqual(res7["continuous_ip_count"], 0)
        self.assertTrue(any("历史采集天数不足" in w for w in res7["warnings"]))
        self.assertTrue(any("未采集日期" in w for w in res7["warnings"]))
        conn.close()

    def test_07_shanghai_midnight_boundary(self) -> None:
        """验证上海时区午夜切分：23:59 与次日 00:01（同属一个 UTC 日）正确分属两个上海自然日。"""
        conn = storage.open_db(self.db_path)
        # 2026-11-10 23:59 Asia/Shanghai == 2026-11-10 15:59 UTC
        t_before = ts_shanghai(2026, 11, 10, 23, 59)
        # 2026-11-11 00:01 Asia/Shanghai == 2026-11-10 16:01 UTC
        t_after = ts_shanghai(2026, 11, 11, 0, 1)

        lk = "vless://mid@example.com:443#mid"
        ip = "54.65.1.1"
        rk1 = storage.begin_run(conn, run_id="601", started_at=t_before)
        storage.record_probe_batch(
            conn, rk1, [storage.ProbeRecord(lk, "good", ip, "ok", t_before, "candidate", 1)]
        )
        storage.end_run(conn, rk1, "completed", ended_at=t_before + 10)

        rk2 = storage.begin_run(conn, run_id="602", started_at=t_after)
        storage.record_probe_batch(
            conn, rk2, [storage.ProbeRecord(lk, "good", ip, "ok", t_after, "retest", 1)]
        )
        storage.end_run(conn, rk2, "completed", ended_at=t_after + 10)

        days = [
            r[0]
            for r in conn.execute("SELECT day FROM daily_ip_links ORDER BY day").fetchall()
        ]
        self.assertEqual(days, ["2026-11-10", "2026-11-11"])

        # 同时验证旧版 links.last_ok_day 仍保持 UTC 日期（两次都在 UTC 2026-11-10，故 ok_days 为 1）
        ok_days, last_ok_day = conn.execute(
            "SELECT ok_days, last_ok_day FROM links WHERE h=?",
            (storage.link_hash(lk),),
        ).fetchone()
        self.assertEqual((ok_days, last_ok_day), (1, "2026-11-10"))
        conn.close()

    def test_08_raw_retention_purge_preserves_exports_and_queries(self) -> None:
        """清理过期原始 observations 后，所有导出文件与查询结果保持完全一致。"""
        conn = storage.open_db(self.db_path)
        # 构造 40 天前与 39 天前两天的数据
        t_d1 = ts_shanghai(2026, 9, 20, 12, 0)
        t_d2 = ts_shanghai(2026, 9, 21, 12, 0)
        t_now = ts_shanghai(2026, 11, 11, 12, 0)

        lk = "vless://old@example.com:443#old"
        ip = "54.248.10.20"
        for idx, t in enumerate([t_d1, t_d2], start=1):
            rk = storage.begin_run(conn, run_id=f"70{idx}", started_at=t)
            storage.record_probe_batch(
                conn, rk, [storage.ProbeRecord(lk, "good", ip, "ok", t + 1, "candidate", 1)]
            )
            storage.end_run(conn, rk, "completed", ended_at=t + 5)

        out1 = self.dir / "out_before"
        out2 = self.dir / "out_after"
        export.export_all(conn, out1, now_ts=t_now)
        q_before = export.query_continuous_ips(
            conn, days=2, end_day="2026-09-21", now_ts=t_now
        )

        deleted = storage.purge_old_observations(conn, retention_days=30, now_ts=t_now)
        self.assertEqual(deleted, 2)
        obs_left = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        self.assertEqual(obs_left, 0)

        export.export_all(conn, out2, now_ts=t_now)
        q_after = export.query_continuous_ips(
            conn, days=2, end_day="2026-09-21", now_ts=t_now
        )

        self.assertEqual(q_before, q_after)
        for fname in [
            "good_links.txt",
            "failed_links.txt",
            "stable_links.txt",
            "stable_links_by_ip.txt",
            "ip_day_counts.csv",
            "ip_summary.csv",
            "collection_days.csv",
            "ip_report.html",
        ]:
            self.assertEqual(
                (out1 / fname).read_bytes(),
                (out2 / fname).read_bytes(),
                f"文件 {fname} 在清理原始观测前后不一致",
            )
        conn.close()

    def test_09_ip_validation_and_source_isolation(self) -> None:
        """测试出口 IP 严格校验（拒绝多 IP/私网/错误协议栈）及不同 ip_source 连续性隔离。"""
        # 1) 校验器测试
        self.assertEqual(
            storage.parse_and_validate_exit_ip("54.238.1.2\n", allowed_family="4"),
            ("54.238.1.2", "ipv4", "ok"),
        )
        self.assertEqual(
            storage.parse_and_validate_exit_ip("1.1.1.1, 2.2.2.2", allowed_family="4")[2],
            "ip_multi",
        )
        self.assertEqual(
            storage.parse_and_validate_exit_ip("127.0.0.1", allowed_family="4")[2],
            "ip_non_global",
        )
        self.assertEqual(
            storage.parse_and_validate_exit_ip("2606:4700:4700::1111", allowed_family="4")[2],
            "ip_family",
        )
        self.assertEqual(
            storage.parse_and_validate_exit_ip("<html>error</html>", allowed_family="4")[2],
            "ip_invalid",
        )

        # 2) 不同 ip_source 不混入同一连续序列
        conn = storage.open_db(self.db_path)
        t_d1 = ts_shanghai(2026, 11, 9, 12, 0)
        t_d2 = ts_shanghai(2026, 11, 10, 12, 0)
        lk = "vless://src@example.com:443#src"
        ip = "104.21.1.1"

        rk1 = storage.begin_run(conn, run_id="801", started_at=t_d1)
        storage.record_probe_batch(
            conn,
            rk1,
            [
                storage.ProbeRecord(
                    lk, "good", ip, "ok", t_d1 + 1, "candidate", 1, ip_source="checkip.amazonaws.com"
                )
            ],
        )
        storage.end_run(conn, rk1, "completed", ended_at=t_d1 + 5)

        rk2 = storage.begin_run(conn, run_id="802", started_at=t_d2)
        storage.record_probe_batch(
            conn,
            rk2,
            [
                storage.ProbeRecord(
                    lk, "good", ip, "ok", t_d2 + 1, "retest", 1, ip_source="api.ipify.org"
                )
            ],
        )
        storage.end_run(conn, rk2, "completed", ended_at=t_d2 + 5)

        # 虽然 11-09 和 11-10 都看到了 104.21.1.1，但来自不同测量源，不应算作连续 2 天同一序列
        res = export.query_continuous_ips(
            conn, days=2, end_day="2026-11-10", now_ts=t_d2 + 60
        )
        self.assertEqual(res["continuous_ip_count"], 0)
        conn.close()

    def test_10_cli_queries_are_strictly_readonly(self) -> None:
        """执行 CLI 查询前后，数据库文件内容不发生任何变化。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 12, 0)
        rk = storage.begin_run(conn, run_id="901", started_at=t1)
        lk = "vless://ro@example.com:443#ro"
        storage.record_probe_batch(
            conn, rk, [storage.ProbeRecord(lk, "good", "3.115.1.1", "ok", t1 + 1, "candidate", 1)]
        )
        storage.end_run(conn, rk, "completed", ended_at=t1 + 5)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()

        before_sha = hashlib.sha256(self.db_path.read_bytes()).hexdigest()

        cmd_today = [
            sys.executable,
            str(ROOT / "export.py"),
            "--db",
            str(self.db_path),
            "today",
            "--day",
            "2026-11-10",
            "--json",
        ]
        r1 = subprocess.run(cmd_today, capture_output=True, text=True, check=True)
        data_today = json.loads(r1.stdout)
        self.assertEqual(data_today["ever_good_link_count"], 1)
        self.assertNotIn("links", data_today)  # 默认不输出敏感链接明文

        cmd_cont = [
            sys.executable,
            str(ROOT / "export.py"),
            "--db",
            str(self.db_path),
            "continuous",
            "--days",
            "1",
            "--end-day",
            "2026-11-10",
            "--show-links",
            "--json",
        ]
        r2 = subprocess.run(cmd_cont, capture_output=True, text=True, check=True)
        data_cont = json.loads(r2.stdout)
        self.assertEqual(data_cont["continuous_ip_count"], 1)
        self.assertEqual(data_cont["ips"][0]["daily"][0]["links"], [lk])

        after_sha = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        self.assertEqual(before_sha, after_sha)

    def test_11_interrupted_run_recovery(self) -> None:
        """未完结的 running 轮次在下一轮启动时自动标记为 interrupted，已提交批次保留。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 10, 0)
        rk1 = storage.begin_run(conn, run_id="1001", started_at=t1)
        lk = "vless://int@example.com:443#int"
        storage.record_probe_batch(
            conn, rk1, [storage.ProbeRecord(lk, "good", "18.179.1.1", "ok", t1 + 1, "candidate", 1)]
        )
        # 不调用 end_run，模拟进程中断；启动下一轮
        rk2 = storage.begin_run(conn, run_id="1002", started_at=t1 + 300)
        storage.end_run(conn, rk2, "completed", ended_at=t1 + 310)

        st1 = conn.execute("SELECT status FROM runs WHERE run_key=?", (rk1,)).fetchone()[0]
        self.assertEqual(st1, "interrupted")
        cd = conn.execute(
            "SELECT run_count, completed_runs, interrupted_runs, success_observations FROM collection_days WHERE day='2026-11-10'"
        ).fetchone()
        self.assertEqual(cd, (2, 1, 1, 1))
        conn.close()

    def test_12_select_links_end_to_end_mocked(self) -> None:
        """在不发起任何真实网络探测的前提下，验证 select_links 主流程与导出完整协同。"""
        l1 = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#n1"
        l2 = "vless://22222222-2222-2222-2222-222222222222@example.com:443?security=tls#n2"
        l3 = "vless://33333333-3333-3333-3333-333333333333@example.com:443?security=tls#n3"

        orig_data = select_links.DATA
        orig_db = select_links.DB
        orig_progress = select_links.PROGRESS_FILE
        orig_fetch = select_links.fetch_candidates
        orig_probe = select_links.probe

        try:
            select_links.DATA = self.out_dir
            select_links.DB = self.db_path
            select_links.PROGRESS_FILE = self.out_dir / "progress.txt"
            select_links.fetch_candidates = lambda: [l1, l2, l3]

            def fake_probe(link: str, timeout: float | None = None):
                if link in (l1, l2):
                    return "good", "54.150.1.10", "ok"
                return "failed", None, "917"

            select_links.probe = fake_probe
            rc = select_links.main()
            self.assertEqual(rc, 0)

            self.assertTrue((self.out_dir / "good_links.txt").exists())
            self.assertTrue((self.out_dir / "ip_day_counts.csv").exists())
            self.assertTrue((self.out_dir / "ip_summary.csv").exists())
            self.assertTrue((self.out_dir / "collection_days.csv").exists())
            self.assertTrue((self.out_dir / "ip_report.html").exists())

            # l1 和 l2 同出口 IP，good_links.txt 代表去重后为 1 行，ip_day_counts.csv 中 distinct_link_count 为 2
            good_lines = (self.out_dir / "good_links.txt").read_text().splitlines()
            self.assertEqual(len(good_lines), 1)
            with open(self.out_dir / "ip_day_counts.csv", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(int(rows[0]["distinct_link_count"]), 2)
        finally:
            select_links.DATA = orig_data
            select_links.DB = orig_db
            select_links.PROGRESS_FILE = orig_progress
            select_links.fetch_candidates = orig_fetch
            select_links.probe = orig_probe


if __name__ == "__main__":
    unittest.main()
