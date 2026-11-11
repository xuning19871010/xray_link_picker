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

    def test_01_v1_migration_preserves_state_and_repeat_idempotency(self) -> None:
        """v1 迁移保留身份/状态/updated_at/streak 与 legacy_links_snapshot，不伪造历史或 added_at。"""
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
            (storage.link_hash(l2), l2, "failed", None, 0, None, t0 - 86400 * 10),
        )
        raw_conn.commit()
        raw_conn.close()

        conn = storage.open_db(self.db_path, readonly=False)
        self.assertEqual(storage.get_schema_version(conn), 2)
        self.assertTrue(self.db_path.with_suffix(".sqlite.v1.bak").exists())

        rows = conn.execute(
            "SELECT link, status, exit_ip, ip_source, ip_version, ok_days, last_ok_day, updated_at FROM links ORDER BY link"
        ).fetchall()
        self.assertEqual(
            rows,
            [
                (l1, "good", "54.230.1.10", "legacy_mixed", "ipv4", 5, "2026-11-01", t0),
                (l2, "failed", None, None, None, 0, None, t0 - 86400 * 10),
            ],
        )
        snap_cnt = conn.execute("SELECT COUNT(*) FROM legacy_links_snapshot").fetchone()[0]
        self.assertEqual(snap_cnt, 2)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM daily_ip_links").fetchone()[0], 0)

        # 次日复测成功时，旧版 ok_days 在 UTC 口径下继续从 5 递增为 6（不静默清零旧计数器）
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
        self.assertEqual(
            new_row, ("54.230.1.99", "https://checkip.amazonaws.com", 6, "2026-11-02")
        )
        conn.close()

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
        self.assertEqual(
            conn.execute("SELECT status FROM links ORDER BY h").fetchall(),
            [("good",), ("good",)],
        )

        q = export.query_day_links_and_ips(conn, "2026-11-10", now_ts=t1 + 20)
        self.assertEqual(q["ever_good_link_count"], 2)
        self.assertEqual(q["by_ip"][0]["distinct_link_count"], 2)

        stats = export.export_all(conn, self.out_dir, now_ts=t1 + 20)
        self.assertEqual((stats["good_total"], stats["good_representative"]), (2, 1))
        self.assertEqual(len((self.out_dir / "good_links.txt").read_text().splitlines()), 1)
        with open(self.out_dir / "ip_day_counts.csv", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(int(rows[0]["distinct_link_count"]), 2)
        conn.close()

    def test_03_same_link_rotates_ip_and_repeated_probes_dedup(self) -> None:
        """同一链接同日切换出口 IP 时两个 IP 均保留；同日重复测通同一 IP 时 distinct 不重复计数。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 10, 0)
        rk1 = storage.begin_run(conn, run_id="201", run_attempt=1, started_at=t1)
        lk = "vless://rot@host.example:443?security=tls#rot"
        ip1, ip2 = "13.230.10.1", "13.230.10.2"

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
            conn, rk2, [storage.ProbeRecord(lk, "good", ip2, "ok", t2 + 1, "retest", 1)]
        )
        storage.end_run(conn, rk2, "completed", ended_at=t2 + 10)

        q = export.query_day_links_and_ips(conn, "2026-11-10", now_ts=t2 + 20)
        self.assertEqual((q["ever_good_link_count"], q["distinct_exit_ip_count"]), (1, 2))
        by_ip = {item["exit_ip"]: item for item in q["by_ip"]}
        self.assertEqual((by_ip[ip1]["distinct_link_count"], by_ip[ip1]["success_observations"]), (1, 2))
        self.assertEqual((by_ip[ip2]["distinct_link_count"], by_ip[ip2]["success_observations"]), (1, 1))
        self.assertEqual(sorted(q["links"][0]["exit_ips"]), sorted([ip1, ip2]))
        conn.close()

    def test_04_fail_success_transitions_and_no_ip_excluded(self) -> None:
        """区分先失败后成功 vs 先成功再失败；无 IP 的伪 good 自动降级为 failed；失败不绑定旧 IP。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 11, 8, 0)
        rk1 = storage.begin_run(conn, run_id="301", started_at=t1)

        link_a = "vless://a@example.com:443#fail_then_ok"
        link_b = "vless://b@example.com:443#ok_then_fail"
        link_no_ip = "vless://c@example.com:443#no_ip"
        ip_a, ip_b = "18.180.1.1", "18.180.1.2"

        storage.record_probe_batch(
            conn,
            rk1,
            [
                storage.ProbeRecord(link_a, "failed", None, "917", t1 + 1, "candidate", 1),
                storage.ProbeRecord(link_b, "good", ip_b, "ok", t1 + 2, "candidate", 1),
                storage.ProbeRecord(link_no_ip, "good", None, "ok", t1 + 3, "candidate", 1),
            ],
        )
        storage.end_run(conn, rk1, "completed", ended_at=t1 + 10)

        t2 = ts_shanghai(2026, 11, 11, 9, 0)
        rk2 = storage.begin_run(conn, run_id="302", started_at=t2)
        storage.record_probe_batch(
            conn,
            rk2,
            [
                storage.ProbeRecord(link_a, "good", ip_a, "ok", t2 + 1, "retry", 1),
                storage.ProbeRecord(link_b, "failed", ip_b, "917", t2 + 2, "retest", 1),
            ],
        )
        storage.end_run(conn, rk2, "completed", ended_at=t2 + 10)

        fail_obs_ips = conn.execute(
            "SELECT exit_ip FROM observations WHERE status='failed'"
        ).fetchall()
        self.assertTrue(all(r[0] is None for r in fail_obs_ips))

        q = export.query_day_links_and_ips(conn, "2026-11-11", now_ts=t2 + 30)
        self.assertEqual(q["ever_good_link_count"], 2)  # link_a, link_b（不含 link_no_ip）
        self.assertEqual(q["latest_good_on_day_link_count"], 1)  # 仅 link_a
        self.assertEqual(q["global_current_good_link_count"], 1)
        conn.close()

    def test_05_replay_idempotency_and_retries(self) -> None:
        """相同 obs_id 重放幂等；同一轮内不同 seq（重试）或不同 run_attempt 正常记录。"""
        conn = storage.open_db(self.db_path)
        t1 = ts_shanghai(2026, 11, 10, 10, 0)
        rk_att1 = storage.begin_run(conn, run_id="400", run_attempt=1, started_at=t1)
        lk = "vless://idem@example.com:443#1"
        rec_seq1 = storage.ProbeRecord(lk, "good", "52.192.1.1", "ok", t1 + 1, "candidate", 1)
        rec_seq2 = storage.ProbeRecord(lk, "good", "52.192.1.1", "ok", t1 + 2, "candidate", 2)

        self.assertEqual(storage.record_probe_batch(conn, rk_att1, [rec_seq1])[0], 1)
        self.assertEqual(storage.record_probe_batch(conn, rk_att1, [rec_seq1])[0], 0)
        self.assertEqual(storage.record_probe_batch(conn, rk_att1, [rec_seq2])[0], 1)

        rk_att2 = storage.begin_run(conn, run_id="400", run_attempt=2, started_at=t1 + 60)
        self.assertEqual(storage.record_probe_batch(conn, rk_att2, [rec_seq1])[0], 1)
        cnt = conn.execute("SELECT success_count FROM daily_ip_links").fetchone()[0]
        self.assertEqual(cnt, 3)
        conn.close()

    def test_06_continuous_ips_and_missing_day_warnings(self) -> None:
        """测试连续 X 天存在 IP 查询（支持不同链接接力）、缺失采集日告警与今日 incomplete 标记。"""
        conn = storage.open_db(self.db_path)
        l1, l2, l3 = "vless://d1@e.com:443#1", "vless://d2@e.com:443#2", "vless://d3@e.com:443#3"
        ip_steady, ip_gap = "35.72.10.1", "35.72.10.2"

        days_data = [
            ((2026, 11, 8), [(l1, ip_steady), (l1, ip_gap)]),
            ((2026, 11, 9), [(l2, ip_steady), (l3, ip_steady)]),
            ((2026, 11, 10), [(l3, ip_steady), (l2, ip_gap)]),
            ((2026, 11, 11), [(l1, ip_steady)]),
        ]
        for idx, (ymd, pairs) in enumerate(days_data, start=1):
            t = ts_shanghai(*ymd, 12, 0)
            rk = storage.begin_run(conn, run_id=f"50{idx}", started_at=t)
            recs = [
                storage.ProbeRecord(lk, "good", ip, "ok", t + i, "candidate", 1)
                for i, (lk, ip) in enumerate(pairs, start=1)
            ]
            storage.record_probe_batch(conn, rk, recs)
            storage.end_run(conn, rk, "completed", ended_at=t + 30)

        now_sh = ts_shanghai(2026, 11, 11, 15, 0)
        res3 = export.query_continuous_ips(conn, days=3, now_ts=now_sh)
        self.assertEqual(res3["window_days"], ["2026-11-08", "2026-11-09", "2026-11-10"])
        self.assertEqual(res3["continuous_ip_count"], 1)
        self.assertEqual(res3["ips"][0]["distinct_links_total_in_window"], 3)
        self.assertEqual([d["distinct_link_count"] for d in res3["ips"][0]["daily"]], [1, 2, 1])

        res7 = export.query_continuous_ips(conn, days=7, now_ts=now_sh)
        self.assertFalse(res7["history_sufficient"])
        self.assertEqual(res7["continuous_ip_count"], 0)
        self.assertTrue(any("历史采集天数不足" in w for w in res7["warnings"]))
        conn.close()

    def test_07_shanghai_midnight_boundary(self) -> None:
        """上海时区 23:59 与次日 00:01（同属一个 UTC 日）正确分属两个上海自然日。"""
        conn = storage.open_db(self.db_path)
        t_before = ts_shanghai(2026, 11, 10, 23, 59)
        t_after = ts_shanghai(2026, 11, 11, 0, 1)
        lk, ip = "vless://mid@example.com:443#mid", "54.65.1.1"

        for idx, t in enumerate([t_before, t_after], start=1):
            rk = storage.begin_run(conn, run_id=f"60{idx}", started_at=t)
            storage.record_probe_batch(
                conn, rk, [storage.ProbeRecord(lk, "good", ip, "ok", t, "candidate", 1)]
            )
            storage.end_run(conn, rk, "completed", ended_at=t + 5)

        days = [r[0] for r in conn.execute("SELECT day FROM daily_ip_links ORDER BY day")]
        self.assertEqual(days, ["2026-11-10", "2026-11-11"])
        conn.close()

    def test_08_raw_retention_purge_preserves_exports_and_latest_queries(self) -> None:
        """清理过期原始 observations 后，导出文件、run 计数与当日最新状态查询完全一致。"""
        conn = storage.open_db(self.db_path)
        t_d1 = ts_shanghai(2026, 9, 20, 12, 0)
        t_d2 = ts_shanghai(2026, 9, 21, 12, 0)
        t_now = ts_shanghai(2026, 11, 11, 12, 0)
        l_ok = "vless://ok@example.com:443#ok"
        l_drop = "vless://drop@example.com:443#drop"
        ip = "54.248.10.20"

        rk1 = storage.begin_run(conn, run_id="701", started_at=t_d1)
        storage.record_probe_batch(
            conn,
            rk1,
            [
                storage.ProbeRecord(l_ok, "good", ip, "ok", t_d1 + 1, "candidate", 1),
                storage.ProbeRecord(l_drop, "good", ip, "ok", t_d1 + 2, "candidate", 1),
            ],
        )
        storage.end_run(conn, rk1, "completed", ended_at=t_d1 + 5)

        rk2 = storage.begin_run(conn, run_id="702", started_at=t_d2)
        storage.record_probe_batch(
            conn,
            rk2,
            [
                storage.ProbeRecord(l_ok, "good", ip, "ok", t_d2 + 1, "retest", 1),
                storage.ProbeRecord(l_drop, "good", ip, "ok", t_d2 + 2, "retest", 1),
                storage.ProbeRecord(l_drop, "failed", None, "917", t_d2 + 10, "verify", 1),
            ],
        )
        storage.end_run(conn, rk2, "completed", ended_at=t_d2 + 15)

        out1, out2 = self.dir / "out_before", self.dir / "out_after"
        export.export_all(conn, out1, now_ts=t_now)
        q_day_before = export.query_day_links_and_ips(conn, "2026-09-21", now_ts=t_now)
        q_cont_before = export.query_continuous_ips(conn, days=2, end_day="2026-09-21", now_ts=t_now)

        deleted = storage.purge_old_observations(conn, retention_days=30, now_ts=t_now)
        self.assertEqual(deleted, 5)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 0)

        export.export_all(conn, out2, now_ts=t_now)
        q_day_after = export.query_day_links_and_ips(conn, "2026-09-21", now_ts=t_now)
        q_cont_after = export.query_continuous_ips(conn, days=2, end_day="2026-09-21", now_ts=t_now)

        self.assertEqual(q_day_before, q_day_after)
        self.assertEqual(q_day_after["ever_good_link_count"], 2)
        self.assertEqual(q_day_after["latest_good_on_day_link_count"], 1)
        self.assertEqual(q_cont_before, q_cont_after)
        for fname in ["ip_day_counts.csv", "ip_summary.csv", "collection_days.csv", "ip_report.html"]:
            self.assertEqual((out1 / fname).read_bytes(), (out2 / fname).read_bytes())
        conn.close()

    def test_09_ip_source_uri_identity_credential_strip_and_isolation(self) -> None:
        """测试完整 URI 标识（同域名不同路径不混用、剥离 user:pass 凭据）与 IP 校验。"""
        self.assertEqual(
            storage.normalize_ip_source("https://user:secret@Example.com:443/ip/v1?fmt=text#frag"),
            "https://example.com/ip/v1?fmt=text",
        )
        self.assertNotEqual(
            storage.normalize_ip_source("https://example.com/observer-a"),
            storage.normalize_ip_source("https://example.com/observer-b"),
        )
        self.assertEqual(storage.parse_and_validate_exit_ip("1.1.1.1, 2.2.2.2", "4")[2], "ip_multi")
        self.assertEqual(storage.parse_and_validate_exit_ip("10.0.0.1", "4")[2], "ip_non_global")
        self.assertEqual(storage.parse_and_validate_exit_ip("2606:4700::1", "4")[2], "ip_family")

        conn = storage.open_db(self.db_path)
        t_d1 = ts_shanghai(2026, 11, 9, 12, 0)
        t_d2 = ts_shanghai(2026, 11, 10, 12, 0)
        lk, ip = "vless://src@example.com:443#src", "104.21.1.1"

        rk1 = storage.begin_run(conn, run_id="801", started_at=t_d1)
        storage.record_probe_batch(
            conn,
            rk1,
            [storage.ProbeRecord(lk, "good", ip, "ok", t_d1 + 1, "candidate", 1, ip_source="https://obs.example.com/a")],
        )
        storage.end_run(conn, rk1, "completed", ended_at=t_d1 + 5)

        rk2 = storage.begin_run(conn, run_id="802", started_at=t_d2)
        storage.record_probe_batch(
            conn,
            rk2,
            [storage.ProbeRecord(lk, "good", ip, "ok", t_d2 + 1, "retest", 1, ip_source="https://obs.example.com/b")],
        )
        storage.end_run(conn, rk2, "completed", ended_at=t_d2 + 5)

        res = export.query_continuous_ips(conn, days=2, end_day="2026-11-10", now_ts=t_d2 + 60)
        self.assertEqual(res["continuous_ip_count"], 0)
        conn.close()

    def test_10_cli_queries_are_strictly_readonly_and_end_to_end_mocked(self) -> None:
        """验证 select_links Mock 全流程运行及 CLI 查询严格只读不改动数据库。"""
        l1 = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#n1"
        l2 = "vless://22222222-2222-2222-2222-222222222222@example.com:443?security=tls#n2"
        l3 = "vless://33333333-3333-3333-3333-333333333333@example.com:443?security=tls#n3"

        orig = (
            select_links.DATA,
            select_links.DB,
            select_links.PROGRESS_FILE,
            select_links.fetch_candidates,
            select_links.probe,
        )
        try:
            select_links.DATA = self.out_dir
            select_links.DB = self.db_path
            select_links.PROGRESS_FILE = self.out_dir / "progress.txt"
            select_links.fetch_candidates = lambda: [l1, l2, l3]
            select_links.probe = lambda link, timeout=None: (
                ("good", "54.150.1.10", "ok") if link in (l1, l2) else ("failed", None, "917")
            )
            self.assertEqual(select_links.main(), 0)
        finally:
            (
                select_links.DATA,
                select_links.DB,
                select_links.PROGRESS_FILE,
                select_links.fetch_candidates,
                select_links.probe,
            ) = orig

        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        before_sha = hashlib.sha256(self.db_path.read_bytes()).hexdigest()

        r1 = subprocess.run(
            [sys.executable, str(ROOT / "export.py"), "--db", str(self.db_path), "today", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        data_today = json.loads(r1.stdout)
        self.assertEqual(data_today["ever_good_link_count"], 2)
        self.assertNotIn("links", data_today)

        after_sha = hashlib.sha256(self.db_path.read_bytes()).hexdigest()
        self.assertEqual(before_sha, after_sha)


if __name__ == "__main__":
    unittest.main()
