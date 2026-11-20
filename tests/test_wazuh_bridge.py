import argparse
import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wazuh_bridge as wb

SCRIPT = Path(__file__).resolve().parents[1] / "wazuh_bridge.py"

GOOD = (
    '{"timestamp":"2026-01-01T00:00:00-0600","rule":{"level":10,"description":"high"},'
    '"agent":{"name":"a"},"srcip":"1.2.3.4"}\n'
    '{"timestamp":"2026-01-01T00:00:01-0600","rule":{"level":3,"description":"low"},'
    '"agent":{"name":"a"},"srcip":"1.2.3.4"}\n'
)


def run_cli(*args, cwd):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                          cwd=cwd, capture_output=True)


class WazuhBridgeChecksTests(unittest.TestCase):
    def test_check_status_vocabulary_is_closed(self):
        with self.assertRaises(ValueError):
            wb._check("tail", "maybe")
        for status in wb.CHECK_STATUSES:
            self.assertEqual(wb._check("x", status)["status"], status)

    def test_successful_run_reports_three_confirmed_checks(self):
        result = {"read_ok": True, "lines_read": 5, "alerts_read": 4,
                  "malformed": 1, "groups": 2, "queue": [{"count": 1}]}
        rows = wb.checks(result)
        self.assertEqual([r["check"] for r in rows], ["tail", "parse", "grouping"])
        self.assertEqual([r["status"] for r in rows], ["confirmed"] * 3)
        self.assertEqual(rows[0]["detail"], "5 line(s)")
        self.assertIn("4 alert(s)", rows[1]["detail"])
        self.assertIn("1 malformed", rows[1]["detail"])
        self.assertIn("1 queued", rows[2]["detail"])

    def test_failed_read_is_never_clean(self):
        result = {"read_ok": False, "read_error": "wsl read failed"}
        rows = wb.checks(result)
        self.assertEqual([r["status"] for r in rows],
                         ["not_confirmed", "not_confirmed", "skipped"])
        self.assertEqual(rows[2]["detail"], "parse not confirmed")

    def test_csv_is_byte_stable_and_parseable(self):
        rows = [wb._check("tail", "confirmed", "a, b"),
                wb._check("grouping", "skipped", "why")]
        data = wb.checks_csv(rows).encode("utf-8")
        self.assertNotIn(b"\r", data)
        self.assertTrue(data.endswith(b"\n"))
        parsed = list(csv.reader(io.StringIO(data.decode("utf-8"))))
        self.assertEqual(parsed[0], ["check", "status", "detail"])
        self.assertEqual(parsed[1], ["tail", "confirmed", "a, b"])

    def test_parse_lines_counts_malformed_and_rejects_non_objects(self):
        rows, malformed = wb.parse_lines([GOOD.splitlines()[0], "not json", "[]", GOOD.splitlines()[1]])
        self.assertEqual(len(rows), 2)
        self.assertEqual(malformed, 2)

    def test_cli_checks_emit_byte_stable_csv_on_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_text(GOOD, encoding="utf-8")
            r = run_cli("--input", src, "--checks", cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            self.assertTrue(r.stdout.endswith(b"\n"))
            parsed = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            self.assertEqual(parsed[0], ["check", "status", "detail"])
            self.assertEqual([row[1] for row in parsed[1:]], ["confirmed"] * 3)
            self.assertFalse((Path(d) / "wazuh_queue.json").exists())

    def test_cli_fail_closed_on_unreadable_input(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "checks.csv"
            r = run_cli("--input", Path(d) / "missing.jsonl", "--checks", "--out", out, cwd=d)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            data = out.read_bytes()
            self.assertNotIn(b"\r", data)
            rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
            self.assertEqual([row[1] for row in rows[1:]],
                             ["not_confirmed", "not_confirmed", "skipped"])

    def test_cli_default_json_report_keeps_full_result(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_text(GOOD, encoding="utf-8")
            out = Path(d) / "report.json"
            r = run_cli("--input", src, "--out", out, cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            self.assertEqual(r.stderr, b"")
            summary = json.loads(r.stdout)
            self.assertEqual((summary["alerts_read"], summary["groups"], summary["queued"]),
                             (2, 1, 1))
            report = json.loads(out.read_bytes())
            self.assertTrue(report["read_ok"])
            self.assertEqual([c["status"] for c in report["checks"]], ["confirmed"] * 3)


class WazuhFreshnessTests(unittest.TestCase):
    def test_parse_timestamp_handles_wazuh_offsets(self):
        self.assertIsNotNone(wb.parse_timestamp("2026-11-18T14:53:49.864-0600"))
        self.assertIsNotNone(wb.parse_timestamp("2026-11-18T14:53:49Z"))
        self.assertIsNotNone(wb.parse_timestamp("2026-11-18 14:53:49+0000"))
        for bad in ("", None, "not-a-date", 123):
            self.assertIsNone(wb.parse_timestamp(bad))

    def test_freshness_reports_age_and_breach(self):
        now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
        fresh = wb.freshness([{"timestamp": "2026-11-20T08:00:00+0000"}], 1, now)
        self.assertEqual(fresh["status"], "confirmed")
        self.assertFalse(fresh["breach"])
        self.assertEqual(fresh["age_days"], 0.1667)
        stale = wb.freshness([{"timestamp": "2026-11-01T08:00:00+0000"}], 1, now)
        self.assertEqual(stale["status"], "not_confirmed")
        self.assertTrue(stale["breach"])
        missing = wb.freshness([{"timestamp": "n/a"}], 1, now)
        self.assertEqual(missing["status"], "not_confirmed")
        self.assertTrue(missing["breach"])
        self.assertIsNone(missing["newest"])

    def test_positive_days_rejects_bad_values(self):
        for bad in ("0", "-1", "abc", "nan"):
            with self.assertRaises(argparse.ArgumentTypeError):
                wb._positive_days(bad)
        self.assertEqual(wb._positive_days("1.5"), 1.5)

    def test_cli_freshness_pass_exit0_and_breach_exit2(self):
        now = datetime.now().astimezone()
        fresh_ts = (now - timedelta(hours=1)).isoformat(timespec="seconds")
        stale_ts = (now - timedelta(days=40)).isoformat(timespec="seconds")
        with tempfile.TemporaryDirectory() as d:
            fresh = Path(d) / "fresh.jsonl"
            fresh.write_text(
                '{"timestamp":"%s","rule":{"level":3},"agent":{"name":"a"}}\n' % fresh_ts,
                encoding="utf-8")
            r = run_cli("--input", fresh, "--checks", "--max-age-days", "7", cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            parsed = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            self.assertEqual(parsed[-1][0], "freshness")
            self.assertEqual(parsed[-1][1], "confirmed")
            self.assertNotIn(b"\r", r.stdout)

            stale = Path(d) / "stale.jsonl"
            stale.write_text(
                '{"timestamp":"%s","rule":{"level":3},"agent":{"name":"a"}}\n' % stale_ts,
                encoding="utf-8")
            out = Path(d) / "checks.csv"
            r = run_cli("--input", stale, "--checks", "--max-age-days", "7",
                        "--out", out, cwd=d)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            parsed = list(csv.reader(io.StringIO(out.read_bytes().decode("utf-8"))))
            self.assertEqual(parsed[-1][0], "freshness")
            self.assertEqual(parsed[-1][1], "not_confirmed")

    def test_cli_unparseable_timestamp_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "bad.jsonl"
            src.write_text(
                '{"timestamp":"n/a","rule":{"level":3},"agent":{"name":"a"}}\n',
                encoding="utf-8")
            out = Path(d) / "report.json"
            r = run_cli("--input", src, "--out", out, "--max-age-days", "7", cwd=d)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            report = json.loads(out.read_bytes())
            self.assertEqual(report["freshness"]["status"], "not_confirmed")
            self.assertEqual([c["status"] for c in report["checks"]][-1], "not_confirmed")

    def test_default_json_report_has_no_freshness(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_text(GOOD, encoding="utf-8")
            out = Path(d) / "report.json"
            r = run_cli("--input", src, "--out", out, cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            report = json.loads(out.read_bytes())
            self.assertNotIn("freshness", report)
            self.assertEqual(len(report["checks"]), 3)


class WazuhBridgeSelftestTests(unittest.TestCase):
    BASE = SCRIPT.parent
    FIXTURE = BASE / "wazuh_alert_fixture.txt"
    EXPECT = BASE / "wazuh_expect.json"

    def _staged(self, tmp, with_fixture=True, with_expect=True, mutate=None):
        """Copy the script plus fixtures into a temp dir for real CLI probes."""
        script = Path(tmp) / "wazuh_bridge.py"
        script.write_bytes(SCRIPT.read_bytes())
        if with_fixture:
            (Path(tmp) / self.FIXTURE.name).write_bytes(self.FIXTURE.read_bytes())
        if with_expect:
            expectation = json.loads(self.EXPECT.read_text(encoding="utf-8"))
            if mutate:
                mutate(expectation)
            (Path(tmp) / self.EXPECT.name).write_text(
                json.dumps(expectation), encoding="utf-8")
        return script

    def test_selftest_status_vocabulary_is_closed(self):
        with self.assertRaises(ValueError):
            wb._selftest_check("x", "maybe")
        for status in wb.SELFTEST_STATUSES:
            self.assertEqual(wb._selftest_check("x", status)["status"], status)

    def test_committed_fixture_passes_with_independent_hash(self):
        st = wb.selftest(self.BASE)
        self.assertEqual(st["status"], "pass", st["checks"])
        self.assertEqual([c["status"] for c in st["checks"]],
                         ["pass"] * len(st["checks"]))
        self.assertNotIn("skipped", [c["status"] for c in st["checks"]])
        expected = __import__("hashlib").sha256(self.FIXTURE.read_bytes()).hexdigest()
        self.assertEqual(st["fixture_sha256"], expected)
        self.assertEqual(st["observed_counts"], {
            "lines_read": 5, "alerts_read": 4, "malformed": 1,
            "groups": 3, "queued": 2})

    def test_missing_fixture_is_error_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            st = wb.selftest(d)
            self.assertEqual(st["status"], "error")
            self.assertEqual(st["checks"][0]["check"], "fixture")
            self.assertEqual(st["checks"][0]["status"], "error")

    def test_unreadable_expectation_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / self.FIXTURE.name).write_bytes(self.FIXTURE.read_bytes())
            (Path(d) / self.EXPECT.name).write_text("{not json", encoding="utf-8")
            st = wb.selftest(d)
            self.assertEqual(st["status"], "error")
            self.assertEqual(st["checks"][-1]["check"], "expectation")
            self.assertEqual(st["checks"][-1]["status"], "error")

    def test_wrong_expectation_is_fail(self):
        with tempfile.TemporaryDirectory() as d:
            script = self._staged(d, mutate=lambda e: e.__setitem__("alerts_read", 99))
            r = subprocess.run([sys.executable, str(script), "--selftest"],
                               cwd=d, capture_output=True)
            self.assertEqual(r.returncode, 1)
            st = json.loads(r.stdout.decode("utf-8"))
            self.assertEqual(st["status"], "fail")
            self.assertIn("counts", [c["check"] for c in st["checks"]])

    def test_cli_selftest_is_byte_stable_exit0_and_short_circuits(self):
        with tempfile.TemporaryDirectory() as d:
            script = self._staged(d)
            r = subprocess.run([sys.executable, str(script), "--selftest"],
                               cwd=d, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            st = json.loads(r.stdout.decode("utf-8"))
            self.assertEqual(st["mode"], "selftest")
            self.assertEqual(st["status"], "pass")
            self.assertTrue(r.stdout.endswith(b"\n"))
            # --selftest wins and writes nothing to the default report path.
            self.assertFalse((Path(d) / "wazuh_queue.json").exists())
            # No other flags required: --selftest alone succeeds.
            r2 = subprocess.run([sys.executable, str(script), "--selftest"],
                                cwd=d, capture_output=True)
            self.assertEqual(r2.stdout, r.stdout)

    def test_cli_selftest_missing_fixture_is_exit2(self):
        with tempfile.TemporaryDirectory() as d:
            script = self._staged(d, with_fixture=False)
            r = subprocess.run([sys.executable, str(script), "--selftest"],
                               cwd=d, capture_output=True)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            st = json.loads(r.stdout.decode("utf-8"))
            self.assertEqual(st["status"], "error")

    def test_default_run_has_no_selftest_fields(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_text(GOOD, encoding="utf-8")
            out = Path(d) / "report.json"
            r = run_cli("--input", src, "--out", out, cwd=d)
            self.assertEqual(r.returncode, 0)
            report = json.loads(out.read_bytes())
            self.assertNotIn("mode", report)
            self.assertNotIn("observed_counts", report)


if __name__ == "__main__":
    unittest.main()
