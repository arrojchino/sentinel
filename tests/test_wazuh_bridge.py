import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
