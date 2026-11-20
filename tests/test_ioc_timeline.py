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
import iocscan as ioc
import timeline as tl


class IocTests(unittest.TestCase):
    def test_private_suppressed_and_public_deduped(self):
        text = "10.0.0.5 8.8.8.8\n8.8.8.8 example.com\n"
        r = ioc.scan(text)
        values = [f["value"] for f in r["findings"]]
        self.assertNotIn("10.0.0.5", values)
        pub = [f for f in r["findings"] if f["value"] == "8.8.8.8"][0]
        self.assertEqual(pub["lines"], [1, 2])

    def test_hashes_are_typed(self):
        r = ioc.scan("a" * 64 + "\n")
        self.assertEqual(r["findings"][0]["type"], "sha256")

    def test_short_parse_is_incomplete(self):
        r = ioc.scan("8.8.8.8 example.com\n", expected=5)
        self.assertEqual(r["status"], "incomplete")
        self.assertEqual(r["expected"], 5)
        self.assertEqual(r["raw_matches"], 2)
        self.assertIn("truncated", r["reason"])

    def test_met_or_exceeded_expectation_is_complete(self):
        text = "8.8.8.8 example.com\n"
        self.assertEqual(ioc.scan(text, expected=2)["status"], "complete")
        self.assertEqual(ioc.scan(text, expected=1)["status"], "complete")

    def test_private_and_dupes_still_count_as_raw_matches(self):
        r = ioc.scan("10.0.0.5 8.8.8.8 8.8.8.8\n", expected=3)
        self.assertEqual(r["status"], "complete")
        self.assertEqual(r["raw_matches"], 3)
        self.assertEqual(r["count"], 1)

    def test_cli_exit_codes_for_clean_dirty_and_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            dirty = Path(d) / "dirty.txt"
            dirty.write_text("8.8.8.8 example.com\n", encoding="utf-8")
            clean = Path(d) / "clean.txt"
            clean.write_text("10.0.0.1\n", encoding="utf-8")

            def run(path, *extra):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = ioc.main([str(path), *extra])
                return code, json.loads(buf.getvalue())

            self.assertEqual(run(dirty)[0], 1)
            self.assertEqual(run(clean)[0], 0)
            code, doc = run(dirty, "--expect", "9")
            self.assertEqual(code, 2)
            self.assertEqual(doc["status"], "incomplete")
            code, doc = run(dirty, "--expect", "2")
            self.assertEqual((code, doc["status"]), (1, "complete"))
            code, doc = run(dirty, "--expect", "-1")
            self.assertEqual((code, doc["status"]), (2, "incomplete"))
            code, doc = run(Path(d) / "missing.txt")
            self.assertEqual((code, doc["status"]), (2, "incomplete"))


class IocPrioritizeCsvTests(unittest.TestCase):
    def test_column_contract_and_deterministic_bytes(self):
        findings = ioc.scan("8.8.8.8 example.com\n8.8.8.8\n")["findings"]
        csv_text = ioc.prioritize_csv(findings)
        self.assertTrue(csv_text.startswith("type,value,line\n"))
        self.assertNotIn("\r", csv_text)
        self.assertTrue(csv_text.endswith("\n"))
        # Same findings always render identical bytes.
        self.assertEqual(csv_text, ioc.prioritize_csv(findings))

    def test_one_row_per_line_occurrence_in_sorted_order(self):
        findings = ioc.scan("8.8.8.8 example.com\n8.8.8.8\n")["findings"]
        rows = list(csv.reader(io.StringIO(ioc.prioritize_csv(findings))))
        self.assertEqual(rows[0], ["type", "value", "line"])
        # domain < ipv4 lexically, so the domain row comes first; 8.8.8.8
        # appears once per source line after dedup.
        self.assertEqual(rows[1], ["domain", "example.com", "1"])
        self.assertEqual(rows[2], ["ipv4", "8.8.8.8", "1"])
        self.assertEqual(rows[3], ["ipv4", "8.8.8.8", "2"])

    def test_cli_prioritize_exit_codes_and_parse(self):
        with tempfile.TemporaryDirectory() as d:
            dirty = Path(d) / "dirty.txt"
            dirty.write_text("8.8.8.8 example.com\n", encoding="utf-8")
            clean = Path(d) / "clean.txt"
            clean.write_text("10.0.0.1\n", encoding="utf-8")

            def run(path, *extra):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = ioc.main([str(path), "--prioritize", *extra])
                return code, list(csv.reader(io.StringIO(buf.getvalue())))

            code, rows = run(dirty)
            self.assertEqual(code, 1)
            self.assertEqual(rows[0], ["type", "value", "line"])
            self.assertEqual(len(rows), 3)  # header + domain + ipv4
            code, rows = run(clean)
            self.assertEqual((code, len(rows)), (0, 1))  # header only
            # An incomplete parse still emits CSV and keeps the fail-closed exit.
            code, rows = run(dirty, "--expect", "9")
            self.assertEqual(code, 2)
            self.assertEqual(rows[0], ["type", "value", "line"])

    def test_out_writes_same_bytes_as_stdout(self):
        text = "8.8.8.8 example.com\n8.8.8.8\n"
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.txt"
            src.write_text(text, encoding="utf-8")
            out = Path(d) / "triage.csv"
            with contextlib.redirect_stdout(io.StringIO()):
                ioc.main([str(src), "--prioritize", "--out", str(out)])
            self.assertEqual(out.read_bytes(),
                             ioc.prioritize_csv(ioc.scan(text)["findings"]).encode("utf-8"))


class TimelineTests(unittest.TestCase):
    def test_gap_splits_sessions(self):
        rows = [
            {"timestamp": "2026-01-01T10:00:00", "source": "a"},
            {"timestamp": "2026-01-01T10:01:00", "source": "a"},
            {"timestamp": "2026-01-01T12:00:00", "source": "b"},
        ]
        r = tl.sessions(rows, gap_seconds=900, max_span_seconds=3600)
        self.assertEqual(r["sessions"], 2)
        self.assertEqual(r["groups"][0]["events"], 2)

    def test_long_dwell_flagged(self):
        rows = [
            {"timestamp": "2026-01-01T10:00:00", "source": "a"},
            {"timestamp": "2026-01-01T12:00:00", "source": "a"},
        ]
        r = tl.sessions(rows, gap_seconds=9000, max_span_seconds=3600)
        self.assertTrue(r["groups"][0]["long_dwell"])


class TimelinePrioritizeCsvTests(unittest.TestCase):
    FIXTURE = (
        '{"timestamp": "2026-01-01T08:00:00", "source": "clean"}\n'
        '{"timestamp": "2026-01-01T08:00:30", "source": "clean"}\n'
        '{"timestamp": "2026-01-01T10:00:00", "source": "long"}\n'
        '{"timestamp": "2026-01-01T12:00:00", "source": "long"}\n'
    )

    def test_column_contract_and_deterministic_bytes(self):
        result = tl.sessions(
            [json.loads(line) for line in self.FIXTURE.splitlines()],
            gap_seconds=9000, max_span_seconds=3600)
        csv_text = tl.prioritize_csv(result)
        self.assertTrue(csv_text.startswith("session,source,event_count,long_dwell\n"))
        self.assertNotIn("\r", csv_text)
        self.assertTrue(csv_text.endswith("\n"))
        self.assertEqual(csv_text, tl.prioritize_csv(result))

    def test_one_row_per_session_in_chronological_order(self):
        result = tl.sessions(
            [json.loads(line) for line in self.FIXTURE.splitlines()],
            gap_seconds=9000, max_span_seconds=3600)
        rows = list(csv.reader(io.StringIO(tl.prioritize_csv(result))))
        self.assertEqual(rows[0], ["session", "source", "event_count", "long_dwell"])
        self.assertEqual(rows[1], ["1", "clean", "2", "false"])
        self.assertEqual(rows[2], ["2", "long", "2", "true"])

    def test_empty_result_emits_header_only(self):
        rows = list(csv.reader(io.StringIO(tl.prioritize_csv(tl.sessions([], 900, 3600)))))
        self.assertEqual(rows, [["session", "source", "event_count", "long_dwell"]])

    def test_cli_prioritize_exit_codes_and_parse(self):
        with tempfile.TemporaryDirectory() as d:
            mixed = Path(d) / "mixed.jsonl"
            mixed.write_text(self.FIXTURE, encoding="utf-8")
            clean = Path(d) / "clean.jsonl"
            clean.write_text(
                '{"timestamp": "2026-01-01T08:00:00", "source": "clean"}\n'
                '{"timestamp": "2026-01-01T08:00:30", "source": "clean"}\n',
                encoding="utf-8")

            def run(path, *extra):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = tl.main([str(path), "--gap", "9000", "--prioritize", *extra])
                return code, buf.getvalue(), list(csv.reader(io.StringIO(buf.getvalue())))

            code, raw, rows = run(mixed)
            self.assertEqual(code, 1)  # long dwell denies, as in the JSON path
            self.assertNotIn("\r", raw)
            self.assertEqual(rows[0], ["session", "source", "event_count", "long_dwell"])
            self.assertEqual(rows[2], ["2", "long", "2", "true"])
            code, raw, rows = run(clean)
            self.assertEqual(code, 0)
            self.assertEqual(rows[1][3], "false")

    def test_out_writes_same_bytes_as_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.jsonl"
            src.write_text(self.FIXTURE, encoding="utf-8")
            out = Path(d) / "sessions.csv"
            with contextlib.redirect_stdout(io.StringIO()):
                tl.main([str(src), "--gap", "9000", "--prioritize", "--out", str(out)])
            result = tl.sessions(
                [json.loads(line) for line in self.FIXTURE.splitlines()],
                gap_seconds=9000, max_span_seconds=3600)
            self.assertEqual(out.read_bytes(), tl.prioritize_csv(result).encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
