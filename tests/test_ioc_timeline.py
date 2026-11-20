import contextlib
import csv
import hashlib
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


class IocSourceManifestTests(unittest.TestCase):
    FIXTURE = "8.8.8.8 example.com\n8.8.8.8\n\n"

    def test_manifest_fields_and_hash(self):
        data = self.FIXTURE.encode("utf-8")
        m = ioc.source_manifest("capture.txt", data)
        self.assertEqual(m["name"], "capture.txt")
        self.assertEqual(m["bytes"], len(data))
        self.assertEqual(m["lines"], 2)
        self.assertEqual(m["sha256"], hashlib.sha256(data).hexdigest())

    def test_blank_lines_excluded_and_single_read_reused(self):
        data = b'8.8.8.8\n\n   \n'
        m = ioc.source_manifest("capture.txt", data)
        self.assertEqual(m["lines"], 1)
        self.assertEqual(m["bytes"], len(data))

    def test_cli_emits_manifest_matching_actual_file_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "capture.txt"
            src.write_bytes(self.FIXTURE.encode("utf-8"))
            before = src.read_bytes()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = ioc.main([str(src)])
            out = buf.getvalue()
            doc = json.loads(out)
            self.assertEqual(code, 1)
            self.assertEqual(out.count("\r"), 0)
            entry = doc["source_files"][0]
            self.assertEqual(entry["name"], "capture.txt")
            self.assertEqual(entry["bytes"], len(before))
            self.assertEqual(entry["lines"], 2)
            self.assertEqual(entry["sha256"], hashlib.sha256(before).hexdigest())
            self.assertEqual(src.read_bytes(), before)  # source is never modified

    def test_prioritize_output_unchanged_by_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "capture.txt"
            src.write_bytes(self.FIXTURE.encode("utf-8"))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = ioc.main([str(src), "--prioritize"])
            self.assertEqual(code, 1)
            rows = list(csv.reader(io.StringIO(buf.getvalue())))
            self.assertEqual(rows[0], ["type", "value", "line"])
            self.assertFalse(any("sha256" in r for r in rows))  # no provenance rows

    def test_input_error_has_no_manifest(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ioc.main(["does-not-exist.txt"])
        doc = json.loads(buf.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(doc["status"], "incomplete")
        self.assertNotIn("source_files", doc)


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


class TimelineSourceManifestTests(unittest.TestCase):
    FIXTURE = (
        '{"timestamp": "2026-01-01T08:00:00", "source": "a"}\n'
        '{"timestamp": "2026-01-01T08:00:30", "source": "a"}\n'
    )

    def test_manifest_fields_and_hash(self):
        data = self.FIXTURE.encode("utf-8")
        m = tl.source_manifest("alerts.jsonl", data)
        self.assertEqual(m["name"], "alerts.jsonl")
        self.assertEqual(m["bytes"], len(data))
        self.assertEqual(m["lines"], 2)
        self.assertEqual(m["sha256"], hashlib.sha256(data).hexdigest())

    def test_blank_lines_excluded_and_single_read_reused(self):
        data = b'{"timestamp": "2026-01-01T08:00:00"}\n\n   \n'
        m = tl.source_manifest("x.jsonl", data)
        self.assertEqual(m["lines"], 1)

    def test_cli_emits_manifest_matching_actual_file_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_bytes(self.FIXTURE.encode("utf-8"))
            before = src.read_bytes()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = tl.main([str(src)])
            doc = json.loads(buf.getvalue())
            self.assertEqual(code, 0)
            entry = doc["source_files"][0]
            self.assertEqual(entry["name"], "alerts.jsonl")
            self.assertEqual(entry["bytes"], len(before))
            self.assertEqual(entry["sha256"], hashlib.sha256(before).hexdigest())
            self.assertEqual(src.read_bytes(), before)  # source is never modified

    def test_prioritize_output_unchanged_by_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_bytes(self.FIXTURE.encode("utf-8"))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = tl.main([str(src), "--prioritize"])
            self.assertEqual(code, 0)
            rows = list(csv.reader(io.StringIO(buf.getvalue())))
            self.assertEqual(rows[0], ["session", "source", "event_count", "long_dwell"])
            self.assertEqual(len(rows), 2)  # header + one session, no provenance rows


class IocChecksTests(unittest.TestCase):
    FIXTURE = "8.8.8.8 example.com\n"

    def test_closed_vocabulary_and_fixed_order(self):
        result = ioc.scan(self.FIXTURE)
        result["source_files"] = [
            ioc.source_manifest("capture.txt", self.FIXTURE.encode("utf-8"))]
        rows = ioc.checks(result)
        self.assertEqual([r["check"] for r in rows],
                         ["parse", "completeness", "provenance"])
        for row in rows:
            self.assertIn(row["status"], ioc.CHECK_STATUSES)
        self.assertEqual(rows[1]["status"], "skipped")
        self.assertEqual(rows[1]["detail"], "no claimed total")
        self.assertEqual(rows[0]["detail"], "2 observables")

    def test_csv_column_contract_and_deterministic_bytes(self):
        result = ioc.scan(self.FIXTURE)
        result["source_files"] = [
            ioc.source_manifest("capture.txt", self.FIXTURE.encode("utf-8"))]
        text = ioc.checks_csv(ioc.checks(result))
        self.assertTrue(text.startswith("check,status,detail\n"))
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, ioc.checks_csv(ioc.checks(result)))

    def test_cli_checks_exit_parse_and_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "capture.txt"
            src.write_text(self.FIXTURE, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = ioc.main([str(src), "--checks"])
            raw = buf.getvalue()
            self.assertEqual(code, 1)
            self.assertNotIn("\r", raw)
            rows = list(csv.reader(io.StringIO(raw)))
            self.assertEqual(rows[0], ["check", "status", "detail"])
            by_check = {r[0]: r for r in rows[1:]}
            self.assertEqual(by_check["parse"][1], "confirmed")
            self.assertEqual(by_check["parse"][2], "2 observables")
            self.assertEqual(by_check["completeness"][1], "skipped")
            self.assertEqual(by_check["completeness"][2], "no claimed total")
            self.assertEqual(by_check["provenance"][1], "confirmed")
            self.assertEqual(by_check["provenance"][2],
                             hashlib.sha256(src.read_bytes()).hexdigest())

    def test_short_parse_marks_completeness_not_confirmed(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "capture.txt"
            src.write_text(self.FIXTURE, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = ioc.main([str(src), "--checks", "--expect", "9"])
            self.assertEqual(code, 2)
            rows = list(csv.reader(io.StringIO(buf.getvalue())))
            by_check = {r[0]: r for r in rows[1:]}
            self.assertEqual(by_check["parse"][1], "confirmed")
            self.assertEqual(by_check["completeness"][1], "not_confirmed")
            self.assertEqual(by_check["completeness"][2], "parsed 2 of 9")

    def test_input_error_has_no_confirmed_checks(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ioc.main(["does-not-exist.txt", "--checks"])
        self.assertEqual(code, 2)
        rows = list(csv.reader(io.StringIO(buf.getvalue())))
        self.assertEqual(rows[0], ["check", "status", "detail"])
        by_check = {r[0]: r for r in rows[1:]}
        self.assertEqual(by_check["parse"][1], "not_confirmed")
        self.assertEqual(by_check["provenance"][1], "skipped")
        self.assertEqual(by_check["provenance"][2], "no readable input")


class TimelineChecksTests(unittest.TestCase):
    FIXTURE = (
        '{"timestamp": "2026-01-01T08:00:00", "source": "clean"}\n'
        '{"timestamp": "2026-01-01T08:00:30", "source": "clean"}\n'
        '{"timestamp": "2026-01-01T10:00:00", "source": "long"}\n'
        '{"timestamp": "2026-01-01T12:00:00", "source": "long"}\n'
    )

    def test_closed_vocabulary_and_fixed_order(self):
        result = tl.sessions(
            [json.loads(line) for line in self.FIXTURE.splitlines()], 9000, 3600)
        result["source_files"] = [
            tl.source_manifest("alerts.jsonl", self.FIXTURE.encode("utf-8"))]
        rows = tl.checks(result)
        self.assertEqual([r["check"] for r in rows], ["parse", "dwell", "provenance"])
        for row in rows:
            self.assertIn(row["status"], tl.CHECK_STATUSES)
            self.assertEqual(set(row), {"check", "status", "detail"})

    def test_confirmed_zero_dwell_is_not_a_no_risk_claim(self):
        result = tl.sessions([], 900, 3600)
        result["source_files"] = [
            tl.source_manifest("alerts.jsonl", self.FIXTURE.encode("utf-8"))]
        dwell = tl.checks(result)[1]
        self.assertEqual(dwell["status"], "confirmed")
        self.assertEqual(dwell["detail"], "0 long dwell(s)")

    def test_unreadable_result_marks_parse_not_confirmed(self):
        rows = tl.checks({})
        by_check = {r["check"]: r for r in rows}
        self.assertEqual(by_check["parse"]["status"], "not_confirmed")
        self.assertEqual(by_check["provenance"]["status"], "skipped")
        self.assertEqual(by_check["provenance"]["detail"], "no readable input")

    def test_csv_column_contract_and_deterministic_bytes(self):
        result = tl.sessions(
            [json.loads(line) for line in self.FIXTURE.splitlines()], 9000, 3600)
        result["source_files"] = [
            tl.source_manifest("alerts.jsonl", self.FIXTURE.encode("utf-8"))]
        text = tl.checks_csv(tl.checks(result))
        self.assertTrue(text.startswith("check,status,detail\n"))
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, tl.checks_csv(tl.checks(result)))

    def test_cli_checks_exit_parse_and_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "alerts.jsonl"
            src.write_text(self.FIXTURE, encoding="utf-8")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = tl.main([str(src), "--gap", "9000", "--checks"])
            raw = buf.getvalue()
            self.assertEqual(code, 1)
            self.assertNotIn("\r", raw)
            rows = list(csv.reader(io.StringIO(raw)))
            self.assertEqual(rows[0], ["check", "status", "detail"])
            by_check = {r[0]: r for r in rows[1:]}
            self.assertEqual(by_check["parse"][1], "confirmed")
            self.assertEqual(by_check["parse"][2], "2 sessions")
            self.assertEqual(by_check["dwell"][1], "confirmed")
            self.assertEqual(by_check["dwell"][2], "1 long dwell(s)")
            self.assertEqual(by_check["provenance"][1], "confirmed")
            self.assertEqual(by_check["provenance"][2],
                             hashlib.sha256(src.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
