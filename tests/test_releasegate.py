import csv
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import releasegate as g


class GateTests(unittest.TestCase):
    def test_critical_denies(self):
        r = g.decide([{"severity": "critical"}], g.DEFAULTS)
        self.assertEqual(r["verdict"], "deny")
        self.assertTrue(any("critical" in x for x in r["reasons"]))

    def test_within_limits_allows(self):
        rows = [{"severity": "high"}, {"severity": "low"}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(r["total"], 2)

    def test_unreadable_evidence_is_indeterminate_not_allow(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text("not json", encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertTrue(out["reasons"][0].startswith("input error:"))
            self.assertEqual(r.stderr, "")

    def test_decision_states_the_limits_it_applied(self):
        r = g.decide([], g.DEFAULTS)
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(r["limits"], g.DEFAULTS)

    def test_envelope_shape_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps({"findings": [{"severity": "critical"}]}), encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["verdict"], "deny")


    def test_unrecognized_severity_is_indeterminate(self):
        rows = [{"severity": "critical"}, {"severity": "mystery"}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertIn("mystery", r["reasons"][0])
        self.assertEqual(r["counts"]["mystery"], 1)
        self.assertEqual(r["total"], 2)

    def test_missing_severity_is_indeterminate(self):
        r = g.decide([{"title": "no severity field"}], g.DEFAULTS)
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertIn("unspecified", r["reasons"][0])

    def test_known_severities_still_score(self):
        rows = [{"severity": "medium"}, {"severity": "low"}, {"severity": "Info"}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(r["total"], 3)

    def test_unrecognized_severity_cli_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "medium"}, {"severity": "weird"}]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertIn("weird", out["reasons"][0])
            self.assertEqual(r.stderr, "")


    def test_custom_severity_is_scored_not_indeterminate(self):
        smap = g.build_severity_map({"blocker": "critical"})
        r = g.decide([{"severity": "blocker"}], g.DEFAULTS, smap)
        self.assertEqual(r["verdict"], "deny")
        self.assertIn("critical=1", r["reasons"][0])
        self.assertEqual(r["counts"]["blocker"], 1)
        self.assertEqual(r["buckets"]["critical"], 1)

    def test_custom_severity_still_counts_toward_total(self):
        smap = g.build_severity_map({"Low": "low", "blocker": "critical"})
        rows = [{"severity": "BLOCKER"}, {"severity": "low"}, {"severity": "critical"}]
        r = g.decide(rows, g.DEFAULTS, smap)
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(r["total"], 3)
        self.assertEqual(r["buckets"]["critical"], 2)

    def test_name_not_in_custom_map_is_indeterminate(self):
        smap = g.build_severity_map({"blocker": "critical"})
        r = g.decide([{"severity": "blocker"}, {"severity": "mystery"}],
                     g.DEFAULTS, smap)
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertIn("mystery", r["reasons"][0])

    def test_bad_custom_bucket_is_rejected(self):
        with self.assertRaises(ValueError):
            g.build_severity_map({"blocker": "critcal"})

    def test_custom_severity_cli_denies(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "blocker"}]), encoding="utf-8")
            rules = Path(d) / "rules.json"
            rules.write_text(json.dumps({"severities": {"blocker": "critical"}}),
                             encoding="utf-8")
            r = subprocess.run(
                [sys.executable, str(Path(g.__file__).resolve()), str(f),
                 "--rules", str(rules)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "deny")
            self.assertEqual(out["buckets"]["critical"], 1)
            self.assertEqual(r.stderr, "")

    def test_bad_custom_bucket_cli_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "blocker"}]), encoding="utf-8")
            rules = Path(d) / "rules.json"
            rules.write_text(json.dumps({"severities": {"blocker": "oops"}}),
                             encoding="utf-8")
            r = subprocess.run(
                [sys.executable, str(Path(g.__file__).resolve()), str(f),
                 "--rules", str(rules)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertTrue(out["reasons"][0].startswith("input error:"))
            self.assertEqual(r.stderr, "")

    def test_parsed_fewer_than_claimed_is_indeterminate(self):
        rows = [{"severity": "low"}, {"severity": "low"}]
        r = g.decide(rows, g.DEFAULTS, claimed_total=5)
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertIn("parsed 2 of claimed 5", r["reasons"][0])
        self.assertEqual(r["total"], 2)
        self.assertEqual(sum(r["counts"].values()), 2)

    def test_parsed_claimed_count_scores_normally(self):
        rows = [{"severity": "low"}, {"severity": "low"}]
        r = g.decide(rows, g.DEFAULTS, claimed_total=2)
        self.assertEqual(r["verdict"], "allow")

    def test_parsed_more_than_claimed_is_not_incomplete(self):
        rows = [{"severity": "low"}, {"severity": "low"}]
        r = g.decide(rows, g.DEFAULTS, claimed_total=1)
        self.assertEqual(r["verdict"], "allow")

    def test_short_parse_cli_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            env = {"reported_total": 4, "findings": [{"severity": "low"}]}
            f.write_text(json.dumps(env), encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertIn("parsed 1 of claimed 4", out["reasons"][0])
            self.assertEqual(r.stderr, "")

    def test_bad_reported_total_is_input_error(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps({"reported_total": "five", "findings": []}),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertTrue(out["reasons"][0].startswith("input error:"))

    def test_cvss_upgrades_low_to_critical_and_denies(self):
        rows = [{"severity": "low", "cvss_score": 9.8}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(r["buckets"]["low"], 1)
        self.assertEqual(r["effective_buckets"]["critical"], 1)
        self.assertEqual(r["upgrades"][0]["to"], "critical")
        self.assertEqual(r["upgrades"][0]["cvss"], 9.8)
        self.assertIn("critical=1", r["reasons"][0])

    def test_cvss_never_downgrades_declared_severity(self):
        rows = [{"severity": "critical", "cvss": 2.0}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(r["effective_buckets"]["critical"], 1)
        self.assertEqual(r["upgrades"], [])

    def test_cvss_band_boundaries(self):
        expected = {0.0: "info", 3.9: "low", 4.0: "medium", 6.9: "medium",
                    7.0: "high", 8.9: "high", 9.0: "critical", 10.0: "critical"}
        for score, band in expected.items():
            with self.subTest(score=score):
                self.assertEqual(g.band_for_score(score), band)

    def test_no_cvss_effective_matches_declared(self):
        rows = [{"severity": "medium"}, {"severity": "low"}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual(r["effective_buckets"], r["buckets"])
        self.assertEqual(r["upgrades"], [])

    def test_invalid_cvss_is_indeterminate(self):
        r = g.decide([{"severity": "low", "cvss_score": "high"}], g.DEFAULTS)
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertIn("cvss", r["reasons"][0])
        self.assertTrue(r["reasons"][0].startswith("input error:"))

    def test_cvss_out_of_range_is_indeterminate(self):
        for score in (-1.0, 10.1, True):
            with self.subTest(score=score):
                r = g.decide([{"severity": "low", "cvss": score}], g.DEFAULTS)
                self.assertEqual(r["verdict"], "indeterminate")

    def test_cvss_upgrade_cli_denies(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low", "cvss_score": 9.1}]),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            out = json.loads(r.stdout)
            self.assertEqual(out["effective_buckets"]["critical"], 1)
            self.assertEqual(r.stderr, "")

    def test_invalid_cvss_cli_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low", "cvss_score": "n/a"}]),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(r.stdout)["verdict"], "indeterminate")
            self.assertEqual(r.stderr, "")


class PrioritizedTests(unittest.TestCase):
    def test_leads_with_highest_effective_severity(self):
        rows = [{"severity": "low"}, {"severity": "high"}, {"severity": "critical"}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual([e["bucket"] for e in r["prioritized"]],
                         ["critical", "high", "low"])
        self.assertEqual(r["prioritized"][0]["severity"], "critical")
        self.assertEqual(r["prioritized"][0]["index"], 2)

    def test_cvss_upgrade_leads_the_list(self):
        rows = [{"severity": "high"}, {"severity": "low", "cvss": 9.8}]
        r = g.decide(rows, g.DEFAULTS)
        first = r["prioritized"][0]
        self.assertEqual(first["bucket"], "critical")
        self.assertEqual(first["severity"], "low")
        self.assertEqual(first["cvss"], 9.8)
        self.assertEqual(first["index"], 1)

    def test_tie_break_by_cvss_then_input_position(self):
        rows = [{"severity": "critical", "cvss": 9.0},
                {"severity": "critical", "cvss": 9.9},
                {"severity": "critical", "cvss": 9.9}]
        r = g.decide(rows, g.DEFAULTS)
        self.assertEqual([e["index"] for e in r["prioritized"]], [1, 2, 0])

    def test_indeterminate_has_empty_prioritized(self):
        r = g.decide([{"severity": "low"}, {"severity": "mystery"}], g.DEFAULTS)
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertEqual(r["prioritized"], [])

    def test_cli_prioritized_leads_with_critical(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low"}, {"severity": "critical"}]),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            out = json.loads(r.stdout)
            self.assertEqual(out["prioritized"][0]["severity"], "critical")
            self.assertEqual(r.stderr, "")


class TriageCsvTests(unittest.TestCase):
    def test_header_and_priority_order(self):
        csv_text = g.prioritize_csv(g.decide(
            [{"severity": "low"}, {"severity": "high"},
             {"severity": "low", "cvss": 9.8}], g.DEFAULTS)["prioritized"])
        rows = list(csv.reader(io.StringIO(csv_text)))
        self.assertEqual(rows[0], ["index", "severity", "declared_bucket",
                                   "bucket", "cvss"])
        self.assertEqual(rows[1], ["2", "low", "low", "critical", "9.8"])
        self.assertEqual(rows[2], ["1", "high", "high", "high", ""])
        self.assertEqual(rows[3], ["0", "low", "low", "low", ""])

    def test_bytes_are_lf_only_with_trailing_newline(self):
        data = g.prioritize_csv(g.decide([{"severity": "low"}],
                                         g.DEFAULTS)["prioritized"]).encode("utf-8")
        self.assertNotIn(b"\r", data)
        self.assertTrue(data.endswith(b"\n"))

    def test_indeterminate_emits_header_only_and_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "mystery"}]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--prioritize"], capture_output=True)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            rows = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "index")

    def test_out_writes_identical_bytes_to_stdout_version(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low", "cvss": 4.0}]),
                         encoding="utf-8")
            out = Path(d) / "triage.csv"
            base = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                   str(f), "--prioritize"], capture_output=True)
            written = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                      str(f), "--prioritize", "--out", str(out)],
                                     capture_output=True)
            self.assertEqual(written.returncode, base.returncode)
            self.assertEqual(written.stdout, b"")
            self.assertEqual(out.read_bytes(), base.stdout)


class SourceProvenanceTests(unittest.TestCase):
    def test_manifest_shape_and_independent_hash(self):
        raw = b'{"findings": []}\n'
        m = g.source_manifest("findings.json", raw)
        self.assertEqual(set(m), {"name", "bytes", "lines", "sha256"})
        self.assertEqual(m["name"], "findings.json")
        self.assertEqual(m["bytes"], len(raw))
        self.assertEqual(m["lines"], 1)
        self.assertEqual(m["sha256"], hashlib.sha256(raw).hexdigest())

    def test_cli_report_carries_matching_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            raw = json.dumps([{"severity": "critical"}]).encode("utf-8")
            f.write_bytes(raw)
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f)], capture_output=True)
            self.assertEqual(r.returncode, 1)
            out = json.loads(r.stdout)
            sf = out["source_files"]
            self.assertEqual(len(sf), 1)
            self.assertEqual(sf[0]["name"], "findings.json")
            self.assertEqual(sf[0]["bytes"], len(raw))
            self.assertEqual(sf[0]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)

    def test_unreadable_file_has_no_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(Path(d) / "missing.json")], capture_output=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertNotIn("source_files", out)

    def test_source_bytes_are_not_modified(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            raw = b'[{"severity": "low"}]'
            f.write_bytes(raw)
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f)], capture_output=True)
            self.assertEqual(r.returncode, 0)
            self.assertEqual(f.read_bytes(), raw)
            self.assertEqual(json.loads(r.stdout)["source_files"][0]["sha256"],
                             hashlib.sha256(raw).hexdigest())

    def test_prioritize_output_unchanged_by_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "critical"}]).encode("utf-8"))
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--prioritize"], capture_output=True)
            self.assertEqual(r.returncode, 1)
            rows = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0], ["index", "severity", "declared_bucket",
                                       "bucket", "cvss"])
            self.assertNotIn(b"source_files", r.stdout)


class ConfirmationWorksheetTests(unittest.TestCase):
    def test_vocabulary_is_closed_and_order_fixed(self):
        r = g.decide([{"severity": "low"}], g.DEFAULTS)
        self.assertEqual([c["check"] for c in r["checks"]], list(g.CHECK_NAMES))
        self.assertTrue(all(c["status"] in g.CHECK_STATUSES for c in r["checks"]))

    def test_clean_decision_confirms_evaluated_checks(self):
        r = g.decide([{"severity": "low"}], g.DEFAULTS)
        by = {c["check"]: c for c in r["checks"]}
        self.assertEqual(by["parse"]["status"], "confirmed")
        self.assertEqual(by["completeness"]["status"], "skipped")
        self.assertEqual(by["cvss_validity"]["status"], "skipped")
        self.assertEqual(by["max_total"]["status"], "confirmed")
        self.assertIn("total=1", by["max_total"]["detail"])

    def test_worksheet_has_documented_columns_and_fixed_rows(self):
        rows = list(csv.reader(io.StringIO(
            g.checks_csv(g.decide([{"severity": "low"}], g.DEFAULTS)["checks"]))))
        self.assertEqual(rows[0], ["check", "status", "detail"])
        self.assertEqual(len(rows), 1 + len(g.CHECK_NAMES))

    def test_incomplete_marks_completeness_not_confirmed(self):
        r = g.decide([{"severity": "low"}], g.DEFAULTS, claimed_total=4)
        by = {c["check"]: c for c in r["checks"]}
        self.assertEqual(r["verdict"], "indeterminate")
        self.assertEqual(by["completeness"]["status"], "not_confirmed")
        self.assertEqual(by["max_total"]["status"], "skipped")

    def test_unrecognized_severity_marks_vocabulary_not_confirmed(self):
        r = g.decide([{"severity": "mystery"}], g.DEFAULTS)
        by = {c["check"]: c for c in r["checks"]}
        self.assertEqual(by["severity_vocabulary"]["status"], "not_confirmed")
        self.assertEqual(by["severity_vocabulary"]["detail"], "mystery")

    def test_invalid_cvss_marks_cvss_not_confirmed(self):
        r = g.decide([{"severity": "low", "cvss": "n/a"}], g.DEFAULTS)
        by = {c["check"]: c for c in r["checks"]}
        self.assertEqual(by["cvss_validity"]["status"], "not_confirmed")

    def test_cvss_upgrade_marks_cvss_confirmed(self):
        r = g.decide([{"severity": "low", "cvss": 9.8}], g.DEFAULTS)
        by = {c["check"]: c for c in r["checks"]}
        self.assertEqual(by["cvss_validity"]["status"], "confirmed")
        self.assertIn("1 upgrades", by["cvss_validity"]["detail"])

    def test_deny_still_confirms_threshold_checks(self):
        r = g.decide([{"severity": "critical"}], g.DEFAULTS)
        by = {c["check"]: c for c in r["checks"]}
        self.assertEqual(r["verdict"], "deny")
        self.assertEqual(by["max_critical"]["status"], "confirmed")
        self.assertIn("effective=1", by["max_critical"]["detail"])

    def test_json_envelope_carries_checks(self):
        r = g.decide([{"severity": "low"}], g.DEFAULTS)
        self.assertEqual(len(r["checks"]), len(g.CHECK_NAMES))

    def test_cli_checks_is_byte_stable_and_gates_on_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "low", "cvss": 9.8}]).encode("utf-8"))
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--checks"], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            self.assertTrue(r.stdout.endswith(b"\n"))
            rows = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            self.assertEqual(rows[0], ["check", "status", "detail"])
            self.assertEqual(len(rows), 1 + len(g.CHECK_NAMES))
            by = {row[0]: row[1] for row in rows[1:]}
            self.assertEqual(by["parse"], "confirmed")
            self.assertEqual(by["max_critical"], "confirmed")

    def test_cli_checks_on_unreadable_input_marks_parse_not_confirmed(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(Path(d) / "missing.json"), "--checks"],
                               capture_output=True)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            rows = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            by = {row[0]: row[1] for row in rows[1:]}
            self.assertEqual(by["parse"], "not_confirmed")
            self.assertEqual(by["max_total"], "skipped")

    def test_prioritize_still_takes_precedence_over_checks(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "critical"}]).encode("utf-8"))
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--prioritize", "--checks"], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertTrue(r.stdout.decode("utf-8").startswith("index,severity,"))


class ReleasegateSelftestTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(g.__file__).resolve().parent

    def _copy_ground_truth(self, d):
        (Path(d) / "releasegate_expect.json").write_bytes(
            (self.base / "releasegate_expect.json").read_bytes())

    def test_committed_fixture_matches_ground_truth(self):
        st = g.selftest(self.base)
        self.assertEqual(st["status"], "pass")
        self.assertEqual(st["mode"], "selftest")
        self.assertEqual(st["verdict"], "deny")
        by_check = {c["check"]: c for c in st["checks"]}
        self.assertEqual(set(by_check),
                         {"fixture", "expectation", "fixture_hash", "score",
                          "verdict", "total", "buckets", "effective_buckets"})
        for check in by_check.values():
            self.assertEqual(check["status"], "pass")
            self.assertEqual(set(check), {"check", "status", "detail"})
        self.assertEqual(st["fixture_sha256"],
                         hashlib.sha256(
                             (self.base / "releasegate_fixture.json").read_bytes()
                         ).hexdigest())

    def test_regression_is_fail_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            self._copy_ground_truth(d)
            # Remove the CVSS upgrade so effective buckets drift from the answer.
            (Path(d) / "releasegate_fixture.json").write_text(
                json.dumps([{"severity": "critical"}, {"severity": "High"},
                            {"severity": "low"}, {"severity": "info"}]),
                encoding="utf-8")
            st = g.selftest(d)
            self.assertEqual(st["status"], "fail")
            by_check = {c["check"]: c for c in st["checks"]}
            self.assertEqual(by_check["effective_buckets"]["status"], "fail")
            self.assertIn("expected", by_check["effective_buckets"]["detail"])

    def test_hash_drift_is_fail_even_when_decision_matches(self):
        with tempfile.TemporaryDirectory() as d:
            self._copy_ground_truth(d)
            original = (self.base / "releasegate_fixture.json").read_bytes()
            (Path(d) / "releasegate_fixture.json").write_bytes(original + b"\n")
            st = g.selftest(d)
            self.assertEqual(st["status"], "fail")
            by_check = {c["check"]: c for c in st["checks"]}
            self.assertEqual(by_check["fixture_hash"]["status"], "fail")
            self.assertIn("drift", by_check["fixture_hash"]["detail"])
            self.assertEqual(by_check["verdict"]["status"], "pass")
            self.assertEqual(by_check["total"]["status"], "pass")

    def test_unreadable_fixture_is_error_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            st = g.selftest(d)
            self.assertEqual(st["status"], "error")
            self.assertEqual(st["checks"], [
                {"check": "fixture", "status": "error",
                 "detail": "unreadable: FileNotFoundError"}])

    def test_bad_expectation_is_error_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "releasegate_fixture.json").write_bytes(
                (self.base / "releasegate_fixture.json").read_bytes())
            (Path(d) / "releasegate_expect.json").write_text(
                "{not json", encoding="utf-8")
            st = g.selftest(d)
            self.assertEqual(st["status"], "error")
            self.assertEqual(st["checks"][1]["check"], "expectation")
            self.assertEqual(st["checks"][1]["status"], "error")

    def test_cli_selftest_exit_zero_with_parseable_json(self):
        proc = subprocess.run(
            [sys.executable, str(self.base / "releasegate.py"), "--selftest"],
            capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertEqual(proc.stderr, b"")
        self.assertNotIn(b"\r", proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["verdict"], "deny")


class FreshnessTests(unittest.TestCase):
    NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)

    def test_recent_finding_is_confirmed(self):
        f = g.freshness([{"severity": "low", "first_found": "2026-11-19T00:00:00Z"}],
                        7, now=self.NOW)
        self.assertEqual(f["status"], "confirmed")
        self.assertFalse(f["breach"])
        self.assertAlmostEqual(f["age_days"], 1.0, places=3)
        self.assertEqual(f["dated"], 1)

    def test_stale_finding_is_not_confirmed(self):
        f = g.freshness([{"severity": "low", "date": "2026-10-01T00:00:00Z"}],
                        7, now=self.NOW)
        self.assertEqual(f["status"], "not_confirmed")
        self.assertTrue(f["breach"])
        self.assertGreater(f["age_days"], 7)

    def test_no_parseable_date_is_not_confirmed(self):
        f = g.freshness([{"severity": "low"}, {"severity": "high", "date": "n/a"}],
                        7, now=self.NOW)
        self.assertEqual(f["status"], "not_confirmed")
        self.assertTrue(f["breach"])
        self.assertIsNone(f["newest"])
        self.assertIsNone(f["age_days"])
        self.assertIn("no parseable date", f["detail"])

    def test_newest_observation_wins(self):
        rows = [{"date": "2026-10-01T00:00:00Z"},
                {"first_found": "2026-11-19T12:00:00Z"}]
        f = g.freshness(rows, 7, now=self.NOW)
        self.assertEqual(f["status"], "confirmed")
        self.assertEqual(f["dated"], 2)
        self.assertEqual(f["newest"], "2026-11-19T12:00:00+00:00")

    def test_date_parser_variants(self):
        self.assertEqual(g.parse_finding_date("2026-11-19T00:00:00Z"),
                         datetime(2026, 11, 19, tzinfo=timezone.utc))
        self.assertEqual(g.parse_finding_date("2026-11-19 00:00:00-0600"),
                         datetime(2026, 11, 19, 6, tzinfo=timezone.utc))
        self.assertEqual(g.parse_finding_date(True), None)
        self.assertEqual(g.parse_finding_date("not a date"), None)

    def test_positive_days_rejects_bad_values(self):
        for raw in ("0", "-1", "nan", "abc"):
            with self.subTest(raw=raw), self.assertRaises(Exception):
                g._positive_days(raw)
        self.assertEqual(g._positive_days("7"), 7.0)

    def test_cli_stale_exits_2_with_indeterminate_and_freshness_row(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low", "date": "2026-01-01T00:00:00Z"}]),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--max-age-days", "7", "--checks"],
                               capture_output=True)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            rows = list(csv.reader(io.StringIO(r.stdout.decode("utf-8"))))
            by = {row[0]: (row[1], row[2]) for row in rows[1:]}
            self.assertEqual(by["freshness"][0], "not_confirmed")

    def test_cli_stale_json_forces_indeterminate_over_allow(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low", "date": "2026-01-01T00:00:00Z"}]),
                         encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--max-age-days", "7"], capture_output=True)
            self.assertEqual(r.returncode, 2)
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertTrue(out["reasons"][0].startswith("stale evidence:"))
            self.assertEqual(out["freshness"]["status"], "not_confirmed")
            self.assertEqual(out["prioritized"], [])

    def test_cli_fresh_within_limit_keeps_allow(self):
        with tempfile.TemporaryDirectory() as d:
            recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            f = Path(d) / "findings.json"
            f.write_text(json.dumps([{"severity": "low", "date": recent}]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                str(f), "--max-age-days", "7"], capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            out = json.loads(r.stdout)
            self.assertEqual(out["verdict"], "allow")
            self.assertEqual(out["freshness"]["status"], "confirmed")
            self.assertIsNotNone(out["newest_finding_date"])

    def test_default_output_has_no_freshness_field(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "low"}]).encode("utf-8"))
            base = subprocess.run([sys.executable, str(Path(g.__file__).resolve()),
                                   str(f)], capture_output=True)
            self.assertEqual(base.returncode, 0)
            out = json.loads(base.stdout)
            self.assertNotIn("freshness", out)
            self.assertEqual(len(out["checks"]), len(g.CHECK_NAMES))


class BucketCoverageTests(unittest.TestCase):
    """Threshold coverage: every reachable bucket must map to a limit."""

    def test_cvss_band_buckets_match_ranking(self):
        self.assertEqual(g.cvss_band_buckets(), set(g.BUCKETS))

    def test_default_vocabulary_is_fully_covered(self):
        cov = g.bucket_coverage(g.CANONICAL, g.DEFAULTS)
        self.assertEqual(cov["unmapped"], [])
        self.assertEqual([c["bucket"] for c in cov["covered"]],
                         ["critical", "high", "info", "low", "medium"])
        by_bucket = {c["bucket"]: c["threshold"] for c in cov["covered"]}
        self.assertEqual(by_bucket["critical"], "max_critical")
        self.assertEqual(by_bucket["high"], "max_high")
        self.assertEqual(by_bucket["medium"], "max_total")
        self.assertEqual(by_bucket["low"], "max_total")
        self.assertEqual(by_bucket["info"], "max_total")

    def test_reachable_includes_custom_severity_and_emits(self):
        smap = g.build_severity_map({"blocker": "critical"})
        cov = g.bucket_coverage(smap, g.DEFAULTS,
                                {"emits": ["medium", "severe", 7, ""]})
        self.assertIn("critical", cov["reachable"])
        self.assertIn("medium", cov["reachable"])
        self.assertIn("severe", cov["reachable"])
        self.assertNotIn(7, cov["reachable"])  # non-string emit ignored
        self.assertEqual(cov["unmapped"], ["severe"])

    def test_threshold_override_to_missing_limit_is_unmapped(self):
        cov = g.bucket_coverage(g.CANONICAL, g.DEFAULTS,
                                {"thresholds": {"critical": "max_bogus"}})
        self.assertEqual(cov["unmapped"], ["critical"])

    def test_threshold_override_to_configured_limit_is_covered(self):
        limits = dict(g.DEFAULTS)
        limits["max_medium"] = 1
        cov = g.bucket_coverage(g.CANONICAL, limits,
                                {"thresholds": {"medium": "max_medium"}})
        self.assertEqual(cov["unmapped"], [])
        by_bucket = {c["bucket"]: c["threshold"] for c in cov["covered"]}
        self.assertEqual(by_bucket["medium"], "max_medium")

    def test_cli_unmapped_bucket_rule_exits_2_indeterminate(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "low"}]).encode("utf-8"))
            rules = Path(d) / "rules.json"
            rules.write_text(json.dumps({"emits": ["severe"]}), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(Path(g.__file__).resolve()), str(f),
                 "--rules", str(rules)], capture_output=True)
            self.assertEqual(proc.returncode, 2, proc.stderr.decode("utf-8", "replace"))
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "indeterminate")
            self.assertIn("unmapped bucket", out["reasons"][0])
            self.assertEqual(out["bucket_coverage"]["unmapped"], ["severe"])
            self.assertEqual(proc.stderr, b"")
            self.assertNotIn(b"\r", proc.stdout)

    def test_cli_unmapped_bucket_marks_bucket_coverage_check(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "low"}]).encode("utf-8"))
            rules = Path(d) / "rules.json"
            rules.write_text(json.dumps({"thresholds": {"critical": "max_gone"}}),
                             encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(Path(g.__file__).resolve()), str(f),
                 "--rules", str(rules), "--checks"], capture_output=True)
            self.assertEqual(proc.returncode, 2)
            rows = list(csv.reader(io.StringIO(proc.stdout.decode("utf-8"))))
            self.assertEqual(rows[0], ["check", "status", "detail"])
            self.assertEqual(rows[1][0], "bucket_coverage")
            self.assertEqual(rows[1][1], "not_confirmed")

    def test_cli_covered_rule_keeps_normal_verdict_and_exposes_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "blocker"}]).encode("utf-8"))
            rules = Path(d) / "rules.json"
            rules.write_text(json.dumps({"severities": {"blocker": "critical"},
                                         "emits": ["medium"], "max_critical": 0}),
                             encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(Path(g.__file__).resolve()), str(f),
                 "--rules", str(rules)], capture_output=True)
            self.assertEqual(proc.returncode, 1)  # critical breach still denies
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "deny")
            self.assertEqual(out["bucket_coverage"]["unmapped"], [])
            self.assertNotIn("emits", out["limits"])
            self.assertNotIn("thresholds", out["limits"])

    def test_cli_without_rules_has_no_coverage_field(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_bytes(json.dumps([{"severity": "low"}]).encode("utf-8"))
            proc = subprocess.run(
                [sys.executable, str(Path(g.__file__).resolve()), str(f)],
                capture_output=True)
            self.assertEqual(proc.returncode, 0)
            out = json.loads(proc.stdout)
            self.assertNotIn("bucket_coverage", out)
            self.assertEqual(len(out["checks"]), len(g.CHECK_NAMES))


if __name__ == "__main__":
    unittest.main()
