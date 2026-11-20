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


if __name__ == "__main__":
    unittest.main()
