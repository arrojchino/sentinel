import csv
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sentinel as s


class SentinelTests(unittest.TestCase):
    def test_evidence_fields_are_structural(self):
        rules = s.json.loads((s.RULES / "traceverify.json").read_text())
        payload = {"state": "confirmed", "note": "mentions tool_call reported_execution observed_effect"}
        out = s.check(json.dumps(payload), rules, Path("x.json"))
        kinds = [f["kind"] for f in out]
        self.assertEqual(kinds.count("missing_evidence"), 3)

    def test_unresolved_state_is_flagged(self):
        rules = s.json.loads((s.RULES / "traceverify.json").read_text())
        payload = {"state": "open_proof_gap", "tool_call": 1, "reported_execution": 2, "observed_effect": 3}
        kinds = [f["kind"] for f in s.check(json.dumps(payload), rules, Path("x.json"))]
        self.assertIn("unresolved_state", kinds)

    def test_authorization_is_required_and_expiry_checked(self):
        rules = s.json.loads((s.RULES / "toolallow.json").read_text())
        base = {"tool": "verify"}
        kinds = [f["kind"] for f in s.check(json.dumps(base), rules, Path("x.json"))]
        self.assertEqual(kinds.count("missing_authorization"), 3)
        auth = {**base, "scope_ref": "S-1", "approver": "owner", "expires_at": "2020-01-01"}
        kinds = [f["kind"] for f in s.check(json.dumps(auth), rules, Path("x.json"))]
        self.assertIn("expired_authorization", kinds)

    def test_custody_hash_is_verified(self):
        rules = s.json.loads((s.RULES / "chaincustody.json").read_text())
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.bin"
            p.write_bytes(b"proof")
            manifest = Path(d) / "manifest.csv"
            manifest.write_text("path,sha256,size,role\na.bin,BAD,5,primary\n", encoding="utf-8")
            kinds = [f["kind"] for f in s.check(manifest.read_text(), rules, manifest)]
            self.assertIn("hash_mismatch", kinds)
            manifest.write_text("path,sha256,size,role\na.bin," + __import__("hashlib").sha256(b"proof").hexdigest() + ",5,primary\n", encoding="utf-8")
            self.assertEqual(s.check(manifest.read_text(), rules, manifest), [])

    def test_exit_code_gates_findings(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{}", encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), "--tool", "outputschema", str(bad)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            good = Path(d) / "good.json"
            good.write_text('{"schema_version":1,"report_id":"abc","generated_at":"now","findings":[]}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), "--tool", "outputschema", str(good)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)


class SeverityOrderingTests(unittest.TestCase):
    def test_known_kind_maps_and_unknown_defaults_to_info(self):
        self.assertEqual(s.severity_of("hash_mismatch"), "critical")
        self.assertEqual(s.severity_of("missing_field"), "low")
        self.assertEqual(s.severity_of("pattern"), "info")
        self.assertEqual(s.severity_of("never_seen_kind"), "info")

    def test_error_tool_is_indeterminate_and_empty_tool_is_clear(self):
        self.assertEqual(s.tool_severity({"tool": "x", "error": "ValueError: bad"}), "indeterminate")
        self.assertEqual(s.tool_severity({"tool": "x", "count": 0, "findings": []}), "clear")

    def test_tool_uses_its_most_severe_finding(self):
        result = {"tool": "x", "findings": [{"kind": "pattern"}, {"kind": "hash_mismatch"}]}
        self.assertEqual(s.tool_severity(result), "critical")

    def test_prioritized_leads_critical_over_noisy_info(self):
        results = [
            {"tool": "noisy", "count": 25, "findings": [{"kind": "pattern"}] * 25},
            {"tool": "critical", "count": 1, "findings": [{"kind": "hash_mismatch"}]},
        ]
        order = s.prioritized(results)
        self.assertEqual(order[0], {"tool": "critical", "severity": "critical",
                                    "count": 1, "must_fix": True})
        self.assertEqual(order[-1], {"tool": "noisy", "severity": "info",
                                     "count": 25, "must_fix": False})

    def test_error_tool_outleads_every_scored_tool(self):
        results = [
            {"tool": "critical", "findings": [{"kind": "tool_not_allowed"}]},
            {"tool": "broken", "error": "JSONDecodeError: bad"},
        ]
        order = s.prioritized(results)
        self.assertEqual(order[0]["tool"], "broken")
        self.assertEqual(order[0]["severity"], "indeterminate")
        self.assertTrue(order[0]["must_fix"])

    def test_tiebreak_is_count_then_name(self):
        results = [
            {"tool": "zeta", "count": 2, "findings": [{"kind": "missing_field"}] * 2},
            {"tool": "alpha", "count": 5, "findings": [{"kind": "missing_field"}] * 5},
        ]
        order = s.prioritized(results)
        self.assertEqual([p["tool"] for p in order], ["alpha", "zeta"])

    def test_cli_probe_critical_tool_leads_info_tool(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            out = Path(d) / "out.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--out", str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["prioritized"][0]["tool"], "toolallow")
            self.assertEqual(doc["prioritized"][0]["severity"], "critical")
            self.assertEqual(doc["results"][0]["tool"], "toolallow")
            eml = [p for p in doc["prioritized"] if p["tool"] == "emlhash"][0]
            self.assertEqual(eml["severity"], "info")
            self.assertFalse(eml["must_fix"])


class TriageCsvTests(unittest.TestCase):
    def test_contract_columns_lowercase_bool_and_order(self):
        rows = [
            {"tool": "critical", "severity": "critical", "count": 1, "must_fix": True},
            {"tool": "noisy", "severity": "info", "count": 25, "must_fix": False},
        ]
        text = s.prioritize_csv(rows)
        self.assertEqual(text.splitlines()[0], "tool,severity,count,must_fix")
        parsed = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(parsed[0], {"tool": "critical", "severity": "critical",
                                     "count": "1", "must_fix": "true"})
        self.assertEqual(parsed[1]["must_fix"], "false")
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("\r", text)

    def test_cli_probe_emits_only_parseable_csv_and_gates(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--prioritize"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stderr, "")
            self.assertNotIn('"schema_version"', r.stdout)
            parsed = list(csv.DictReader(io.StringIO(r.stdout)))
            self.assertEqual(list(parsed[0].keys()), ["tool", "severity", "count", "must_fix"])
            self.assertEqual(parsed[0]["tool"], "toolallow")
            self.assertEqual(parsed[0]["severity"], "critical")
            self.assertEqual(parsed[0]["must_fix"], "true")

    def test_stdout_bytes_use_lf_only(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--prioritize"], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertNotIn(b"\r", r.stdout)
            self.assertTrue(r.stdout.endswith(b"\n"))

    def test_prioritize_with_out_writes_csv_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            out = Path(d) / "triage.csv"
            src.write_text('{"schema_version":1,"report_id":"r","generated_at":"now",'
                           '"findings":[]}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--tool", "outputschema", "--prioritize", "--out", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertEqual(r.stdout, "")
            self.assertEqual(out.read_text(encoding="utf-8").splitlines()[0],
                             "tool,severity,count,must_fix")


class SourceProvenanceTests(unittest.TestCase):
    def test_manifest_shape_from_supplied_bytes(self):
        raw = b'{"a": 1}\n\n{"b": 2}\n'
        m = s.source_manifest("capture.json", raw)
        self.assertEqual(set(m), {"name", "bytes", "lines", "sha256"})
        self.assertEqual(m["name"], "capture.json")
        self.assertEqual(m["bytes"], len(raw))
        self.assertEqual(m["lines"], 2)
        self.assertEqual(m["sha256"], hashlib.sha256(raw).hexdigest())

    def test_run_attaches_one_manifest_entry(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            raw = b'{"state": "open_proof_gap", "tool": "dropper"}\n'
            src.write_bytes(raw)
            doc = s.run(src, None, None)
            self.assertEqual(len(doc["source_files"]), 1)
            m = doc["source_files"][0]
            self.assertEqual(m["name"], "in.json")
            self.assertEqual(m["bytes"], len(raw))
            self.assertEqual(m["sha256"], hashlib.sha256(raw).hexdigest())

    def test_cli_probe_sha256_matches_independent_read(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            out = Path(d) / "out.json"
            raw = b'{"state": "open_proof_gap", "tool": "dropper"}\n'
            src.write_bytes(raw)
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--out", str(out)], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", out.read_bytes())
            doc = json.loads(out.read_text(encoding="utf-8"))
            m = doc["source_files"][0]
            self.assertEqual(m["bytes"], len(raw))
            self.assertEqual(m["lines"], 1)
            # Independent computation from a separate read of the same file.
            self.assertEqual(m["sha256"], hashlib.sha256(src.read_bytes()).hexdigest())
            self.assertEqual(src.read_bytes(), raw)  # detection never rewrites input

    def test_prioritize_stays_observables_only(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--prioritize"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stderr, "")
            self.assertNotIn("source_files", r.stdout)
            self.assertEqual(r.stdout.splitlines()[0], "tool,severity,count,must_fix")


class ConfirmationWorksheetTests(unittest.TestCase):
    def test_closed_vocabulary_and_no_dropped_tools(self):
        rows = s.checks(["alpha", "beta", "gamma"], [
            {"tool": "alpha", "count": 0, "findings": []},
            {"tool": "beta", "error": "ValueError: bad"},
        ])
        by = {r["tool"]: r for r in rows}
        self.assertEqual(set(by), {"alpha", "beta", "gamma"})
        self.assertEqual(by["alpha"]["status"], "confirmed")
        self.assertEqual(by["alpha"]["findings"], 0)  # zero is a real result
        self.assertEqual(by["beta"]["status"], "not_confirmed")
        self.assertIsNone(by["beta"]["findings"])
        self.assertEqual(by["gamma"]["status"], "skipped")
        self.assertIsNone(by["gamma"]["findings"])
        self.assertTrue(all(r["status"] in s.CHECK_STATUSES for r in rows))

    def test_csv_contract_and_byte_stability(self):
        text = s.checks_csv([
            {"tool": "alpha", "status": "confirmed", "findings": 0},
            {"tool": "beta", "status": "not_confirmed", "findings": None},
            {"tool": "gamma", "status": "skipped", "findings": None},
        ])
        self.assertEqual(text.splitlines()[0], "tool,status,findings")
        parsed = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(parsed[0], {"tool": "alpha", "status": "confirmed", "findings": "0"})
        self.assertEqual(parsed[1]["findings"], "")
        self.assertEqual(parsed[2]["findings"], "")
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("\r", text)

    def test_cli_probe_emits_only_worksheet_and_gates(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--checks"], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            self.assertNotIn(b'"schema_version"', r.stdout)
            self.assertNotIn(b"source_files", r.stdout)
            text = r.stdout.decode("utf-8")
            self.assertEqual(text.splitlines()[0], "tool,status,findings")
            parsed = list(csv.DictReader(io.StringIO(text)))
            self.assertEqual([row["tool"] for row in parsed], s.tools())
            self.assertTrue(all(row["status"] in s.CHECK_STATUSES for row in parsed))

    def test_tool_filter_marks_others_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            out = Path(d) / "out.json"
            src.write_text('{"schema_version":1,"report_id":"r","generated_at":"now",'
                           '"findings":[]}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--tool", "outputschema", "--out", str(out)], capture_output=True)
            self.assertEqual(r.returncode, 0)
            doc = json.loads(out.read_text(encoding="utf-8"))
            by = {c["tool"]: c for c in doc["checks"]}
            self.assertEqual(len(doc["checks"]), len(s.tools()))
            self.assertEqual(by["outputschema"]["status"], "confirmed")
            self.assertTrue(all(c["status"] == "skipped" for t, c in by.items()
                                if t != "outputschema"))

    def test_prioritize_takes_precedence_over_checks(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src),
                                "--prioritize", "--checks"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stdout.splitlines()[0], "tool,severity,count,must_fix")


class QuickstartTests(unittest.TestCase):
    """A bare invocation is a discovery aid (the scanner no-parameter pattern)."""

    def test_zero_args_returns_quickstart_and_exit_zero(self):
        out = io.StringIO()
        old = sys.stdout
        try:
            sys.stdout = out
            code = s.main([])
        finally:
            sys.stdout = old
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("--list --team blue", text)
        self.assertIn("Exit status is the CI contract", text)
        self.assertIn("--prioritize", text)

    def test_argument_without_file_is_still_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            s.main(["--tool", "headerscheck"])
        self.assertEqual(ctx.exception.code, 2)

    def test_cli_probe_no_args_is_lf_only_and_empty_stderr(self):
        r = subprocess.run([sys.executable, str(Path(s.__file__).resolve())],
                           capture_output=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, b"")
        self.assertNotIn(b"\r", r.stdout)
        self.assertTrue(r.stdout.endswith(b"\n"))
        self.assertIn(b"--list --team blue", r.stdout)

    def test_file_path_bytes_are_unchanged_by_quickstart(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.json"
            src.write_text('{"state": "open_proof_gap", "tool": "dropper"}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), str(src)],
                               capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertNotIn(b"\r", r.stdout)
            doc = json.loads(r.stdout)
            self.assertIn("results", doc)
            self.assertIn("prioritized", doc)


class SentinelSelftestTests(unittest.TestCase):
    """Ground-truth check for the severity/order reporting engine."""

    def _copy_base(self, d):
        base = Path(d)
        shutil.copy(s.HERE / "sentinel.py", base / "sentinel.py")
        shutil.copy(s.HERE / "teams.json", base / "teams.json")
        shutil.copy(s.HERE / "sentinel_expect.json", base / "sentinel_expect.json")
        shutil.copytree(s.HERE / "rules", base / "rules")
        return base

    def test_committed_fixture_passes(self):
        st = s.selftest(s.HERE)
        self.assertEqual(st["status"], "pass")
        self.assertEqual(st["mode"], "selftest")
        self.assertTrue(all(c["status"] == "pass" for c in st["checks"]))
        self.assertEqual(len(st["checks"]), 9)
        self.assertEqual(st["tool_results"], 6)
        by = {c["check"]: c for c in st["checks"]}
        self.assertEqual(by["kind_coverage"]["status"], "pass")

    def test_fixture_hash_matches_hashlib(self):
        data = (s.HERE / "sentinel_fixture.json").read_bytes()
        st = s.selftest(s.HERE)
        self.assertEqual(st["fixture_sha256"], hashlib.sha256(data).hexdigest())

    def test_cli_selftest_is_byte_stable_and_empty_stderr(self):
        r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()), "--selftest"],
                           capture_output=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, b"")
        self.assertNotIn(b"\r", r.stdout)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["status"], "pass")

    def test_regression_fails_closed_with_exit_one(self):
        with tempfile.TemporaryDirectory() as d:
            base = self._copy_base(d)
            fix = json.loads((s.HERE / "sentinel_fixture.json").read_text(encoding="utf-8"))
            fix[1]["findings"][0]["kind"] = "sha256"
            (base / "sentinel_fixture.json").write_text(json.dumps(fix), encoding="utf-8")
            r = subprocess.run([sys.executable, str(base / "sentinel.py"), "--selftest"],
                               capture_output=True)
            self.assertEqual(r.returncode, 1)
            st = json.loads(r.stdout)
            self.assertEqual(st["status"], "fail")
            failed = {c["check"] for c in st["checks"] if c["status"] == "fail"}
            self.assertIn("prioritized", failed)
            self.assertIn("must_fix", failed)

    def test_missing_fixture_errors_with_exit_two(self):
        with tempfile.TemporaryDirectory() as d:
            base = self._copy_base(d)
            st = s.selftest(base)
            self.assertEqual(st["status"], "error")
            self.assertEqual(st["checks"][0]["status"], "error")
            r = subprocess.run([sys.executable, str(base / "sentinel.py"), "--selftest"],
                               capture_output=True)
            self.assertEqual(r.returncode, 2)

    def test_unparsable_fixture_errors_with_exit_two(self):
        with tempfile.TemporaryDirectory() as d:
            base = self._copy_base(d)
            (base / "sentinel_fixture.json").write_text("not json", encoding="utf-8")
            st = s.selftest(base)
            self.assertEqual(st["status"], "error")
            self.assertEqual(st["checks"][-1]["check"], "parse")
            self.assertEqual(st["checks"][-1]["status"], "error")

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(ValueError):
            s._selftest_check("x", "bogus")


class KindCoverageTests(unittest.TestCase):
    """Every reachable finding kind must be declared in SEVERITY."""

    def test_all_configured_kinds_are_declared(self):
        cov = s.kind_coverage()
        self.assertEqual(cov["errors"], [])
        self.assertEqual(cov["unmapped"], [])
        self.assertEqual(cov["declared"], cov["reachable"])
        self.assertGreaterEqual(len(cov["reachable"]), 15)

    def test_coverage_derives_kinds_from_every_emission_type(self):
        kinds = set(s.kind_coverage()["reachable"])
        # One representative kind from each rule type's emission inventory.
        for kind in ("missing_header", "pattern", "missing_field", "hash_mismatch",
                     "sha256", "invalid_state", "tool_not_allowed"):
            self.assertIn(kind, kinds)

    def test_missing_rules_directory_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            cov = s.kind_coverage(Path(d) / "absent")
            self.assertTrue(cov["errors"])
            self.assertEqual(cov["unmapped"], [])
            self.assertIn("missing", cov["errors"][0])

    def test_unmapped_rule_type_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            rules = Path(d)
            (rules / "odd.json").write_text('{"type": "brand_new_type"}', encoding="utf-8")
            cov = s.kind_coverage(rules)
            self.assertTrue(any("unmapped rule type" in e for e in cov["errors"]))

    def test_temporary_rule_emitting_new_kind_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            shutil.copy(s.HERE / "sentinel.py", base / "sentinel.py")
            shutil.copy(s.HERE / "teams.json", base / "teams.json")
            shutil.copy(s.HERE / "sentinel_fixture.json", base / "sentinel_fixture.json")
            shutil.copy(s.HERE / "sentinel_expect.json", base / "sentinel_expect.json")
            shutil.copytree(s.HERE / "rules", base / "rules")
            (base / "rules" / "zzprobe.json").write_text(
                '{"type": "regex", "patterns": [], "emits": ["probe_only_kind"]}',
                encoding="utf-8")

            st = s.selftest(base)
            self.assertEqual(st["status"], "fail")
            by = {c["check"]: c for c in st["checks"]}
            self.assertEqual(by["kind_coverage"]["status"], "fail")
            self.assertIn("probe_only_kind", by["kind_coverage"]["detail"])

            r = subprocess.run([sys.executable, str(base / "sentinel.py"), "--selftest"],
                               capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            doc = json.loads(r.stdout)
            self.assertEqual(doc["status"], "fail")
            cov_by = {c["check"]: c for c in doc["checks"]}
            self.assertEqual(cov_by["kind_coverage"]["status"], "fail")


class CompletenessWorksheetTests(unittest.TestCase):
    def test_closed_vocabulary_and_pending_never_clean(self):
        results = [
            {"tool": "verified", "count": 3},
            {"tool": "pending", "count": 0},
            {"tool": "extra", "count": 5},
            {"tool": "not_confirmed", "error": "boom"},
        ]
        claims = {"verified": 3, "pending": 2, "extra": 2,
                  "not_confirmed": 0, "not_run": 0}
        rows = s.completeness(claims, results)
        self.assertEqual([r["tool"] for r in rows], sorted(claims))
        by = {r["tool"]: r for r in rows}
        self.assertEqual({t: by[t]["status"] for t in sorted(claims)}, {
            "verified": "verified", "pending": "pending", "extra": "extra",
            "not_confirmed": "not_confirmed", "not_run": "not_run"})
        self.assertTrue(all(r["status"] in s.COMPLETENESS_STATUSES for r in rows))
        self.assertEqual(by["pending"]["parsed"], 0)
        self.assertEqual(by["pending"]["claimed"], 2)
        self.assertIsNone(by["not_run"]["parsed"])
        self.assertIsNone(by["not_confirmed"]["parsed"])

    def test_csv_contract_and_byte_stability(self):
        rows = [
            {"tool": "a", "status": "verified", "claimed": 1, "parsed": 1},
            {"tool": "b", "status": "not_run", "claimed": 0, "parsed": None},
        ]
        text = s.completeness_csv(rows)
        self.assertEqual(text, "tool,status,claimed,parsed\na,verified,1,1\nb,not_run,0,\n")
        self.assertNotIn("\r", text)
        self.assertEqual(text, s.completeness_csv(rows))

    def test_load_claims_valid_and_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "claims.json"
            path.write_text('{"outputschema": 2}', encoding="utf-8")
            claims, err = s.load_claims(path)
            self.assertIsNone(err)
            self.assertEqual(claims, {"outputschema": 2})
            for body in ('[]', '{"x": -1}', '{"x": "2"}', '{"x": true}', '{bad'):
                path.write_text(body, encoding="utf-8")
                claims, err = s.load_claims(path)
                self.assertIsNone(claims)
                self.assertTrue(err)
            claims, err = s.load_claims(Path(d) / "missing.json")
            self.assertIsNone(claims)
            self.assertIn("unreadable", err)

    def _probe(self, directory, claim_text, input_text='{"schema_version":1,"report_id":"abc","generated_at":"now","findings":[]}'):
        good = Path(directory) / "good.json"
        good.write_text(input_text, encoding="utf-8")
        claims = Path(directory) / "claims.json"
        claims.write_text(claim_text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(Path(s.__file__).resolve()), "--tool", "outputschema",
             str(good), "--completeness", "--claims", str(claims)],
            capture_output=True)

    def test_cli_probe_verified_exits_clean(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._probe(d, '{"outputschema": 0}')
            self.assertEqual(r.returncode, 0)
            self.assertEqual(r.stderr, b"")
            self.assertNotIn(b"\r", r.stdout)
            self.assertEqual(r.stdout.decode("utf-8"),
                             "tool,status,claimed,parsed\noutputschema,verified,0,0\n")

    def test_cli_probe_pending_exits_one_with_zero_findings(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._probe(d, '{"outputschema": 2}')
            self.assertEqual(r.returncode, 1)  # pending is never clean at parsed zero
            self.assertIn("outputschema,pending,2,0", r.stdout.decode("utf-8"))

    def test_cli_probe_bad_claim_and_missing_file_exit_two(self):
        with tempfile.TemporaryDirectory() as d:
            good = Path(d) / "good.json"
            good.write_text("{}", encoding="utf-8")
            claims = Path(d) / "claims.json"
            claims.write_text('{"outputschema": -1}', encoding="utf-8")
            base = [sys.executable, str(Path(s.__file__).resolve()),
                    "--tool", "outputschema", str(good), "--completeness"]
            self.assertEqual(subprocess.run(base + ["--claims", str(claims)],
                                            capture_output=True).returncode, 2)
            self.assertEqual(subprocess.run(base, capture_output=True).returncode, 2)

    def test_default_envelope_has_no_completeness_field(self):
        with tempfile.TemporaryDirectory() as d:
            good = Path(d) / "good.json"
            good.write_text('{"schema_version":1,"report_id":"abc","generated_at":"now","findings":[]}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(s.__file__).resolve()),
                                "--tool", "outputschema", str(good)], capture_output=True)
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("completeness", json.loads(r.stdout))
            self.assertNotIn("claimed", r.stdout.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
