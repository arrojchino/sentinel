import csv
import io
import json
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


if __name__ == "__main__":
    unittest.main()
