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


if __name__ == "__main__":
    unittest.main()
