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

    def test_envelope_shape_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "findings.json"
            f.write_text(json.dumps({"findings": [{"severity": "critical"}]}), encoding="utf-8")
            r = subprocess.run([sys.executable, str(Path(g.__file__).resolve()), str(f)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["verdict"], "deny")


if __name__ == "__main__":
    unittest.main()
