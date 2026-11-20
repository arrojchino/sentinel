import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "ci"

SPEC = importlib.util.spec_from_file_location("selftest_all", CI / "selftest_all.py")
sa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sa)


def run_cli(*args):
    return subprocess.run([sys.executable, str(CI / "selftest_all.py"),
                           *map(str, args)], capture_output=True)


class SelftestAllContractTests(unittest.TestCase):
    def test_vocabulary_and_tool_inventory(self):
        self.assertEqual(sa.EXIT_CODES, {"pass": 0, "fail": 1, "error": 2})
        self.assertEqual(sa.STATUSES, ("pass", "fail", "error"))
        self.assertEqual(sa.TOOLS, ("sentinel.py", "releasegate.py",
                                    "iocscan.py", "timeline.py",
                                    "wazuh_bridge.py"))
        self.assertEqual(sa.SCHEMA_VERSION, 1)

    def test_all_committed_selftests_pass(self):
        doc = sa.run_all()
        self.assertEqual(doc["mode"], "selftest_all")
        self.assertEqual(doc["status"], "pass")
        self.assertEqual(doc["counts"], {"pass": 5, "fail": 0, "error": 0})
        self.assertEqual(len(doc["tools"]), len(sa.TOOLS))
        for row in doc["tools"]:
            with self.subTest(tool=row["tool"]):
                self.assertEqual(row["status"], "pass")
                self.assertEqual(row["exit_code"], 0)
                self.assertGreater(row["checks"], 0)
                self.assertGreater(row["bytes"], 0)
                self.assertEqual(row["detail"], "")

    def test_cli_output_is_byte_stable_and_lf_only(self):
        first = run_cli()
        second = run_cli()
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)
        self.assertNotIn(b"\r", first.stdout)
        self.assertTrue(first.stdout.endswith(b"\n"))
        self.assertEqual(json.loads(first.stdout)["status"], "pass")

    def test_cli_list_is_byte_stable(self):
        proc = run_cli("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn(b"\r", proc.stdout)
        self.assertEqual(proc.stdout.decode().splitlines(), list(sa.TOOLS))


class SelftestAllFailureTests(unittest.TestCase):
    def test_tampered_expectation_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for pattern in ("*.py", "*.json", "*.txt"):
                for src in ROOT.glob(pattern):
                    shutil.copy2(src, directory / src.name)
            shutil.copytree(ROOT / "rules", directory / "rules")
            (directory / "sentinel_expect.json").write_text("{", encoding="utf-8")

            doc = sa.run_all(directory)
            self.assertEqual(doc["status"], "error")
            self.assertEqual(doc["counts"], {"pass": 4, "fail": 0, "error": 1})
            by_tool = {r["tool"]: r for r in doc["tools"]}
            self.assertEqual(by_tool["sentinel.py"]["status"], "error")
            self.assertEqual(by_tool["sentinel.py"]["exit_code"], 2)
            for name in sa.TOOLS[1:]:
                self.assertEqual(by_tool[name]["status"], "pass")

            cli = run_cli("--dir", str(directory))
            self.assertEqual(cli.returncode, 2)
            self.assertEqual(json.loads(cli.stdout)["status"], "error")
            self.assertNotIn(b"\r", cli.stdout)

    def test_non_json_output_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "probe.py"
            script.write_text("print('not json')\n", encoding="utf-8")
            row = sa._tool_result("probe.py", tmp)
            self.assertEqual(row["status"], "error")
            self.assertEqual(row["detail"], "selftest output is not JSON")
            self.assertEqual(row["exit_code"], 0)
            self.assertGreater(row["bytes"], 0)

    def test_status_and_exit_disagreement_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "probe.py"
            script.write_text(
                "import json, sys\n"
                "print(json.dumps({'status': 'pass', 'mode': 'selftest', 'checks': []}))\n"
                "sys.exit(2)\n", encoding="utf-8")
            row = sa._tool_result("probe.py", tmp)
            self.assertEqual(row["status"], "error")
            self.assertIn("disagrees", row["detail"])

    def test_unknown_status_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "probe.py"
            script.write_text(
                "import json\n"
                "print(json.dumps({'status': 'maybe', 'mode': 'selftest'}))\n",
                encoding="utf-8")
            row = sa._tool_result("probe.py", tmp)
            self.assertEqual(row["status"], "error")
            self.assertIn("unknown selftest status", row["detail"])

    def test_missing_tool_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = sa._tool_result("missing.py", tmp)
            self.assertEqual(row["status"], "error")
            self.assertIsNone(row["exit_code"])
            self.assertEqual(row["detail"], "tool script missing")


if __name__ == "__main__":
    unittest.main()
