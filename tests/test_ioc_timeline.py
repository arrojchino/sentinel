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


if __name__ == "__main__":
    unittest.main()
