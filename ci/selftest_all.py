#!/usr/bin/env python3
"""Run every committed ground-truth selftest through one canonical front-end.

Each tool in this repository exposes a --selftest that replays its engine over
a committed fixture and compares the result with a pinned expectation. This
runner does not duplicate those checks: it invokes each tool exactly as CI does
and reports the aggregated verdict. The shape is borrowed from toolkits whose
documentation offers one canonical command per task rather than restating the
procedure for every audience -- one front-end, each component's own interface.

The status vocabulary is inherited from the tools: pass / fail / error, mapped
to exit codes 0 / 1 / 2. The aggregate status is the worst of the per-tool
statuses. Output is byte-stable: LF newlines, fixed key order, no timestamps and
only tool basenames, never machine-dependent paths.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = 1

TOOLS = (
    "sentinel.py",
    "releasegate.py",
    "iocscan.py",
    "timeline.py",
    "wazuh_bridge.py",
)

EXIT_CODES = {"pass": 0, "fail": 1, "error": 2}
STATUSES = tuple(EXIT_CODES)

HERE = Path(__file__).resolve().parent
DEFAULT_DIR = HERE.parent
TIMEOUT_SECONDS = 60


def _emit(text: str) -> None:
    """Write exact UTF-8 bytes, with no platform newline translation."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)  # captured stdout (e.g. StringIO) has no buffer
    else:
        buffer.write(text.encode("utf-8"))
        buffer.flush()


def _tool_result(name: str, tool_dir: str | Path) -> dict:
    """Invoke one tool's --selftest and normalise what was observed."""
    path = Path(tool_dir) / name
    entry = {"tool": name, "status": "error", "exit_code": None,
             "checks": 0, "bytes": 0, "detail": ""}
    if not path.is_file():
        entry["detail"] = "tool script missing"
        return entry
    try:
        proc = subprocess.run(
            [sys.executable, str(path), "--selftest"],
            capture_output=True, timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        entry["detail"] = f"invocation error: {type(exc).__name__}"
        return entry

    entry["exit_code"] = proc.returncode
    body = proc.stdout.replace(b"\r\n", b"\n")
    entry["bytes"] = len(body)
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        entry["detail"] = "selftest output is not JSON"
        return entry
    if not isinstance(doc, dict):
        entry["detail"] = "selftest JSON is not an object"
        return entry

    status = doc.get("status")
    if status not in EXIT_CODES:
        entry["detail"] = f"unknown selftest status: {status!r}"
        return entry
    checks = doc.get("checks")
    entry["checks"] = len(checks) if isinstance(checks, list) else 0
    entry["status"] = status

    # An honest front-end reports a disagreement instead of trusting either
    # side: the tool's own status and its exit code are two views of one fact.
    if proc.returncode != EXIT_CODES[status]:
        entry["status"] = "error"
        entry["detail"] = f"exit {proc.returncode} disagrees with status {status}"
    elif doc.get("mode") != "selftest":
        entry["status"] = "error"
        entry["detail"] = "selftest mode marker missing"
    return entry


def run_all(tool_dir: str | Path | None = None) -> dict:
    """Return the aggregate envelope for every configured tool."""
    directory = Path(tool_dir) if tool_dir is not None else DEFAULT_DIR
    results = [_tool_result(name, directory) for name in TOOLS]
    counts = {status: sum(1 for r in results if r["status"] == status)
              for status in STATUSES}
    overall = "error" if counts["error"] else "fail" if counts["fail"] else "pass"
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "selftest_all",
        "status": overall,
        "tools": results,
        "counts": counts,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Run every committed selftest through one canonical front-end")
    p.add_argument("--dir", help="directory holding the tools and fixtures (default: repo root)")
    p.add_argument("--list", action="store_true", help="list the tools this runner covers")
    args = p.parse_args(argv)
    if args.list:
        _emit("\n".join(TOOLS) + "\n")
        return 0
    doc = run_all(args.dir)
    _emit(json.dumps(doc, indent=2) + "\n")
    return EXIT_CODES[doc["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
