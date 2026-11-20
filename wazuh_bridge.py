#!/usr/bin/env python3
"""Read real Wazuh alerts from WSL, triage them, then run Sentinel blue checks.

Read-only on the Wazuh host. No credentials, no network calls from this script.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DISTRO = "Ubuntu-24.04"
ALERTS = "/var/ossec/logs/alerts/alerts.json"

# Closed per-check confirmation vocabulary shared by the sentinel tools.
#   confirmed    - the check ran and produced a result (possibly zero findings)
#   not_confirmed - its input could not be read or trusted (never clean)
#   skipped      - it did not apply to this run
# A confirmed zero means "nothing detected by this check", not "no risk".
CHECK_STATUSES = ("confirmed", "not_confirmed", "skipped")


def _check(name: str, status: str, detail: str = "") -> dict:
    """Build one confirmation row with a closed status and a short detail."""
    if status not in CHECK_STATUSES:
        raise ValueError(f"unknown check status: {status}")
    return {"check": name, "status": status, "detail": detail}


def parse_timestamp(value) -> datetime | None:
    """Parse a Wazuh ISO-8601 timestamp into an aware datetime, or None.

    Wazuh emits ``2026-11-18T14:53:49.864-0600``: a colonless numeric UTC
    offset that older ``fromisoformat`` versions reject. Normalize the offset
    and a trailing ``Z`` or space separator before parsing. An unparseable
    value returns None so freshness can fail closed instead of guessing.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    if len(text) >= 5 and text[-5] in "+-" and text[-4:].isdigit():
        text = text[:-5] + text[-5] + text[-4:-2] + ":" + text[-2:]
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def freshness(rows: list[dict], max_age_days: float, now: datetime | None = None) -> dict:
    """Evaluate the newest alert age against a limit, fail-closed by design.

    A quiet alert log is not evidence of a quiet network: it may simply be
    stale. This reports the age of the newest alert actually observed and
    marks the check ``not_confirmed`` when that age breaches the limit or no
    timestamp can be parsed, so silence can never be mistaken for absence.
    """
    if now is None:
        now = datetime.now().astimezone()
    stamps = [s for s in (parse_timestamp(a.get("timestamp")) for a in rows) if s is not None]
    if not stamps:
        return {"status": "not_confirmed", "breach": True, "newest": None,
                "age_days": None, "max_age_days": max_age_days,
                "detail": f"no parseable timestamp in {len(rows)} alert(s)"}
    newest = max(stamps)
    if newest.tzinfo is None:
        newest = newest.replace(tzinfo=now.tzinfo)
    age_days = (now - newest).total_seconds() / 86400.0
    breach = age_days > max_age_days
    return {"status": "not_confirmed" if breach else "confirmed", "breach": breach,
            "newest": newest.isoformat(timespec="seconds"),
            "age_days": round(age_days, 4), "max_age_days": max_age_days,
            "detail": f"newest alert {age_days:.2f}d old, limit {max_age_days:g}d"}


def _positive_days(raw) -> float:
    """argparse type: a strictly positive, finite age limit in days."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("--max-age-days must be a positive number")
    if value <= 0 or value != value:  # reject zero, negatives and NaN
        raise argparse.ArgumentTypeError("--max-age-days must be a positive number")
    return value


def fetch(count: int, source: str | None = None) -> dict:
    """Read raw alert lines from WSL, or from a local file when ``source`` is set.

    Wazuh separates collection from analysis: an agent forwards logs to a
    manager that then decodes and analyzes them. This step is only the
    collection half. It reports success and a single-line error instead of
    raising, so a failed read can be shown as ``not_confirmed`` downstream
    rather than being mistaken for "no alerts".
    """
    if source is None:
        cmd = ["wsl.exe", "-d", DISTRO, "--", "bash", "-lc",
               f"sudo -n tail -n {count} {ALERTS}"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "raw": [], "error": f"wsl read failed: {type(exc).__name__}"}
        if r.returncode != 0:
            err = " ".join(r.stderr.split())[:120] or f"wsl exit {r.returncode}"
            return {"ok": False, "raw": [], "error": err}
        raw_text = r.stdout.replace("\x00", "")
    else:
        try:
            raw_text = Path(source).read_text(encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "raw": [], "error": f"input unreadable: {type(exc).__name__}"}
    raw = [line for line in raw_text.splitlines() if line.strip()]
    return {"ok": True, "raw": raw, "error": ""}


def parse_lines(raw: list[str]) -> tuple[list[dict], int]:
    """Decode non-blank lines into alert objects; count malformed lines."""
    rows: list[dict] = []
    malformed = 0
    for line in raw:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(obj, dict):
            malformed += 1
            continue
        rows.append(obj)
    return rows, malformed


def triage(rows: list[dict], threshold: int) -> dict:
    groups = defaultdict(lambda: {"count": 0, "max_level": 0, "first": None, "last": None,
                                  "rules": set(), "agents": set()})
    for alert in rows:
        rule = alert.get("rule", {})
        level = int(rule.get("level", 0))
        agent = alert.get("agent", {}).get("name", "unknown")
        src = alert.get("srcip") or alert.get("data", {}).get("srcip") or "-"
        ts = alert.get("timestamp")
        g = groups[(agent, src)]
        g["count"] += 1
        g["max_level"] = max(g["max_level"], level)
        g["first"] = min(filter(None, [g["first"], ts])) if g["first"] else ts
        g["last"] = max(filter(None, [g["last"], ts])) if g["last"] else ts
        g["rules"].add(rule.get("description", "-"))
        g["agents"].add(agent)
    queue = []
    for (agent, src), g in groups.items():
        if g["max_level"] < threshold:
            continue
        queue.append({"agent": agent, "srcip": src, "count": g["count"],
                      "max_level": g["max_level"], "first": g["first"], "last": g["last"],
                      "rules": sorted(g["rules"])[:5]})
    queue.sort(key=lambda x: (-x["max_level"], -x["count"]))
    return {"generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "alerts_read": len(rows), "threshold": threshold,
            "groups": len(groups), "queue": queue}


def checks(result: dict) -> list:
    """Return a per-check confirmation worksheet for one bridge run, in order.

    The three checks mirror the Wazuh collection pipeline and the shared
    sentinel vocabulary: ``tail`` is collection, ``parse`` is decoding and
    ``grouping`` is analysis. A failed read makes ``tail`` and ``parse``
    ``not_confirmed`` and leaves ``grouping`` ``skipped``, so "no data" can
    never look like "no alerts". A confirmed zero is only an evidence result,
    not absolution.
    """
    read_ok = bool(result.get("read_ok"))
    if read_ok:
        rows = [
            _check("tail", "confirmed", f"{result.get('lines_read', 0)} line(s)"),
            _check("parse", "confirmed",
                   f"{result.get('alerts_read', 0)} alert(s), "
                   f"{result.get('malformed', 0)} malformed"),
            _check("grouping", "confirmed",
                   f"{result.get('groups', 0)} group(s), "
                   f"{len(result.get('queue', []))} queued"),
        ]
    else:
        rows = [
            _check("tail", "not_confirmed", result.get("read_error", "read failed")),
            _check("parse", "not_confirmed", "input not read"),
            _check("grouping", "skipped", "parse not confirmed"),
        ]
    # Freshness is an opt-in fourth check. When absent the worksheet keeps its
    # original three rows, so an unchanged run produces byte-identical output.
    if "freshness" in result:
        f = result["freshness"]
        rows.append(_check("freshness", f["status"], f["detail"]))
    return rows


def checks_csv(rows: list) -> str:
    """Render the confirmation worksheet as a byte-stable CSV.

    Column contract: check,status,detail -- one row per check in the fixed
    order returned by :func:`checks`. ``status`` is from the closed
    CHECK_STATUSES vocabulary; ``detail`` is a short fact or reason (a skipped
    check still states why it did not apply). An LF terminator and trailing
    newline keep the bytes stable across platforms.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("check", "status", "detail"))
    for row in rows:
        writer.writerow((row["check"], row["status"], row.get("detail", "")))
    return buf.getvalue()


# A ground-truth check answers "does this front-end still match its pinned
# answer", not "did this input confirm a step". It exercises the very same
# fetch -> parse -> triage -> checks pipeline as a normal run, so a pass is
# evidence that the shipped engine (not a parallel reimplementation) still
# produces the recorded result.
SELFTEST_STATUSES = ("pass", "fail", "error", "skipped")


def _selftest_check(name: str, status: str, detail: str = "") -> dict:
    """Build one selftest row with a closed status and a short detail."""
    if status not in SELFTEST_STATUSES:
        raise ValueError(f"unknown selftest status: {status}")
    return {"check": name, "status": status, "detail": detail}


def selftest(base: str | Path | None = None) -> dict:
    """Validate the bridge pipeline against a committed ground-truth fixture.

    Like TShark and Wireshark sharing one dissection engine behind two
    front-ends, this check drives the same production functions as a normal
    run over ``wazuh_alert_fixture.txt`` and compares the result to
    ``wazuh_expect.json``. It is a coverage regression check, not a risk
    verdict: ``status`` is pass (all expectations met), fail (a regression),
    or error (fixture or expectation unreadable, always fail-closed). The
    pinned SHA-256 binds the exact fixture bytes; it says nothing about the
    authenticity or completeness of the alerts those bytes represent.
    """
    base = Path(base) if base is not None else Path(__file__).resolve().parent
    fixture = base / "wazuh_alert_fixture.txt"
    expect_path = base / "wazuh_expect.json"
    selftest_rows: list = []
    try:
        data = fixture.read_bytes()
    except OSError as e:
        selftest_rows.append(_selftest_check("fixture", "error",
                                             f"unreadable: {type(e).__name__}"))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "checks": selftest_rows}
    selftest_rows.append(_selftest_check("fixture", "pass", f"{len(data)} bytes"))
    try:
        expectation = json.loads(expect_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        selftest_rows.append(_selftest_check("expectation", "error",
                                             f"unreadable: {type(e).__name__}"))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "checks": selftest_rows}
    selftest_rows.append(_selftest_check("expectation", "pass", "ground truth loaded"))

    actual_hash = hashlib.sha256(data).hexdigest()
    pinned = expectation.get("fixture_sha256")
    if pinned:
        matched = pinned == actual_hash
        selftest_rows.append(_selftest_check(
            "fixture_hash", "pass" if matched else "fail",
            "bytes match the pinned answer" if matched
            else f"drift: expected {pinned}, got {actual_hash}"))
    else:
        selftest_rows.append(_selftest_check("fixture_hash", "skipped", "no pinned hash"))

    # Drive the production pipeline over the committed fixture.
    threshold = expectation.get("threshold", 7)
    read = fetch(200, str(fixture))
    if not read["ok"]:
        selftest_rows.append(_selftest_check("pipeline", "error", read["error"]))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "checks": selftest_rows}
    rows, malformed = parse_lines(read["raw"])
    result = triage(rows, threshold)
    result.update({"read_ok": True, "read_error": "", "lines_read": len(read["raw"]),
                   "malformed": malformed})
    result["checks"] = checks(result)
    observed = {
        "lines_read": result["lines_read"],
        "alerts_read": result["alerts_read"],
        "malformed": result["malformed"],
        "groups": result["groups"],
        "queued": len(result["queue"]),
    }
    observed["queue"] = result["queue"]
    observed["checks_csv"] = checks_csv(result["checks"])

    count_mismatches = [k for k in ("lines_read", "alerts_read", "malformed",
                                    "groups", "queued")
                        if expectation.get(k) != observed[k]]
    if count_mismatches:
        selftest_rows.append(_selftest_check("counts", "fail",
                                             "mismatched: " + ", ".join(count_mismatches)))
    else:
        selftest_rows.append(_selftest_check("counts", "pass", "all counts match"))

    if expectation.get("queue") == observed["queue"]:
        selftest_rows.append(_selftest_check("queue", "pass", "exact order and content"))
    else:
        selftest_rows.append(_selftest_check("queue", "fail", "queue drift"))

    if expectation.get("checks_csv") == observed["checks_csv"]:
        selftest_rows.append(_selftest_check("checks", "pass", "byte-identical worksheet"))
    else:
        selftest_rows.append(_selftest_check("checks", "fail", "worksheet drift"))

    if any(c["status"] == "error" for c in selftest_rows):
        status = "error"
    elif any(c["status"] == "fail" for c in selftest_rows):
        status = "fail"
    else:
        status = "pass"
    return {
        "schema_version": 1,
        "mode": "selftest",
        "status": status,
        "fixture": fixture.name,
        "fixture_sha256": actual_hash,
        "observed_counts": {k: observed[k] for k in
                            ("lines_read", "alerts_read", "malformed", "groups", "queued")},
        "checks": selftest_rows,
    }


def _emit(output: str, out: str | None) -> None:
    """Write output as exact UTF-8 bytes, with no platform newline translation."""
    data = output.encode("utf-8")
    if out:
        Path(out).write_bytes(data)
        return
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(output)  # captured stdout (e.g. StringIO) has no buffer
    else:
        buffer.write(data)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Wazuh alert bridge for Sentinel")
    p.add_argument("--count", type=int, default=200, help="last N alerts to read")
    p.add_argument("--threshold", type=int, default=7, help="minimum rule level")
    p.add_argument("--input", help="read alerts from a local UTF-8 file instead of the WSL tail")
    p.add_argument("--out",
                   help="write output to a file instead of stdout (default: wazuh_queue.json for the JSON report)")
    p.add_argument("--checks", action="store_true",
                   help="emit only the per-check confirmation worksheet as CSV (check,status,detail)")
    p.add_argument("--max-age-days", type=_positive_days, default=None,
                   help="fail closed (exit 2) when the newest alert is older than this many days")
    p.add_argument("--selftest", action="store_true",
                   help="validate the pipeline against the committed ground-truth fixture (exit 0/1/2)")
    args = p.parse_args(argv)
    if args.selftest:
        st = selftest(Path(__file__).resolve().parent)
        _emit(json.dumps(st, indent=2) + "\n", args.out)
        return {"pass": 0, "fail": 1, "error": 2}[st["status"]]
    out_path = args.out if args.out is not None else "wazuh_queue.json"
    read = fetch(args.count, args.input)
    if not read["ok"]:
        result = {"generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                  "alerts_read": 0, "threshold": args.threshold, "groups": 0, "queue": [],
                  "read_ok": False, "read_error": read["error"],
                  "lines_read": 0, "malformed": 0}
        result["checks"] = checks(result)
        if args.checks:
            _emit(checks_csv(result["checks"]), args.out)
        else:
            Path(out_path).write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
            _emit(json.dumps({"error": read["error"], "out": out_path}, indent=2) + "\n", None)
        return 2
    rows, malformed = parse_lines(read["raw"])
    result = triage(rows, args.threshold)
    result.update({"read_ok": True, "read_error": "", "lines_read": len(read["raw"]),
                   "malformed": malformed})
    breached = False
    if args.max_age_days is not None:
        f = freshness(rows, args.max_age_days)
        breached = f["breach"]
        result["freshness"] = f
        result["newest_alert_timestamp"] = f["newest"]
        result["newest_alert_age_days"] = f["age_days"]
    result["checks"] = checks(result)
    if args.checks:
        _emit(checks_csv(result["checks"]), args.out)
    else:
        Path(out_path).write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
        summary = {"alerts_read": result["alerts_read"], "groups": result["groups"],
                   "queued": len(result["queue"]), "out": out_path}
        if args.max_age_days is not None:
            summary["freshness"] = result["freshness"]["status"]
        _emit(json.dumps(summary, indent=2) + "\n", None)
    return 2 if breached else 0


if __name__ == "__main__":
    raise SystemExit(main())
