#!/usr/bin/env python3
"""Group timestamped events into sessions by source, with gap and dwell checks."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from datetime import datetime
from pathlib import Path


def parse_ts(value: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError("unparsed timestamp: " + value)


def sessions(rows: list[dict], gap_seconds: int, max_span_seconds: int) -> dict:
    ordered = []
    for row in rows:
        try:
            ordered.append((parse_ts(row["timestamp"]), row))
        except (KeyError, ValueError):
            continue
    ordered.sort(key=lambda x: x[0])
    groups = []
    for ts, row in ordered:
        source = str(row.get("source", row.get("srcip", "-")))
        if groups and groups[-1]["source"] == source and (ts - groups[-1]["last"]).total_seconds() <= gap_seconds:
            groups[-1]["events"] += 1
            groups[-1]["last"] = ts
        else:
            groups.append({"source": source, "events": 1, "first": ts, "last": ts})
    for g in groups:
        span = (g["last"] - g["first"]).total_seconds()
        g["span_seconds"] = int(span)
        g["long_dwell"] = span > max_span_seconds
        g["first"] = g["first"].isoformat()
        g["last"] = g["last"].isoformat()
    return {"schema_version": 1, "sessions": len(groups), "groups": groups}


def observation_window(rows: list[dict]) -> dict:
    """Describe the window the timeline actually observed.

    A zero long-dwell count is only meaningful beside the span of events that
    produced it. This returns the oldest and newest parseable timestamps and
    the whole-second span between them; a single event has a zero span. With no
    parseable event it returns null fields rather than a fabricated window.
    Rows with a missing or unparseable timestamp are ignored, matching the
    grouping rule in :func:`sessions`.
    """
    stamps = []
    for row in rows:
        try:
            stamps.append(parse_ts(row["timestamp"]))
        except (KeyError, ValueError):
            continue
    if not stamps:
        return {"oldest_event": None, "newest_event": None,
                "observation_span_seconds": None}
    oldest, newest = min(stamps), max(stamps)
    return {
        "oldest_event": oldest.isoformat(),
        "newest_event": newest.isoformat(),
        "observation_span_seconds": int((newest - oldest).total_seconds()),
    }


def prioritize_csv(result: dict) -> str:
    """Render session summaries as a byte-stable review handoff CSV.

    Column contract: session, source, event_count, long_dwell -- one row per
    session, in the same deterministic chronological order as the JSON groups.
    ``session`` is the 1-based position; ``long_dwell`` is a lowercase boolean
    marking a session that exceeded the span limit and needs analyst review.

    Every session is emitted. A flagged dwell is listed for review, never
    dropped, so the handoff is a complete view of the grouped evidence rather
    than a filtered one. An LF terminator and a trailing newline keep the bytes
    stable, so a committed handoff changes only when the sessions change and
    never picks up a platform newline diff.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("session", "source", "event_count", "long_dwell"))
    for index, group in enumerate(result["groups"], 1):
        writer.writerow((index, group["source"], group["events"],
                         "true" if group["long_dwell"] else "false"))
    return buf.getvalue()


def source_manifest(path: str | Path, data: bytes | None = None) -> dict:
    """Record provenance for the exact bytes a timeline was built from.

    Mirrors a source-files worksheet: name, byte size, non-blank line count
    and SHA-256 let a reviewer tie the grouping back to the input it read.
    The source is read only; nothing is rewritten or decorated with a verdict.
    When ``data`` is supplied the caller's single read is reused, so the hash
    always covers the same bytes that were parsed.
    """
    p = Path(path)
    if data is None:
        data = p.read_bytes()
    text = data.decode("utf-8", errors="replace")
    return {
        "name": p.name,
        "bytes": len(data),
        "lines": sum(1 for line in text.splitlines() if line.strip()),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# Closed per-check confirmation vocabulary shared by the sentinel tools.
#   confirmed    - the check ran and produced a result (possibly zero findings)
#   not_confirmed - its input could not be read or trusted (never clean)
#   skipped      - it did not apply to this grouping
# A confirmed zero means "nothing detected by this check", not "no risk".
CHECK_STATUSES = ("confirmed", "not_confirmed", "skipped")


def _check(name: str, status: str, detail: str = "") -> dict:
    """Build one confirmation row with a closed status and a short detail."""
    if status not in CHECK_STATUSES:
        raise ValueError(f"unknown check status: {status}")
    return {"check": name, "status": status, "detail": detail}


def checks(result: dict) -> list:
    """Return a per-check confirmation worksheet for one timeline, in order.

    The three checks mirror iocscan.py and releasegate.py so every sentinel
    tool exposes one evidence-confirmation contract: a check that ran is
    confirmed, one whose bytes were never read is not_confirmed, and one that
    did not apply is skipped. A readable input (``source_files``) is what
    makes ``parse`` confirmed. ``detail`` is a short fact: a count for a
    confirmed check and why a check was skipped. Grouping adds no verdict: a
    confirmed zero long-dwell sessions is not a claim that no risk exists.

    When an observation window is present (``--coverage``), a fourth
    ``coverage`` check states the newest event and span the count was taken
    over, so a zero is never reported without its boundary.
    """
    readable = bool(result.get("source_files"))
    long_dwells = sum(1 for g in result.get("groups", []) if g.get("long_dwell"))
    rows = [
        _check("parse", "confirmed" if readable else "not_confirmed",
               f"{result.get('sessions', 0)} sessions" if readable
               else "input unreadable"),
        _check("dwell", "confirmed", f"{long_dwells} long dwell(s)"),
        _check("provenance", "confirmed" if readable else "skipped",
               result["source_files"][0]["sha256"] if readable else "no readable input"),
    ]
    if "newest_event" in result:
        newest = result.get("newest_event")
        span = result.get("observation_span_seconds")
        if not readable:
            rows.append(_check("coverage", "skipped", "no readable input"))
        elif newest is None:
            rows.append(_check("coverage", "not_confirmed",
                               "no parseable event timestamp"))
        else:
            rows.append(_check("coverage", "confirmed",
                               f"newest {newest}; span {span}s"))
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


# Selftest statuses are deliberately distinct from CHECK_STATUSES: a
# ground-truth check answers "does the grouping engine still match its known
# answer", not "did this check confirm a step on this input". The same engine
# feeds every front-end (JSON, --prioritize, --checks), so one fixed answer
# guards all of them at once.
SELFTEST_STATUSES = ("pass", "fail", "error", "skipped")


def _selftest_check(name: str, status: str, detail: str = "") -> dict:
    if status not in SELFTEST_STATUSES:
        raise ValueError(f"unknown selftest status: {status}")
    return {"check": name, "status": status, "detail": detail}


def _group_tuple(group: dict) -> tuple:
    """Normalize one group to the fields the ground truth pins.

    Grouping, event counts, spans and long-dwell flags are compared exactly;
    first/last timestamps are not part of the contract because the pinned
    fixture hash already guarantees the exact input bytes behind them.
    """
    return (str(group.get("source", "-")), int(group.get("events", 0)),
            int(group.get("span_seconds", 0)), bool(group.get("long_dwell", False)))


def selftest(base: str | Path | None = None) -> dict:
    """Validate session grouping against a committed ground-truth fixture.

    The study target ships one decompiler engine behind several front-ends,
    all consuming the same core. This tool likewise exposes one grouping
    engine through JSON, a triage CSV and a confirmation worksheet; a single
    known input plus its expected sessions guards every front-end against a
    silent regression. ``timeline_fixture.jsonl`` is the known event stream and
    ``timeline_expect.json`` records the sessions it must produce. The check
    reports a coverage regression, not a risk verdict. ``status`` is pass (all
    expectations met), fail (a regression) or error (input unreadable, which
    is fail-closed and never counted as a pass).
    """
    base = Path(base) if base is not None else Path(__file__).resolve().parent
    fixture = base / "timeline_fixture.txt"
    expect_path = base / "timeline_expect.json"
    checks: list = []
    try:
        data = fixture.read_bytes()
    except OSError as e:
        checks.append(_selftest_check("fixture", "error",
                                      f"unreadable: {type(e).__name__}"))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "checks": checks}
    checks.append(_selftest_check("fixture", "pass", f"{len(data)} bytes"))
    try:
        expectation = json.loads(expect_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        checks.append(_selftest_check("expectation", "error",
                                      f"unreadable: {type(e).__name__}"))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "checks": checks}
    checks.append(_selftest_check("expectation", "pass", "ground truth loaded"))

    actual_hash = hashlib.sha256(data).hexdigest()
    pinned = expectation.get("fixture_sha256")
    if pinned:
        matched = pinned == actual_hash
        checks.append(_selftest_check(
            "fixture_hash", "pass" if matched else "fail",
            "bytes match the pinned answer" if matched
            else f"drift: expected {pinned}, got {actual_hash}"))
    else:
        checks.append(_selftest_check("fixture_hash", "skipped", "no pinned hash"))

    text = data.decode("utf-8", errors="replace")
    try:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    except ValueError as e:
        checks.append(_selftest_check("parse", "error", f"invalid JSON: {type(e).__name__}"))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "fixture_sha256": actual_hash,
                "checks": checks}
    checks.append(_selftest_check("parse", "pass", f"{len(rows)} event(s)"))

    gap = expectation.get("gap_seconds", 900)
    max_span = expectation.get("max_span_seconds", 3600)
    result = sessions(rows, gap, max_span)

    exp_sessions = expectation.get("sessions")
    if isinstance(exp_sessions, int):
        ok = exp_sessions == result["sessions"]
        checks.append(_selftest_check(
            "sessions", "pass" if ok else "fail",
            f"{result['sessions']} observed of {exp_sessions} expected"))
    else:
        checks.append(_selftest_check("sessions", "skipped", "no expected count"))

    observed_long = sum(1 for g in result["groups"] if g["long_dwell"])
    exp_long = expectation.get("long_dwell")
    if isinstance(exp_long, int):
        ok = exp_long == observed_long
        checks.append(_selftest_check(
            "long_dwell", "pass" if ok else "fail",
            f"{observed_long} observed of {exp_long} expected"))
    else:
        checks.append(_selftest_check("long_dwell", "skipped", "no expected count"))

    expected_groups = [_group_tuple(g) for g in expectation.get("groups", [])]
    actual_groups = [_group_tuple(g) for g in result["groups"]]
    if expected_groups and expected_groups == actual_groups:
        checks.append(_selftest_check("groups", "pass", "exact match"))
    else:
        checks.append(_selftest_check(
            "groups", "fail",
            f"expected {len(expected_groups)} group(s), got {len(actual_groups)}"))

    if any(c["status"] == "error" for c in checks):
        status = "error"
    elif any(c["status"] == "fail" for c in checks):
        status = "fail"
    else:
        status = "pass"
    return {
        "schema_version": 1,
        "mode": "selftest",
        "status": status,
        "fixture": fixture.name,
        "fixture_sha256": actual_hash,
        "gap_seconds": gap,
        "max_span_seconds": max_span,
        "expected_sessions": exp_sessions,
        "observed_sessions": result["sessions"],
        "checks": checks,
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
    p = argparse.ArgumentParser(description="Event timeline correlation")
    p.add_argument("file", nargs="?")
    p.add_argument("--gap", type=int, default=900, help="seconds before a new session starts")
    p.add_argument("--max-span", type=int, default=3600)
    p.add_argument("--out", help="write output to a file instead of stdout")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only session summaries as review CSV (session,source,event_count,long_dwell)")
    p.add_argument("--checks", action="store_true",
                   help="emit only the per-check confirmation worksheet as CSV (check,status,detail)")
    p.add_argument("--coverage", action="store_true",
                   help="report the observed event window and add a coverage check")
    p.add_argument("--selftest", action="store_true",
                   help="validate grouping against the committed ground-truth fixture (exit 0/1/2)")
    args = p.parse_args(argv)
    if args.selftest:
        st = selftest(Path(__file__).resolve().parent)
        _emit(json.dumps(st, indent=2) + "\n", args.out)
        return {"pass": 0, "fail": 1, "error": 2}[st["status"]]
    if args.file is None:
        p.error("file is required unless --selftest is given")
    data = Path(args.file).read_bytes()
    text = data.decode("utf-8", errors="replace")
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    result = sessions(rows, args.gap, args.max_span)
    if args.coverage:
        result.update(observation_window(rows))
    result["source_files"] = [source_manifest(args.file, data)]
    result["checks"] = checks(result)
    output = (prioritize_csv(result) if args.prioritize
              else checks_csv(result["checks"]) if args.checks
              else json.dumps(result, indent=2) + "\n")
    _emit(output, args.out)
    return 1 if any(g["long_dwell"] for g in result["groups"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
