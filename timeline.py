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
    p.add_argument("file")
    p.add_argument("--gap", type=int, default=900, help="seconds before a new session starts")
    p.add_argument("--max-span", type=int, default=3600)
    p.add_argument("--out", help="write output to a file instead of stdout")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only session summaries as review CSV (session,source,event_count,long_dwell)")
    p.add_argument("--checks", action="store_true",
                   help="emit only the per-check confirmation worksheet as CSV (check,status,detail)")
    p.add_argument("--coverage", action="store_true",
                   help="report the observed event window and add a coverage check")
    args = p.parse_args(argv)
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
