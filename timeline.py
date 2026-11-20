#!/usr/bin/env python3
"""Group timestamped events into sessions by source, with gap and dwell checks."""
from __future__ import annotations

import argparse
import csv
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
    args = p.parse_args(argv)
    rows = []
    for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    result = sessions(rows, args.gap, args.max_span)
    output = (prioritize_csv(result) if args.prioritize
              else json.dumps(result, indent=2) + "\n")
    _emit(output, args.out)
    return 1 if any(g["long_dwell"] for g in result["groups"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
