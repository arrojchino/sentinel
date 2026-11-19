#!/usr/bin/env python3
"""Group timestamped events into sessions by source, with gap and dwell checks."""
from __future__ import annotations

import argparse
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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Event timeline correlation")
    p.add_argument("file")
    p.add_argument("--gap", type=int, default=900, help="seconds before a new session starts")
    p.add_argument("--max-span", type=int, default=3600)
    args = p.parse_args(argv)
    rows = []
    for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    result = sessions(rows, args.gap, args.max_span)
    print(json.dumps(result, indent=2))
    return 1 if any(g["long_dwell"] for g in result["groups"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
