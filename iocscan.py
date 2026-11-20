#!/usr/bin/env python3
"""Extract typed observables from text, dedupe them, and suppress private ranges."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
import sys
from pathlib import Path

PATTERNS = {
    "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
}
RESERVED = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
             "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4")]


def private(value: str) -> bool:
    try:
        return any(ipaddress.ip_address(value) in net for net in RESERVED)
    except ValueError:
        return False


def scan(text: str, expected: int | None = None) -> dict:
    hits = {}
    raw_matches = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        for kind, pat in PATTERNS.items():
            for value in pat.findall(line):
                raw_matches += 1
                value = value.lower()
                if kind == "ipv4" and private(value):
                    continue
                hits.setdefault((kind, value), []).append(line_no)
    findings = [{"type": k, "value": v, "lines": sorted(lines)}
                for (k, v), lines in sorted(hits.items())]
    result = {"schema_version": 1, "count": len(findings), "findings": findings}
    # A source may state how many observables it produced. Parsing fewer than
    # that is truncated evidence, not a clean result: a partial capture must
    # never be reported as "no observables of interest". Raw pattern hits are
    # counted before private suppression and dedup, so those transformations
    # cannot be mistaken for a short export. Pending is never clean.
    if expected is not None:
        incomplete = raw_matches < expected
        result["expected"] = expected
        result["raw_matches"] = raw_matches
        result["status"] = "incomplete" if incomplete else "complete"
        if incomplete:
            result["reason"] = (
                f"parsed {raw_matches} observable(s) of claimed {expected}; "
                "truncated evidence is never clean")
    return result


def source_manifest(path: str | Path, data: bytes | None = None) -> dict:
    """Record provenance for the exact bytes the observables were read from.

    Mirrors timeline.py's source-files worksheet so both tools in this repo
    share one provenance shape: name, byte size, non-blank line count and
    SHA-256 let a reviewer tie findings back to the input they came from.
    The source is read only; nothing is rewritten or decorated with a verdict.
    When ``data`` is supplied the caller's single read is reused, so the hash
    always covers the same bytes that were scanned.
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


def prioritize_csv(findings: list) -> str:
    """Render typed observables as a triage CSV.

    Column contract: type, value, line -- one row per (type, value, line)
    occurrence. Findings arrive sorted by (type, value) and their ``lines``
    sorted ascending, so the rows are deterministic. Emitting one row per line
    preserves where each observable appeared after deduplication. An LF
    terminator and a trailing newline keep the bytes stable, so a committed
    triage CSV changes only when the observables change, not with the host.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("type", "value", "line"))
    for finding in findings:
        for line in finding["lines"]:
            writer.writerow((finding["type"], finding["value"], line))
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
    p = argparse.ArgumentParser(description="IOC normalizer with private-range suppression")
    p.add_argument("file")
    p.add_argument("--out")
    p.add_argument("--expect", type=int, default=None,
                   help="observables the source claims; a shorter parse is incomplete (exit 2)")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only the typed observables as triage CSV (type,value,line)")
    args = p.parse_args(argv)
    if args.expect is not None and args.expect < 0:
        result = {"schema_version": 1, "count": 0, "findings": [],
                  "expected": args.expect, "status": "incomplete",
                  "reason": "--expect must be a non-negative integer"}
    else:
        try:
            data = Path(args.file).read_bytes()
        except OSError as e:
            result = {"schema_version": 1, "count": 0, "findings": [],
                      "status": "incomplete",
                      "reason": f"input error: {type(e).__name__}: {str(e)[:160]}"}
        else:
            text = data.decode("utf-8", errors="replace")
            result = scan(text, expected=args.expect)
            result["source_files"] = [source_manifest(args.file, data)]
    output = (prioritize_csv(result["findings"]) if args.prioritize
              else json.dumps(result, indent=2) + "\n")
    _emit(output, args.out)
    if result.get("status") == "incomplete":
        return 2
    return 1 if result["count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
