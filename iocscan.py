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


# Closed per-check confirmation vocabulary shared by the sentinel tools.
#   confirmed    - the check ran and produced a result (possibly zero findings)
#   not_confirmed - its input could not be read or trusted (never clean)
#   skipped      - it did not apply to this scan
# A confirmed zero means "nothing detected by this check", not "no risk".
CHECK_STATUSES = ("confirmed", "not_confirmed", "skipped")


def _check(name: str, status: str, detail: str = "") -> dict:
    """Build one confirmation row with a closed status and a short detail."""
    if status not in CHECK_STATUSES:
        raise ValueError(f"unknown check status: {status}")
    return {"check": name, "status": status, "detail": detail}


def checks(result: dict) -> list:
    """Return a per-check confirmation worksheet for one scan, in fixed order.

    Every scan reports the same checks so a reader can tell a check that ran
    (confirmed) from one that did not apply (skipped) or whose input could not
    be trusted (not_confirmed). A ``source_files`` entry proves the single byte
    read succeeded, which is what makes ``parse`` confirmed; without it the
    scan never saw trustworthy bytes. ``detail`` is a short fact: a count for
    a confirmed check, a reason for a not_confirmed one, and why a check was
    skipped. The worksheet adds no maliciousness verdict to the observables.
    """
    readable = bool(result.get("source_files"))
    rows = [
        _check("parse",
               "confirmed" if readable else "not_confirmed",
               (f"{result['count']} observables" if readable
                else result.get("reason", "input unreadable"))),
    ]
    if "expected" not in result:
        rows.append(_check("completeness", "skipped", "no claimed total"))
    elif result.get("status") == "incomplete":
        rows.append(_check("completeness", "not_confirmed",
                           f"parsed {result.get('raw_matches', 0)} of {result['expected']}"))
    else:
        rows.append(_check("completeness", "confirmed",
                           f"{result.get('raw_matches', 0)} of {result['expected']}"))
    rows.append(
        _check("provenance", "confirmed" if readable else "skipped",
               result["source_files"][0]["sha256"] if readable else "no readable input"))
    return rows


def checks_csv(rows: list) -> str:
    """Render the confirmation worksheet as a byte-stable CSV.

    Column contract: check,status,detail -- one row per check in the fixed
    order returned by :func:`checks`. ``status`` is from the closed
    CHECK_STATUSES vocabulary; ``detail`` is a short fact or reason (a skipped
    check still states why it did not apply). An LF terminator and trailing
    newline keep the bytes stable across platforms, so a committed worksheet
    changes only when the checks change.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("check", "status", "detail"))
    for row in rows:
        writer.writerow((row["check"], row["status"], row.get("detail", "")))
    return buf.getvalue()


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


# Selftest statuses are deliberately distinct from CHECK_STATUSES: a
# ground-truth check answers "does the detector still match its known answer",
# not "did this input confirm a step".
SELFTEST_STATUSES = ("pass", "fail", "error", "skipped")


def _selftest_check(name: str, status: str, detail: str = "") -> dict:
    if status not in SELFTEST_STATUSES:
        raise ValueError(f"unknown selftest status: {status}")
    return {"check": name, "status": status, "detail": detail}


def _observable_set(findings: list) -> set:
    """Normalize findings to (type, value, tuple(lines)) for exact comparison."""
    return {(f["type"], f["value"], tuple(f["lines"])) for f in findings}


def selftest(base: str | Path | None = None) -> dict:
    """Validate detector coverage against a committed ground-truth fixture.

    The study target ships a deliberately vulnerable app together with its
    known scan results, so a scanner can be checked against a fixed answer.
    This tool ships the same shape: ``ioc_fixture.txt`` is a known input and
    ``ioc_expect.json`` records the observables it must produce. The check
    compares the detector's current output to that answer; it reports a
    coverage regression rather than a risk verdict. ``status`` is pass (all
    expectations met), fail (a regression) or error (input unreadable, which
    is fail-closed and never counted as a pass).
    """
    base = Path(base) if base is not None else Path(__file__).resolve().parent
    fixture = base / "ioc_fixture.txt"
    expect_path = base / "ioc_expect.json"
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

    result = scan(data.decode("utf-8", errors="replace"))
    expected_findings = expectation.get("findings", [])
    exp_count = expectation.get("count")
    if isinstance(exp_count, int):
        ok = exp_count == result["count"]
        checks.append(_selftest_check(
            "count", "pass" if ok else "fail",
            f"{result['count']} observed of {exp_count} expected"))
    missing = sorted(_observable_set(expected_findings) - _observable_set(result["findings"]))
    unexpected = sorted(_observable_set(result["findings"]) - _observable_set(expected_findings))
    if not missing and not unexpected:
        checks.append(_selftest_check("observables", "pass", "exact match"))
    else:
        detail = []
        if missing:
            detail.append(f"missing {len(missing)}")
        if unexpected:
            detail.append(f"unexpected {len(unexpected)}")
        checks.append(_selftest_check("observables", "fail", ", ".join(detail)))

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
        "expected_count": exp_count,
        "observed_count": result["count"],
        "checks": checks,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="IOC normalizer with private-range suppression")
    p.add_argument("file", nargs="?")
    p.add_argument("--out")
    p.add_argument("--expect", type=int, default=None,
                   help="observables the source claims; a shorter parse is incomplete (exit 2)")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only the typed observables as triage CSV (type,value,line)")
    p.add_argument("--checks", action="store_true",
                   help="emit only the per-check confirmation worksheet as CSV (check,status,detail)")
    p.add_argument("--selftest", action="store_true",
                   help="validate detection against the committed ground-truth fixture (exit 0/1/2)")
    args = p.parse_args(argv)
    if args.selftest:
        st = selftest(Path(__file__).resolve().parent)
        _emit(json.dumps(st, indent=2) + "\n", args.out)
        return {"pass": 0, "fail": 1, "error": 2}[st["status"]]
    if args.file is None:
        p.error("file is required unless --selftest is given")
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
    result["checks"] = checks(result)
    output = (prioritize_csv(result["findings"]) if args.prioritize
              else checks_csv(result["checks"]) if args.checks
              else json.dumps(result, indent=2) + "\n")
    _emit(output, args.out)
    if result.get("status") == "incomplete":
        return 2
    return 1 if result["count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
