#!/usr/bin/env python3
"""Sentinel: one entry point for the 69 focused security checks.

Teams: blue, red, yellow, appsec, devops. Stdlib only, no network, read-only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = HERE / "rules"
TEAMS = json.loads((HERE / "teams.json").read_text(encoding="utf-8"))
SCHEMA = 1

# A no-argument invocation is a discovery aid, not a usage error: show the most
# common commands the way a network scanner prints its common options when run
# bare. File-based runs and argument errors keep their existing exit contract.
QUICKSTART = """Sentinel: focused security checks by team (read-only, local file, stdlib only, no network).

No file was given. The most common commands are:

  python sentinel.py --list --team blue                      List tools for a team
  python sentinel.py --team appsec sample.txt                Run a team's checks on a file
  python sentinel.py --tool headerscheck sample.txt          Run a single tool
  python sentinel.py --team blue alerts.json --out r.json    Save the JSON envelope
  python sentinel.py --team blue alerts.json --prioritize    Emit the triage CSV
  python sentinel.py --team blue alerts.json --checks        Emit the checks worksheet

Exit status is the CI contract: 0 clean, 1 findings or a tool error, 2 a usage error.
Run 'python sentinel.py --help' for every option.
"""

# Every finding kind maps to an explicit severity bucket so the report can lead
# with the tool that needs attention first. Unknown kinds fall back to "info"
# (a documented default, never a silent promotion to high). A tool that failed
# to run is "indeterminate" and outranks everything: unknown risk is never last.
SEVERITY = {
    "hash_mismatch": "critical",
    "tool_not_allowed": "critical",
    "missing_evidence": "high",
    "expired_authorization": "high",
    "missing_authorization": "high",
    "forbidden_value": "high",
    "disallowed": "high",
    "invalid_state": "medium",
    "unresolved_state": "medium",
    "missing_column": "medium",
    "header_mismatch": "medium",
    "size_mismatch": "low",
    "missing_field": "low",
    "missing_header": "low",
    "pattern": "info",
    "sha256": "info",
    "header": "info",
}
DEFAULT_SEVERITY = "info"
BUCKETS = ("indeterminate", "critical", "high", "medium", "low", "info", "clear")
RANK = {name: i for i, name in enumerate(BUCKETS)}  # lower index = higher priority
MUST_FIX = frozenset(("indeterminate", "critical", "high", "medium", "low"))


def severity_of(kind: str) -> str:
    return SEVERITY.get(kind, DEFAULT_SEVERITY)


def tool_severity(result: dict) -> str:
    if result.get("error"):
        return "indeterminate"
    findings = result.get("findings") or []
    if not findings:
        return "clear"
    return min((severity_of(f.get("kind", "")) for f in findings), key=lambda b: RANK[b])


def _ranked(results: list) -> list:
    """Return (severity, result) pairs ordered by risk, then count, then name."""
    pairs = [(tool_severity(r), r) for r in results]
    pairs.sort(key=lambda pair: (RANK[pair[0]], -pair[1].get("count", 0), pair[1]["tool"]))
    return pairs


def prioritized(results: list) -> list:
    return [
        {"tool": r["tool"], "severity": sev, "count": r.get("count", 0),
         "must_fix": sev in MUST_FIX}
        for sev, r in _ranked(results)
    ]


def prioritize_csv(rows: list) -> str:
    """Render the prioritized 'where to start' list as a triage CSV.

    Column contract: tool, severity, count, must_fix -- one row per tool, in
    prioritized order. must_fix is lowercase true/false so any consumer can
    parse it without a special case. An LF terminator and a trailing newline
    keep the bytes deterministic across platforms.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("tool", "severity", "count", "must_fix"))
    for row in rows:
        writer.writerow((row["tool"], row["severity"], row["count"],
                         "true" if row["must_fix"] else "false"))
    return buf.getvalue()


def tools() -> list:
    """Return every configured tool name, sorted, regardless of any filter."""
    return sorted(f.stem for f in RULES.glob("*.json"))


# Closed per-check confirmation vocabulary, borrowed from the TCP handshake
# checker pattern where each step shows matched True/False and False honestly
# means "the capture did not confirm that step" rather than a hard failure.
#   confirmed    - the check ran and produced a result (findings, possibly zero)
#   not_confirmed - it ran but errored, so no result could be confirmed
#   skipped      - it was not selected by --tool/--team
# not_confirmed is never clean: an errored check is indeterminate in the risk
# ranking, so "no result" can never masquerade as "no findings".
CHECK_STATUSES = ("confirmed", "not_confirmed", "skipped")


def checks(all_tools: list, results: list) -> list:
    """Return a confirmation worksheet with one row per configured tool.

    Every tool gets a row, including ones that did not run: a skipped check is
    recorded, never dropped, so a reader can tell "no findings" from "not
    checked". ``findings`` is the integer count only for a confirmed check and
    None otherwise, so a zero count cannot be confused with an errored or
    skipped check. A confirmed zero means "no findings detected by this check",
    not "no risk" - confirmation is about evidence, not absolution.
    """
    by_name = {r["tool"]: r for r in results}
    rows = []
    for name in sorted(all_tools):
        result = by_name.get(name)
        if result is None:
            rows.append({"tool": name, "status": "skipped", "findings": None})
        elif result.get("error"):
            rows.append({"tool": name, "status": "not_confirmed", "findings": None})
        else:
            rows.append({"tool": name, "status": "confirmed",
                         "findings": result.get("count", 0)})
    return rows


def checks_csv(rows: list) -> str:
    """Render the confirmation worksheet as a byte-stable CSV.

    Column contract: tool,status,findings -- one row per configured tool, in
    tool-name order. ``status`` is from the closed CHECK_STATUSES vocabulary;
    ``findings`` is the integer count for a confirmed check and empty otherwise.
    An LF terminator and trailing newline keep bytes stable across platforms,
    so a committed worksheet changes only when the checks change.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("tool", "status", "findings"))
    for row in rows:
        writer.writerow((row["tool"], row["status"],
                         row["findings"] if row["findings"] is not None else ""))
    return buf.getvalue()


def source_manifest(path: str | Path, data: bytes | None = None) -> dict:
    """Record provenance for the exact bytes the checks were built from.

    Detection and remediation are deliberately separate stages: this scanner
    detects, while ``releasegate.py`` decides allow/deny. They share one
    provenance contract so a verdict can always be traced back to the exact
    bytes detection read - the "detect here, remedy there" separation still
    leaves one traceable decision layer. ``source_files`` uses the same shape
    as ``timeline.py``, ``iocscan.py`` and ``releasegate.py``: name, byte size,
    non-blank line count and SHA-256. The source is read only; a check never
    modifies it or adds a maliciousness verdict.

    When ``data`` is supplied the caller's single read is reused, so the hash
    always covers the same bytes that were checked. A hash establishes
    consistency between a report and its input, not authenticity, completeness
    or causation.
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


def _emit(output: str, out: str | None) -> None:
    """Write output as exact UTF-8 bytes, with no platform newline translation.

    A triage CSV may be committed as an audit artifact; stable bytes keep a
    rerun from producing a spurious diff on a different host.
    """
    data = output.encode("utf-8")
    if out:
        Path(out).write_bytes(data)
        return
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(output)  # captured stdout (e.g. StringIO) has no buffer
    else:
        buffer.write(data)


def has_key(obj, key: str) -> bool:
    if isinstance(obj, dict):
        return key in obj or any(has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(has_key(v, key) for v in obj)
    return False


def check(text: str, rules: dict, path: Path) -> list:
    kind, out = rules["type"], []
    if kind == "headers":
        headers = {}
        for line in text.splitlines():
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                headers.setdefault(k.strip().lower(), []).append(v.strip())
        for req in rules.get("required", []):
            if req.lower() not in headers:
                out.append({"kind": "missing_header", "value": req})
        for h, pat in rules.get("patterns", {}).items():
            for v in headers.get(h.lower(), []):
                if not re.search(pat, v, re.I):
                    out.append({"kind": "header_mismatch", "value": h})
        for h, pat in rules.get("forbidden", {}).items():
            for v in headers.get(h.lower(), []):
                if re.search(pat, v, re.I):
                    out.append({"kind": "forbidden_value", "value": h})
    elif kind == "regex":
        for pat in rules["patterns"]:
            for m in re.finditer(pat, text, re.I | re.M):
                out.append({"kind": "pattern", "value": m.group(0)[:120]})
    elif kind == "jsonfields":
        try:
            obj = json.loads(text)
            items = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError:
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        for item in items:
            for key in rules["required"]:
                if key not in item:
                    out.append({"kind": "missing_field", "value": key})
            for key, allowed in rules.get("allowed", {}).items():
                if key in item and item[key] not in allowed:
                    out.append({"kind": "disallowed", "value": str(item[key])})
            for key, forbidden in rules.get("forbidden_values", {}).items():
                if str(item.get(key)) == forbidden:
                    out.append({"kind": "forbidden_value", "value": key})
    elif kind == "csvcols":
        reader = csv.DictReader(io.StringIO(text))
        cols = set(reader.fieldnames or [])
        for key in rules["required"]:
            if key not in cols:
                out.append({"kind": "missing_column", "value": key})
        if rules.get("verify_sha256") and {"path", "sha256"} <= cols:
            for row in reader:
                target = (path.parent / row["path"]).resolve()
                if not target.is_file():
                    out.append({"kind": "missing_evidence", "value": row["path"]})
                    continue
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if actual != row["sha256"].strip().lower():
                    out.append({"kind": "hash_mismatch", "value": row["path"]})
                if rules.get("verify_size") and "size" in cols:
                    if str(target.stat().st_size) != str(row["size"]).strip():
                        out.append({"kind": "size_mismatch", "value": row["path"]})
    elif kind == "hash":
        out.append({"kind": "sha256", "value": hashlib.sha256(path.read_bytes()).hexdigest()})
        for line in text.splitlines():
            if re.match(r"^(From|To|Subject|Received):", line, re.I):
                out.append({"kind": "header", "value": line[:160]})
    elif kind == "states":
        obj = json.loads(text)
        state = obj.get("state") if isinstance(obj, dict) else None
        if state not in rules["states"]:
            out.append({"kind": "invalid_state", "value": str(state)})
        for key in rules.get("required", []):
            if not has_key(obj, key):
                out.append({"kind": "missing_evidence", "value": key})
        if rules.get("terminal_states") and state not in rules["terminal_states"]:
            out.append({"kind": "unresolved_state", "value": str(state)})
    elif kind == "allowlist":
        obj = json.loads(text)
        name = obj.get("tool") if isinstance(obj, dict) else None
        if name not in rules["allowed"]:
            out.append({"kind": "tool_not_allowed", "value": str(name)})
        if rules.get("require_authorization"):
            today = datetime.now(timezone.utc).date().isoformat()
            for key in ("scope_ref", "approver", "expires_at"):
                if not has_key(obj, key):
                    out.append({"kind": "missing_authorization", "value": key})
            expires = obj.get("expires_at") if isinstance(obj, dict) else None
            if expires and str(expires) < today:
                out.append({"kind": "expired_authorization", "value": str(expires)})
    else:
        raise ValueError("unknown rule type: " + kind)
    return out


def run(path: Path, team: str | None, tool: str | None) -> dict:
    # One byte read feeds both the checks and the provenance hash, so the
    # manifest always describes exactly the bytes that were analyzed.
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    results = []
    for f in sorted(RULES.glob("*.json")):
        name = f.stem
        if tool and name != tool:
            continue
        if team and team not in TEAMS.get(name, []):
            continue
        rules = json.loads(f.read_text(encoding="utf-8"))
        try:
            findings = check(text, rules, path)
            results.append({"tool": name, "count": len(findings), "findings": findings})
        except Exception as e:
            results.append({"tool": name, "error": f"{type(e).__name__}: {str(e)[:120]}"})
    ranked = _ranked(results)
    result = {
        "schema_version": SCHEMA,
        "team": team or "all",
        "input": str(path),
        "results": [r for _, r in ranked],
        "prioritized": prioritized(results),
        "checks": checks(tools(), results),
        "severity": {
            "buckets": list(BUCKETS),
            "kind_map": SEVERITY,
            "default": DEFAULT_SEVERITY,
            "must_fix": sorted(MUST_FIX),
        },
        "source_files": [source_manifest(path, data)],
    }
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Sentinel: focused security checks by team")
    p.add_argument("file", nargs="?", help="local file to analyze")
    p.add_argument("--team", choices=("blue", "red", "yellow", "appsec", "devops"))
    p.add_argument("--tool", help="run one tool by name")
    p.add_argument("--list", action="store_true", help="list tools for the selected team")
    p.add_argument("--out", help="write the JSON envelope to a file instead of stdout")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only the prioritized 'where to start' list as triage CSV")
    p.add_argument("--checks", action="store_true",
                   help="emit only the per-check confirmation worksheet as CSV (tool,status,findings)")
    args = p.parse_args(argv)
    supplied = list(sys.argv[1:] if argv is None else argv)
    if args.list:
        names = [n for n in sorted(TEAMS) if not args.team or args.team in TEAMS[n]]
        print("\n".join(names))
        return 0
    if not args.file:
        if not supplied:
            _emit(QUICKSTART, None)
            return 0
        p.error("file is required unless --list is used")
    doc = run(Path(args.file), args.team, args.tool)
    if args.prioritize:
        output = prioritize_csv(doc["prioritized"])
    elif args.checks:
        output = checks_csv(doc["checks"])
    else:
        output = json.dumps(doc, indent=2) + "\n"
    _emit(output, args.out)
    bad = any(r.get("count", 1 if r.get("error") else 0) for r in doc["results"])
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
