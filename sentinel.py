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

# The emission inventory: the finding kinds check() can produce for each rule
# type. A report that states its own classification rules must also account
# for everything those rules can emit, so the --selftest kind-coverage check
# derives the reachable kinds from the configured rules and fails closed if
# any is absent from SEVERITY. The documented info default stays a fallback;
# coverage is what stops an undeclared kind from being absorbed by it silently.
RULE_KINDS = {
    "headers": ("missing_header", "header_mismatch", "forbidden_value"),
    "regex": ("pattern",),
    "jsonfields": ("missing_field", "disallowed", "forbidden_value"),
    "csvcols": ("missing_column", "missing_evidence", "hash_mismatch", "size_mismatch"),
    "hash": ("sha256", "header"),
    "states": ("invalid_state", "missing_evidence", "unresolved_state"),
    "allowlist": ("tool_not_allowed", "missing_authorization", "expired_authorization"),
}


def severity_contract() -> dict:
    """The documented severity contract shared by the report and the selftest.

    One definition feeds both the JSON envelope and the ground-truth check, so
    a reported map can never drift from the one the selftest pins.
    """
    return {
        "buckets": list(BUCKETS),
        "kind_map": SEVERITY,
        "default": DEFAULT_SEVERITY,
        "must_fix": sorted(MUST_FIX),
    }


def severity_of(kind: str) -> str:
    return SEVERITY.get(kind, DEFAULT_SEVERITY)


def reachable_kinds(rule_dir: str | Path | None = None) -> tuple:
    """Return ``(kinds, errors)`` derived from the configured rule files.

    Each rule's ``type`` maps through :data:`RULE_KINDS` to the kinds that
    :func:`check` can emit for it; a rule may also declare additional kinds
    in an optional ``emits`` list for local extensions. A missing rules
    directory, an unreadable or unparsable rule, or a type outside the
    inventory is an error, never an empty coverage: absent or unknown rules
    cannot prove that every reachable kind was declared.
    """
    rule_dir = Path(rule_dir) if rule_dir is not None else RULES
    if not rule_dir.is_dir():
        return set(), [f"rules directory missing: {rule_dir}"]
    files = sorted(rule_dir.glob("*.json"))
    if not files:
        return set(), [f"no rule files in {rule_dir}"]
    kinds, errors = set(), []
    for f in files:
        try:
            rules = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            errors.append(f"{f.name}: unreadable ({type(e).__name__})")
            continue
        rtype = rules.get("type") if isinstance(rules, dict) else None
        if not isinstance(rtype, str) or rtype not in RULE_KINDS:
            errors.append(f"{f.name}: unmapped rule type {rtype!r}")
            continue
        kinds.update(RULE_KINDS[rtype])
        extra = rules.get("emits", [])
        if isinstance(extra, list):
            kinds.update(k for k in extra if isinstance(k, str) and k)
    return kinds, errors


def kind_coverage(rule_dir: str | Path | None = None) -> dict:
    """Report which reachable finding kinds are declared in ``SEVERITY``.

    An ``unmapped`` kind would be absorbed by :func:`severity_of`'s info
    default; the selftest fails closed on it instead of reporting a pass,
    so adding a rule that emits a new kind cannot silently weaken the ranking.
    """
    kinds, errors = reachable_kinds(rule_dir)
    return {
        "reachable": sorted(kinds),
        "declared": sorted(k for k in kinds if k in SEVERITY),
        "unmapped": sorted(k for k in kinds if k not in SEVERITY),
        "errors": errors,
    }


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
        "severity": severity_contract(),
        "source_files": [source_manifest(path, data)],
    }
    return result


# Selftest statuses are deliberately distinct from CHECK_STATUSES: a
# ground-truth check answers "does the severity/order engine still match its
# known answer", not "did this check confirm a step on this input". The same
# severity contract and ranking feed the JSON envelope, --prioritize CSV and
# --checks worksheet, so one captured answer guards every front-end at once.
SELFTEST_STATUSES = ("pass", "fail", "error", "skipped")


def _selftest_check(name: str, status: str, detail: str = "") -> dict:
    if status not in SELFTEST_STATUSES:
        raise ValueError(f"unknown selftest status: {status}")
    return {"check": name, "status": status, "detail": detail}


def selftest(base: str | Path | None = None) -> dict:
    """Validate severity, must_fix and prioritized order against ground truth.

    Like a network scanner that ships a canonical safe target so a user can
    confirm the engine works end-to-end, this ships a captured set of tool
    results (``sentinel_fixture.json``) spanning every severity bucket and its
    exact expected answer (``sentinel_expect.json``). The production
    :func:`severity_contract`, :func:`prioritized` and :func:`prioritize_csv`
    functions run on that fixture and are compared exactly. This reports a
    regression in the reporting engine, not a risk verdict about any input.
    ``status`` is pass (all expectations met), fail (a regression) or error
    (fixture unreadable or unparsable, which is fail-closed and never a pass).
    """
    base = Path(base) if base is not None else HERE
    fixture = base / "sentinel_fixture.json"
    expect_path = base / "sentinel_expect.json"
    checks: list = []
    try:
        data = fixture.read_bytes()
    except OSError as e:
        checks.append(_selftest_check("fixture", "error",
                                      f"unreadable: {type(e).__name__}"))
        return {"schema_version": SCHEMA, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "checks": checks}
    checks.append(_selftest_check("fixture", "pass", f"{len(data)} bytes"))
    try:
        expectation = json.loads(expect_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        checks.append(_selftest_check("expectation", "error",
                                      f"unreadable: {type(e).__name__}"))
        return {"schema_version": SCHEMA, "mode": "selftest", "status": "error",
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

    try:
        results = json.loads(data.decode("utf-8"))
        if not isinstance(results, list):
            raise ValueError("fixture is not a results list")
    except (ValueError, UnicodeDecodeError) as e:
        checks.append(_selftest_check("parse", "error",
                                      f"invalid fixture: {type(e).__name__}"))
        return {"schema_version": SCHEMA, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "fixture_sha256": actual_hash,
                "checks": checks}
    checks.append(_selftest_check("parse", "pass",
                                  f"{len(results)} tool result(s)"))

    # Kind coverage: derive the finding kinds reachable from the configured
    # rules and require every one to be declared in SEVERITY. An undeclared
    # kind would fall through to the documented info default, so the check
    # fails closed (fail) instead of letting the drift report a pass.
    cov = kind_coverage(base / "rules")
    if cov["errors"]:
        checks.append(_selftest_check(
            "kind_coverage", "error", "; ".join(cov["errors"])))
    elif cov["unmapped"]:
        checks.append(_selftest_check(
            "kind_coverage", "fail",
            "undeclared kinds: " + ", ".join(cov["unmapped"])))
    else:
        checks.append(_selftest_check(
            "kind_coverage", "pass",
            f"{len(cov['reachable'])} reachable kinds all declared"))

    expected = expectation.get("expected", {})
    actual_prioritized = prioritized(results)

    exp_severity = expected.get("severity")
    if isinstance(exp_severity, dict):
        ok = exp_severity == severity_contract()
        checks.append(_selftest_check(
            "severity_map", "pass" if ok else "fail",
            "exact match" if ok else "severity contract drift"))
    else:
        checks.append(_selftest_check("severity_map", "skipped",
                                      "no expected severity contract"))

    exp_prioritized = expected.get("prioritized")
    if isinstance(exp_prioritized, list):
        ok = exp_prioritized == actual_prioritized
        checks.append(_selftest_check(
            "prioritized", "pass" if ok else "fail",
            f"{len(actual_prioritized)} tool(s) in exact order" if ok
            else "prioritized order/counts drift"))
    else:
        checks.append(_selftest_check("prioritized", "skipped",
                                      "no expected prioritized list"))

    actual_flags = {row["tool"]: row["must_fix"] for row in actual_prioritized}
    exp_flags = expected.get("must_fix")
    if isinstance(exp_flags, dict):
        ok = exp_flags == actual_flags
        checks.append(_selftest_check(
            "must_fix", "pass" if ok else "fail",
            "exact match" if ok else "must_fix flag drift"))
    else:
        checks.append(_selftest_check("must_fix", "skipped",
                                      "no expected must_fix flags"))

    exp_csv = expected.get("prioritize_csv")
    if isinstance(exp_csv, str):
        ok = exp_csv == prioritize_csv(actual_prioritized)
        checks.append(_selftest_check(
            "prioritize_csv", "pass" if ok else "fail",
            "byte-exact CSV" if ok else "triage CSV drift"))
    else:
        checks.append(_selftest_check("prioritize_csv", "skipped",
                                      "no expected CSV"))

    if any(c["status"] == "error" for c in checks):
        status = "error"
    elif any(c["status"] == "fail" for c in checks):
        status = "fail"
    else:
        status = "pass"
    return {
        "schema_version": SCHEMA,
        "mode": "selftest",
        "status": status,
        "fixture": fixture.name,
        "fixture_sha256": actual_hash,
        "tool_results": len(results),
        "checks": checks,
    }


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
    p.add_argument("--selftest", action="store_true",
                   help="validate severity, must_fix and prioritized order against the committed ground-truth fixture (exit 0/1/2)")
    args = p.parse_args(argv)
    supplied = list(sys.argv[1:] if argv is None else argv)
    if args.selftest:
        st = selftest(HERE)
        _emit(json.dumps(st, indent=2) + "\n", args.out)
        return {"pass": 0, "fail": 1, "error": 2}[st["status"]]
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
