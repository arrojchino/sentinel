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
        obj = json.loads(text)
        for item in obj if isinstance(obj, list) else [obj]:
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
    text = path.read_text(encoding="utf-8", errors="replace")
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
    return {"schema_version": SCHEMA, "team": team or "all", "input": str(path), "results": results}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Sentinel: focused security checks by team")
    p.add_argument("file", nargs="?", help="local file to analyze")
    p.add_argument("--team", choices=("blue", "red", "yellow", "appsec", "devops"))
    p.add_argument("--tool", help="run one tool by name")
    p.add_argument("--list", action="store_true", help="list tools for the selected team")
    args = p.parse_args(argv)
    if args.list:
        names = [n for n in sorted(TEAMS) if not args.team or args.team in TEAMS[n]]
        print("\n".join(names))
        return 0
    if not args.file:
        p.error("file is required unless --list is used")
    doc = run(Path(args.file), args.team, args.tool)
    json.dump(doc, sys.stdout, indent=2)
    print()
    bad = any(r.get("count", 1 if r.get("error") else 0) for r in doc["results"])
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
