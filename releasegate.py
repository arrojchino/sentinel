#!/usr/bin/env python3
"""Release gate: turn normalized findings into an allow/deny decision.

Stdlib only. Reads a findings JSON array or an envelope with a findings list.
Exit 0 allows, exit 1 denies.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULTS = {"max_critical": 0, "max_high": 2, "max_total": 20}


def load_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    raise ValueError("expected a JSON array or an object with findings[]")


def decide(findings: list[dict], limits: dict) -> dict:
    counts = Counter(str(f.get("severity", "Unspecified")).lower() for f in findings)
    reasons = []
    for key, label in (("critical", "critical"), ("high", "high")):
        limit = limits["max_" + key]
        if counts[label] > limit:
            reasons.append(f"{label}={counts[label]} exceeds max_{key}={limit}")
    if len(findings) > limits["max_total"]:
        reasons.append(f"total={len(findings)} exceeds max_total={limits['max_total']}")
    return {"verdict": "deny" if reasons else "allow",
            "counts": dict(counts), "total": len(findings), "reasons": reasons}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Release gate from findings to verdict")
    p.add_argument("file", help="findings JSON file")
    p.add_argument("--rules", help="optional JSON with thresholds")
    args = p.parse_args(argv)
    limits = dict(DEFAULTS)
    if args.rules:
        limits.update(json.loads(Path(args.rules).read_text(encoding="utf-8")))
    result = decide(load_findings(Path(args.file)), limits)
    json.dump(result, sys.stdout, indent=2)
    print()
    return 1 if result["verdict"] == "deny" else 0


if __name__ == "__main__":
    raise SystemExit(main())
