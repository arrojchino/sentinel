#!/usr/bin/env python3
"""Read real Wazuh alerts from WSL, triage them, then run Sentinel blue checks.

Read-only on the Wazuh host. No credentials, no network calls from this script.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DISTRO = "Ubuntu-24.04"
ALERTS = "/var/ossec/logs/alerts/alerts.json"


def fetch(count: int) -> list[dict]:
    cmd = ["wsl.exe", "-d", DISTRO, "--", "bash", "-lc",
           f"sudo -n tail -n {count} {ALERTS}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    if r.returncode != 0:
        raise RuntimeError("wsl read failed: " + r.stderr[:200])
    rows = []
    for line in r.stdout.replace("\x00", "").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def triage(rows: list[dict], threshold: int) -> dict:
    groups = defaultdict(lambda: {"count": 0, "max_level": 0, "first": None, "last": None,
                                  "rules": set(), "agents": set()})
    for alert in rows:
        rule = alert.get("rule", {})
        level = int(rule.get("level", 0))
        agent = alert.get("agent", {}).get("name", "unknown")
        src = alert.get("srcip") or alert.get("data", {}).get("srcip") or "-"
        ts = alert.get("timestamp")
        g = groups[(agent, src)]
        g["count"] += 1
        g["max_level"] = max(g["max_level"], level)
        g["first"] = min(filter(None, [g["first"], ts])) if g["first"] else ts
        g["last"] = max(filter(None, [g["last"], ts])) if g["last"] else ts
        g["rules"].add(rule.get("description", "-"))
        g["agents"].add(agent)
    queue = []
    for (agent, src), g in groups.items():
        if g["max_level"] < threshold:
            continue
        queue.append({"agent": agent, "srcip": src, "count": g["count"],
                      "max_level": g["max_level"], "first": g["first"], "last": g["last"],
                      "rules": sorted(g["rules"])[:5]})
    queue.sort(key=lambda x: (-x["max_level"], -x["count"]))
    return {"generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "alerts_read": len(rows), "threshold": threshold,
            "groups": len(groups), "queue": queue}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Wazuh alert bridge for Sentinel")
    p.add_argument("--count", type=int, default=200, help="last N alerts to read")
    p.add_argument("--threshold", type=int, default=7, help="minimum rule level")
    p.add_argument("--out", default="wazuh_queue.json")
    args = p.parse_args(argv)
    rows = fetch(args.count)
    result = triage(rows, args.threshold)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"alerts_read": result["alerts_read"], "groups": result["groups"],
                      "queued": len(result["queue"]), "out": args.out}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
