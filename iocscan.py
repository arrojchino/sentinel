#!/usr/bin/env python3
"""Extract typed observables from text, dedupe them, and suppress private ranges."""
from __future__ import annotations

import argparse
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


def scan(text: str) -> dict:
    hits = {}
    for line_no, line in enumerate(text.splitlines(), 1):
        for kind, pat in PATTERNS.items():
            for value in pat.findall(line):
                value = value.lower()
                if kind == "ipv4" and private(value):
                    continue
                hits.setdefault((kind, value), []).append(line_no)
    findings = [{"type": k, "value": v, "lines": sorted(lines)}
                for (k, v), lines in sorted(hits.items())]
    return {"schema_version": 1, "count": len(findings), "findings": findings}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="IOC normalizer with private-range suppression")
    p.add_argument("file")
    p.add_argument("--out")
    args = p.parse_args(argv)
    result = scan(Path(args.file).read_text(encoding="utf-8", errors="replace"))
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 1 if result["count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
