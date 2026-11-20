#!/usr/bin/env python3
"""Release gate: turn normalized findings into an allow/deny decision.

Stdlib only. Reads a findings JSON array or an envelope with a findings list.
Exit 0 allows, exit 1 denies, exit 2 means the gate could not evaluate its
evidence. An unevaluable gate is indeterminate, never an allow.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULTS = {"max_critical": 0, "max_high": 2, "max_total": 20}
EXIT_CODES = {"allow": 0, "deny": 1, "indeterminate": 2}

# A finding can only be scored against a threshold if its severity maps to a
# canonical bucket. Anything outside this vocabulary is Unknown, and Unknown is
# never clean. Teams may extend it with the 'severities' key in --rules.
CANONICAL = {
    "critical": "critical", "high": "high", "medium": "medium",
    "moderate": "medium", "low": "low", "info": "info",
    "informational": "info",
}
KNOWN_SEVERITIES = frozenset(CANONICAL)  # default vocabulary, kept public
BUCKETS = frozenset(CANONICAL.values())

# Canonical buckets in ascending risk order. A finding is ranked on the higher
# of its declared severity and its CVSS band, so a critical CVSS score cannot
# be hidden behind a low declared severity.
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CVSS_KEYS = ("cvss", "cvss_score", "cvssScore")


def band_for_score(score: float) -> str:
    """Map a CVSS v3.1 score onto a canonical bucket.

    Bands: 0.0 None (folded into info), 0.1-3.9 low, 4.0-6.9 medium,
    7.0-8.9 high, 9.0-10.0 critical.
    """
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def effective_bucket(finding: dict, declared_bucket: str):
    """Return ``(bucket, cvss, error)`` for one finding.

    The bucket is the higher of ``declared_bucket`` and the finding's CVSS
    band. ``cvss`` is the score that caused an upgrade, else None. A CVSS key
    that is present but not a number in 0.0-10.0 is an error: a broken score
    must never silently downgrade a finding into an unscored bucket.
    """
    scores = []
    for key in CVSS_KEYS:
        if key not in finding:
            continue
        raw = finding[key]
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return None, None, f"invalid cvss value under {key!r}: {raw!r}"
        score = float(raw)
        if score < 0.0 or score > 10.0:
            return None, None, f"cvss out of range 0.0-10.0 under {key!r}: {score}"
        scores.append(score)
    if not scores:
        return declared_bucket, None, None
    score = max(scores)
    band = band_for_score(score)
    if RANK[band] > RANK[declared_bucket]:
        return band, score, None
    return declared_bucket, None, None


def max_cvss(finding: dict) -> float:
    """Return the highest CVSS score present on a finding, or -1.0 if none.

    Used only as a deterministic tie-break when two findings share an
    effective bucket. Validation of the score is effective_bucket's job; by
    the time this runs any present score is known to be in 0.0-10.0.
    """
    best = -1.0
    for key in CVSS_KEYS:
        raw = finding.get(key)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            continue
        best = max(best, float(raw))
    return best


def build_severity_map(extra=None):
    """Return a severity-name -> canonical-bucket map.

    ``extra`` is the optional ``severities`` object from the rules JSON: it maps
    a team's own severity names onto a canonical bucket, e.g.
    ``{"blocker": "critical"}``. Mapping onto a bucket is what makes a custom
    name scoreable against max_critical/max_high instead of indeterminate.
    A bad target is rejected so a misspelled bucket cannot silently downgrade a
    finding into the unscored 'info' bucket.
    """
    result = dict(CANONICAL)
    if extra is not None:
        if not isinstance(extra, dict):
            raise ValueError("'severities' must be an object mapping names to buckets")
        for name, target in extra.items():
            bucket = str(target).lower()
            if bucket not in BUCKETS:
                raise ValueError(
                    f"severity bucket {target!r} is not one of {sorted(BUCKETS)}")
            result[str(name).lower()] = bucket
    return result


def load_findings(path: Path):
    """Return ``(findings, claimed_total)``.

    ``claimed_total`` comes from an envelope's ``reported_total`` key: the count
    the upstream scanner says it produced. It is None for a plain array or when
    the source does not state a count. A malformed claim is an input error so a
    broken count cannot be silently ignored.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        claimed = data.get("reported_total")
        if claimed is not None:
            if isinstance(claimed, bool) or not isinstance(claimed, int) or claimed < 0:
                raise ValueError("'reported_total' must be a non-negative integer")
        return data["findings"], claimed
    raise ValueError("expected a JSON array or an object with findings[]")


def decide(findings: list[dict], limits: dict,
           severity_map: dict | None = None,
           claimed_total: int | None = None) -> dict:
    smap = CANONICAL if severity_map is None else severity_map
    counts = Counter(str(f.get("severity", "Unspecified")).lower() for f in findings)
    total = len(findings)
    # A source may state how many findings it produced. Parsing fewer than that
    # is incomplete evidence, not a clean result: an upstream format change must
    # never shrink the parse into a false pass. Pending is never clean.
    if claimed_total is not None and total < claimed_total:
        return indeterminate(
            f"incomplete evidence: parsed {total} of claimed {claimed_total} findings",
            limits, counts=dict(counts), total=total)
    unrecognized = sorted(s for s in counts if s not in smap)
    if unrecognized:
        return indeterminate(
            "unrecognized severity (Unknown is not clean): " + ", ".join(unrecognized),
            limits, counts=dict(counts), total=total)
    # Normalize every recognized name onto a canonical bucket, then rank each
    # finding on the higher of that bucket and its CVSS band. Declared buckets
    # stay in the report as evidence; effective buckets drive the thresholds.
    buckets = Counter()
    effective = Counter()
    upgrades = []
    ranked = []
    for index, finding in enumerate(findings):
        name = str(finding.get("severity", "Unspecified")).lower()
        declared_bucket = smap[name]
        buckets[declared_bucket] += 1
        bucket, cvss, error = effective_bucket(finding, declared_bucket)
        if error:
            return indeterminate(f"input error: invalid CVSS evidence: {error}",
                                 limits, counts=dict(counts), total=total)
        effective[bucket] += 1
        if bucket != declared_bucket:
            upgrades.append({"severity": name, "cvss": cvss,
                             "from": declared_bucket, "to": bucket})
        ranked.append((RANK[bucket], max_cvss(finding), index,
                       {"index": index, "severity": name,
                        "declared_bucket": declared_bucket, "bucket": bucket,
                        "cvss": cvss}))
    # An ordered "where to start" list for the reader: the highest-risk
    # finding leads. Ordering is deterministic and reproducible - effective
    # bucket descending, then the CVSS score that drove any upgrade descending,
    # then the original position so equal findings keep their input order.
    ranked.sort(key=lambda e: (-e[0], -e[1], e[2]))
    prioritized = [e[3] for e in ranked]
    reasons = []
    for key in ("critical", "high"):
        limit = limits["max_" + key]
        if effective[key] > limit:
            reasons.append(f"{key}={effective[key]} exceeds max_{key}={limit}")
    if total > limits["max_total"]:
        reasons.append(f"total={total} exceeds max_total={limits['max_total']}")
    return {"verdict": "deny" if reasons else "allow",
            "counts": dict(counts), "buckets": dict(buckets),
            "effective_buckets": dict(effective), "upgrades": upgrades,
            "prioritized": prioritized,
            "total": total, "reasons": reasons, "limits": dict(limits)}


def indeterminate(reason: str, limits: dict, *, counts: dict | None = None,
                  total: int = 0) -> dict:
    """Build a decision for evidence that could not be evaluated.

    Scan-health tooling makes the same distinction: an app with no published
    scan is Unknown and a failed retrieval is Error; neither is ever 'clean'.
    The same applies to a finding whose severity is outside the known vocabulary
    - it cannot be mapped to a threshold, so it cannot be scored as clean, and
    to a parse shorter than the source's own claim - it is pending, not passing.
    Here the gate reports why it cannot decide and exits 2, so a caller can tell
    'denied by evidence' from 'could not evaluate'. Any counts supplied are kept
    as evidence of what was actually seen.
    """
    return {"verdict": "indeterminate", "counts": counts or {}, "total": total,
            "reasons": [reason], "limits": dict(limits), "prioritized": []}


def prioritize_csv(rows: list) -> str:
    """Render the prioritized 'where to start' list as a triage CSV.

    Column contract: index, severity, declared_bucket, bucket, cvss -- one row
    per finding, in the decision's prioritized order. ``index`` is the finding's
    original position, ``severity`` its raw name, ``declared_bucket`` the bucket
    that name maps to, ``bucket`` the effective bucket after CVSS ranking, and
    ``cvss`` the score that caused an upgrade (empty when none did). An LF
    terminator and a trailing newline keep the bytes deterministic, so a
    committed CSV changes only when the findings change, not with the host.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("index", "severity", "declared_bucket", "bucket", "cvss"))
    for row in rows:
        writer.writerow((row["index"], row["severity"], row["declared_bucket"],
                         row["bucket"], row["cvss"] if row["cvss"] is not None else ""))
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
    p = argparse.ArgumentParser(description="Release gate from findings to verdict")
    p.add_argument("file", help="findings JSON file")
    p.add_argument("--rules", help="optional JSON with thresholds and a 'severities' map")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only the prioritized 'where to start' list as triage CSV")
    p.add_argument("--out", help="write the output to a file instead of stdout")
    args = p.parse_args(argv)
    limits = dict(DEFAULTS)
    severity_map = dict(CANONICAL)
    try:
        if args.rules:
            rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
            severity_map = build_severity_map(rules.pop("severities", None))
            limits.update(rules)
        findings, claimed_total = load_findings(Path(args.file))
    except (OSError, ValueError) as e:
        result = indeterminate(f"input error: {type(e).__name__}: {str(e)[:160]}", limits)
    else:
        result = decide(findings, limits, severity_map, claimed_total)
    output = (prioritize_csv(result["prioritized"]) if args.prioritize
              else json.dumps(result, indent=2) + "\n")
    _emit(output, args.out)
    return EXIT_CODES[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
