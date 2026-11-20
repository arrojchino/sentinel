#!/usr/bin/env python3
"""Release gate: turn normalized findings into an allow/deny decision.

Stdlib only. Reads a findings JSON array or an envelope with a findings list.
Exit 0 allows, exit 1 denies, exit 2 means the gate could not evaluate its
evidence. An unevaluable gate is indeterminate, never an allow.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from datetime import datetime, timezone
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

# A finding may carry the date it was first observed under one of several
# names used by common scanners (the export vocabulary calls it "First Found
# Date"). The gate reads the first key that parses and never guesses: no
# parseable date is not current evidence, so freshness fails closed.
FINDING_DATE_KEYS = (
    "first_found", "firstFound", "first_found_date", "found_date",
    "first_seen", "discovered", "date", "timestamp",
)

# Closed per-check confirmation vocabulary. Borrowed from the SBOM generator's
# stale-input rule: an input that cannot be used is marked explicitly and is
# never silently treated as clean. ``not_confirmed`` is never clean; ``skipped``
# means the check did not apply to this decision; ``confirmed`` means the check
# ran and produced a result (which may still breach a limit).
CHECK_CONFIRMED = "confirmed"
CHECK_NOT_CONFIRMED = "not_confirmed"
CHECK_SKIPPED = "skipped"
CHECK_STATUSES = (CHECK_CONFIRMED, CHECK_NOT_CONFIRMED, CHECK_SKIPPED)
CHECK_NAMES = ("parse", "completeness", "severity_vocabulary", "cvss_validity",
               "max_critical", "max_high", "max_total")


def _check(name: str, status: str, detail: str = "") -> dict:
    """Build one confirmation row with a closed status and a short detail."""
    return {"check": name, "status": status, "detail": detail}


def _finalize_checks(rows: list) -> list:
    """Return one row per check in fixed order, skipping ones not reported.

    A fixed order makes both the CSV worksheet and the JSON ``checks`` array
    byte-stable, and guarantees a caller sees every check the gate knows about
    rather than only the ones that happened to run.
    """
    by_name = {row["check"]: row for row in rows}
    return [by_name.get(name, _check(name, CHECK_SKIPPED)) for name in CHECK_NAMES]


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


def load_findings(path: Path, raw: bytes | None = None):
    """Return ``(findings, claimed_total)``.

    ``claimed_total`` comes from an envelope's ``reported_total`` key: the count
    the upstream scanner says it produced. It is None for a plain array or when
    the source does not state a count. A malformed claim is an input error so a
    broken count cannot be silently ignored.

    When ``raw`` is supplied, decode it instead of reading ``path`` again, so a
    caller can hash exactly the bytes that were parsed without a second read.
    """
    if raw is None:
        raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        claimed = data.get("reported_total")
        if claimed is not None:
            if isinstance(claimed, bool) or not isinstance(claimed, int) or claimed < 0:
                raise ValueError("'reported_total' must be a non-negative integer")
        return data["findings"], claimed
    raise ValueError("expected a JSON array or an object with findings[]")


def source_manifest(path: str | Path, data: bytes | None = None) -> dict:
    """Record provenance for the exact bytes a decision was built from.

    Mirrors the source-files worksheet shared by ``timeline.py`` and
    ``iocscan.py``: name, byte size, non-blank line count and SHA-256 let a
    reviewer tie a verdict back to the input it read. The source is opened
    read-only; nothing is rewritten or decorated with a verdict. When ``data``
    is supplied, the caller's single read is reused, so the hash always covers
    the same bytes that were parsed.

    The hash establishes consistency between a decision and its bytes - not
    authenticity, completeness or causation. An unreadable file has no
    manifest, and scoring never adds a maliciousness verdict to the source.
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


def parse_finding_date(value) -> datetime | None:
    """Parse a finding date into an aware UTC datetime, or None.

    Accepts ISO-8601 strings (including a trailing ``Z``, a space separator
    and a colonless numeric UTC offset such as ``-0600``) and epoch seconds.
    An unparseable value returns None so freshness can fail closed instead of
    treating an unknown date as current. Naive values are assumed UTC.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    if len(text) >= 5 and text[-5] in "+-" and text[-4:].isdigit():
        text = text[:-5] + text[-5] + text[-4:-2] + ":" + text[-2:]
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def freshness(findings: list[dict], max_age_days: float,
              now: datetime | None = None) -> dict:
    """Evaluate the newest finding observation date against a max-age limit.

    A provenance hash binds a verdict to exact bytes but says nothing about
    when those bytes were collected. This carries the stale-scan rule into the
    gate: evidence whose newest observation is older than the limit, or that
    carries no parseable date, cannot support a release decision and is marked
    ``not_confirmed`` (never clean). The check is opt-in, so an unchanged run
    produces byte-identical output. ``status`` is one of CHECK_STATUSES.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    dates = []
    for finding in findings:
        for key in FINDING_DATE_KEYS:
            if key not in finding:
                continue
            parsed = parse_finding_date(finding[key])
            if parsed is not None:
                dates.append(parsed)
                break
    total = len(findings)
    if not dates:
        return {"status": CHECK_NOT_CONFIRMED, "breach": True, "newest": None,
                "age_days": None, "max_age_days": max_age_days, "dated": 0,
                "total": total,
                "detail": f"no parseable date in {total} finding(s)"}
    newest = max(dates)
    age_days = (now - newest).total_seconds() / 86400.0
    breach = age_days > max_age_days
    return {"status": CHECK_NOT_CONFIRMED if breach else CHECK_CONFIRMED,
            "breach": breach, "newest": newest.isoformat(timespec="seconds"),
            "age_days": round(age_days, 4), "max_age_days": max_age_days,
            "dated": len(dates), "total": total,
            "detail": (f"newest finding {age_days:.2f}d old, limit "
                       f"{max_age_days:g}d, {len(dates)}/{total} dated")}


def decide(findings: list[dict], limits: dict,
           severity_map: dict | None = None,
           claimed_total: int | None = None) -> dict:
    smap = CANONICAL if severity_map is None else severity_map
    counts = Counter(str(f.get("severity", "Unspecified")).lower() for f in findings)
    total = len(findings)
    checks = [_check("parse", CHECK_CONFIRMED, f"{total} findings")]
    # A source may state how many findings it produced. Parsing fewer than that
    # is incomplete evidence, not a clean result: an upstream format change must
    # never shrink the parse into a false pass. Pending is never clean.
    if claimed_total is None:
        checks.append(_check("completeness", CHECK_SKIPPED, "no claimed total"))
    elif total < claimed_total:
        checks.append(_check("completeness", CHECK_NOT_CONFIRMED,
                             f"parsed {total} of claimed {claimed_total}"))
        return indeterminate(
            f"incomplete evidence: parsed {total} of claimed {claimed_total} findings",
            limits, counts=dict(counts), total=total, checks=checks)
    else:
        checks.append(_check("completeness", CHECK_CONFIRMED,
                             f"{total} of {claimed_total}"))
    unrecognized = sorted(s for s in counts if s not in smap)
    if unrecognized:
        checks.append(_check("severity_vocabulary", CHECK_NOT_CONFIRMED,
                             ", ".join(unrecognized)))
        return indeterminate(
            "unrecognized severity (Unknown is not clean): " + ", ".join(unrecognized),
            limits, counts=dict(counts), total=total, checks=checks)
    checks.append(_check("severity_vocabulary", CHECK_CONFIRMED,
                         f"{len(counts)} distinct"))
    # Normalize every recognized name onto a canonical bucket, then rank each
    # finding on the higher of that bucket and its CVSS band. Declared buckets
    # stay in the report as evidence; effective buckets drive the thresholds.
    buckets = Counter()
    effective = Counter()
    upgrades = []
    ranked = []
    has_cvss = any(any(key in f for key in CVSS_KEYS) for f in findings)
    if not has_cvss:
        checks.append(_check("cvss_validity", CHECK_SKIPPED, "no cvss values"))
    for index, finding in enumerate(findings):
        name = str(finding.get("severity", "Unspecified")).lower()
        declared_bucket = smap[name]
        buckets[declared_bucket] += 1
        bucket, cvss, error = effective_bucket(finding, declared_bucket)
        if error:
            checks.append(_check("cvss_validity", CHECK_NOT_CONFIRMED, error))
            return indeterminate(f"input error: invalid CVSS evidence: {error}",
                                 limits, counts=dict(counts), total=total, checks=checks)
        effective[bucket] += 1
        if bucket != declared_bucket:
            upgrades.append({"severity": name, "cvss": cvss,
                             "from": declared_bucket, "to": bucket})
        ranked.append((RANK[bucket], max_cvss(finding), index,
                       {"index": index, "severity": name,
                        "declared_bucket": declared_bucket, "bucket": bucket,
                        "cvss": cvss}))
    if has_cvss:
        checks.append(_check("cvss_validity", CHECK_CONFIRMED,
                             f"{len(upgrades)} upgrades"))
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
    for key in ("critical", "high"):
        checks.append(_check(f"max_{key}", CHECK_CONFIRMED,
                             f"effective={effective[key]} limit={limits['max_' + key]}"))
    checks.append(_check("max_total", CHECK_CONFIRMED,
                         f"total={total} limit={limits['max_total']}"))
    return {"verdict": "deny" if reasons else "allow",
            "counts": dict(counts), "buckets": dict(buckets),
            "effective_buckets": dict(effective), "upgrades": upgrades,
            "prioritized": prioritized, "checks": _finalize_checks(checks),
            "total": total, "reasons": reasons, "limits": dict(limits)}


def indeterminate(reason: str, limits: dict, *, counts: dict | None = None,
                  total: int = 0, checks: list | None = None) -> dict:
    """Build a decision for evidence that could not be evaluated.

    Scan-health tooling makes the same distinction: an app with no published
    scan is Unknown and a failed retrieval is Error; neither is ever 'clean'.
    The same applies to a finding whose severity is outside the known vocabulary
    - it cannot be mapped to a threshold, so it cannot be scored as clean, and
    to a parse shorter than the source's own claim - it is pending, not passing.
    Here the gate reports why it cannot decide and exits 2, so a caller can tell
    'denied by evidence' from 'could not evaluate'. Any counts supplied are kept
    as evidence of what was actually seen. The ``checks`` array reports the
    closed per-check status: any check not explicitly reported is ``skipped``.
    """
    return {"verdict": "indeterminate", "counts": counts or {}, "total": total,
            "reasons": [reason], "limits": dict(limits), "prioritized": [],
            "checks": _finalize_checks(checks or [])}


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


def checks_csv(rows: list) -> str:
    """Render the per-check confirmation worksheet as byte-stable CSV.

    Column contract: ``check,status,detail`` -- one row per gate check in the
    fixed ``CHECK_NAMES`` order. ``status`` is one of ``CHECK_STATUSES``:
    ``confirmed`` means the check ran, ``not_confirmed`` means its input could
    not be trusted or parsed (never clean), and ``skipped`` means it did not
    apply. ``detail`` is a short human-readable fact and is empty for a skipped
    check. LF terminator and a trailing newline keep the bytes deterministic.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(("check", "status", "detail"))
    for row in rows:
        writer.writerow((row["check"], row["status"], row.get("detail", "")))
    return buf.getvalue()


# Ground-truth selftest statuses are deliberately distinct from CHECK_STATUSES:
# a selftest answers "does the gate still match its known answer", not "did this
# input confirm a check".
SELFTEST_STATUSES = ("pass", "fail", "error", "skipped")


def _selftest_check(name: str, status: str, detail: str = "") -> dict:
    if status not in SELFTEST_STATUSES:
        raise ValueError(f"unknown selftest status: {status}")
    return {"check": name, "status": status, "detail": detail}


def selftest(base: str | Path | None = None) -> dict:
    """Validate the gate against a committed ground-truth fixture.

    The study target ships a deliberately vulnerable application together with
    its published scan results, so a detector can be checked against a fixed
    answer. This gate ships the same shape: ``releasegate_fixture.json`` is a
    known findings input and ``releasegate_expect.json`` records the limits,
    canonical buckets, effective buckets and verdict it must produce. The check
    compares the gate's current decision to that answer and reports a coverage
    regression, not a risk verdict. ``status`` is pass (every expectation met),
    fail (a regression, including hash drift) or error (an input could not be
    read, which is fail-closed and never counted as a pass).
    """
    base = Path(base) if base is not None else Path(__file__).resolve().parent
    fixture = base / "releasegate_fixture.json"
    expect_path = base / "releasegate_expect.json"
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
        if not isinstance(expectation, dict):
            raise ValueError("expectation must be a JSON object")
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

    try:
        limits = dict(DEFAULTS)
        limits.update(expectation.get("limits", {}))
        severity_map = build_severity_map(expectation.get("severities"))
        findings, claimed_total = load_findings(fixture, data)
        decision = decide(findings, limits, severity_map, claimed_total)
    except (OSError, ValueError) as e:
        checks.append(_selftest_check("score", "error",
                                      f"{type(e).__name__}: {str(e)[:120]}"))
        return {"schema_version": 1, "mode": "selftest", "status": "error",
                "fixture": fixture.name, "fixture_sha256": actual_hash,
                "checks": checks}
    checks.append(_selftest_check("score", "pass",
                                  f"verdict={decision['verdict']}"))

    # Compare the decision's canonical view to the pinned answer exactly. These
    # fields are the gate's scoreable output; prose reasons and the per-check
    # worksheet are deliberately outside the contract because a selftest
    # answers coverage, not explanation.
    comparisons = (
        ("verdict", decision["verdict"], expectation.get("verdict")),
        ("total", decision["total"], expectation.get("total")),
        ("buckets", decision["buckets"], expectation.get("buckets")),
        ("effective_buckets", decision["effective_buckets"],
         expectation.get("effective_buckets")),
    )
    for name, actual, expected in comparisons:
        ok = actual == expected
        checks.append(_selftest_check(
            name, "pass" if ok else "fail",
            "match" if ok else f"expected {expected!r}, got {actual!r}"))

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
        "verdict": decision["verdict"],
        "checks": checks,
    }


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


def _positive_days(raw) -> float:
    """argparse type: a strictly positive, finite age limit in days."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("--max-age-days must be a positive number")
    if value <= 0 or value != value:  # reject zero, negatives and NaN
        raise argparse.ArgumentTypeError("--max-age-days must be a positive number")
    return value


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Release gate from findings to verdict")
    p.add_argument("file", nargs="?", help="findings JSON file")
    p.add_argument("--rules", help="optional JSON with thresholds and a 'severities' map")
    p.add_argument("--selftest", action="store_true",
                   help="validate the gate against the committed ground-truth fixture (exit 0/1/2)")
    p.add_argument("--prioritize", action="store_true",
                   help="emit only the prioritized 'where to start' list as triage CSV")
    p.add_argument("--out", help="write the output to a file instead of stdout")
    p.add_argument("--checks", action="store_true",
                   help="emit only the per-check confirmation worksheet as CSV (check,status,detail)")
    p.add_argument("--max-age-days", type=_positive_days, default=None,
                   help="fail closed (exit 2) when the newest finding date is older than this many days")
    args = p.parse_args(argv)
    if args.selftest:
        st = selftest(Path(__file__).resolve().parent)
        _emit(json.dumps(st, indent=2) + "\n", args.out)
        return {"pass": 0, "fail": 1, "error": 2}[st["status"]]
    if args.file is None:
        p.error("file is required unless --selftest is given")
    limits = dict(DEFAULTS)
    severity_map = dict(CANONICAL)
    raw = None
    findings = None
    try:
        raw = Path(args.file).read_bytes()
        if args.rules:
            rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
            severity_map = build_severity_map(rules.pop("severities", None))
            limits.update(rules)
        findings, claimed_total = load_findings(Path(args.file), raw)
    except (OSError, ValueError) as e:
        result = indeterminate(
            f"input error: {type(e).__name__}: {str(e)[:160]}", limits,
            checks=[_check("parse", CHECK_NOT_CONFIRMED,
                           f"{type(e).__name__}: {str(e)[:120]}")])
    else:
        result = decide(findings, limits, severity_map, claimed_total)
    # Provenance describes the exact bytes that were read for parsing. An
    # unreadable file leaves raw None, so no manifest is attached - the gate
    # cannot tie a verdict to bytes it never saw.
    if raw is not None:
        result["source_files"] = [source_manifest(args.file, raw)]
    # Freshness is opt-in: without --max-age-days the decision, worksheet and
    # JSON are byte-identical to the original gate. When requested, a freshness
    # row is appended to the confirmation worksheet (check,status,detail) and
    # the newest observation is reported alongside the verdict. A stale or
    # undated input is not current evidence and forces an indeterminate exit 2
    # even when its finding counts are otherwise within the limits.
    if args.max_age_days is not None:
        if findings is not None:
            f = freshness(findings, args.max_age_days)
        else:
            f = {"status": CHECK_NOT_CONFIRMED, "breach": False, "newest": None,
                 "age_days": None, "max_age_days": args.max_age_days,
                 "dated": 0, "total": 0,
                 "detail": "input unreadable; freshness not evaluated"}
        result["freshness"] = f
        result["newest_finding_date"] = f["newest"]
        result["newest_finding_age_days"] = f["age_days"]
        result["checks"] = list(result["checks"]) + [
            _check("freshness", f["status"], f["detail"])]
        if f["breach"]:
            result["verdict"] = "indeterminate"
            result["prioritized"] = []
            result["reasons"] = [f"stale evidence: {f['detail']}"] + result.get("reasons", [])
    if args.prioritize:
        output = prioritize_csv(result["prioritized"])
    elif args.checks:
        output = checks_csv(result["checks"])
    else:
        output = json.dumps(result, indent=2) + "\n"
    _emit(output, args.out)
    return EXIT_CODES[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
