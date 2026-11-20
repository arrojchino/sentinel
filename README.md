# Sentinel

One read-only CLI for 69 focused security checks, grouped by team.

## Teams

- `blue` - detection, alert and evidence checks
- `red` - authorized offensive artifacts and exposure checks
- `yellow` - policy, governance and decision checks
- `appsec` - web and code findings
- `devops` - secrets, build and pipeline artifacts

## Usage

```bash
python sentinel.py --list --team blue
python sentinel.py --team appsec sample.txt
python sentinel.py --tool headerscheck sample.txt
python sentinel.py --team blue wazuh_alerts.json --out result.json
```

Input is a local file. Output is a JSON envelope with `schema_version`, `team`, `input` and per-tool findings. Stdlib only; no network, no writes to the input. Exit status is the machine-facing contract; see CI gate contract below.

## Risk-ordered report

A multi-organization sync tool sends its team a CSV action list, one row per action, with an explicit status per row and a `must_fix` yes/no, ordered so the team knows what to fix first. Sentinel applies the same shape to its own envelope: a tool is not just a count, it is a prioritized work item.

Each finding `kind` maps to one explicit severity bucket - `critical`, `high`, `medium`, `low` or `info`. A tool's severity is the most severe of its findings. Two cases never get buried: a tool that failed to run is `indeterminate` and outranks every scored tool (unknown risk is never last), and a tool with no findings is `clear` and sorts last. Unmapped kinds fall back to `info`, a documented default that never silently promotes a finding.

The envelope adds:

- `results` - the same per-tool records as before, now ordered by risk so the main report leads with the tool that needs attention first.
- `prioritized` - a "where to start" list, one entry per tool with `tool`, `severity`, `count` and `must_fix`. `must_fix` is `true` for `indeterminate`, `critical`, `high`, `medium` and `low`, and `false` for `info` and `clear`, so a noisy hash/header tool cannot look like actionable work.
- `severity` - the buckets, the full kind-to-bucket map, the default and the `must_fix` set, so the output states its own classification rules and a reviewer can reproduce the order from the envelope alone.

Ordering is deterministic: severity descending, then finding count descending, then tool name. A tool with one critical finding therefore leads a tool with twenty informational matches, and two equal tools keep a stable name order. Consumers can take `prioritized[0]` as the first tool to investigate without re-deriving the ranking. Exit status is unchanged; this is a presentation of the same findings, not a new verdict.

## Triage handoff (--prioritize)

A findings tracker keeps a compact "Needs action" view beside its full report: a machine-readable list of what to fix first, with an explicit status per row and a documented schema, so a human or a downstream job can pick it up without re-deriving the ranking from the dashboard. Sentinel exposes the same handoff with `--prioritize`: stdout carries only the prioritized "where to start" list as CSV, with no JSON envelope and no prose.

```bash
python sentinel.py --team blue wazuh_alerts.json --prioritize > triage.csv
```

Column contract - the header is always the first line:

- `tool` - the tool or rule name that produced the finding.
- `severity` - the tool's effective bucket: `indeterminate`, `critical`, `high`, `medium`, `low`, `info` or `clear`.
- `count` - number of findings from that tool.
- `must_fix` - lowercase `true` or `false`; `true` for every bucket except `info` and `clear`.

Rows keep the deterministic severity/count/name order from the envelope, so the first data row is the first tool to investigate. Output is UTF-8 with LF line endings and a trailing newline, so the bytes are stable across platforms and a committed triage CSV shows no spurious diff on a rerun. `--out` writes the same CSV to a file instead of stdout, and `--list` still takes precedence when both are given. The exit status is unchanged (`0`/`1`/`2`) and still gates on findings, so a caller can branch on the decision and hand the CSV to a triage queue from one invocation.

## CI gate contract

Wireshark ships TShark as the line-oriented front-end that reuses the same dissection and filtering code as the GUI, so a scripted run sees exactly what an interactive run sees. Sentinel follows the same shape with one rule engine and one scriptable front-end: stdout carries the evidence envelope, and the exit status carries the decision the pipeline composes on. There is no separate "CI mode" that could drift from what a human runs.

Exit statuses, verified against this checkout:

- `0` - no findings and no tool errors; also returned by `--list`.
- `1` - at least one check reported a finding, **or** at least one tool failed to run. This is fail-closed: an unreadable or unparseable input denies the gate rather than passing it.
- `2` - a usage error (for example, no file given or an invalid `--team`). This is distinct from a gate result, so callers can tell "denied by evidence" from "called wrong".

Worked example (POSIX shell). The `outputschema` check requires `schema_version`, `report_id`, `generated_at` and `findings`:

```bash
# Clean report: all required fields present -> no findings -> gate passes.
printf '%s\n' '{"schema_version":1,"report_id":"r-1","generated_at":"now","findings":[]}' > good.json
python sentinel.py --tool outputschema good.json >/dev/null; echo $?   # 0

# Dirty report: required fields missing -> findings -> gate denies.
printf '%s\n' '{}' > bad.json
python sentinel.py --tool outputschema bad.json >/dev/null; echo $?    # 1

# Broken input: the tool errors -> fail-closed -> gate denies.
printf '%s\n' 'not json' > broken.json
python sentinel.py --tool outputschema broken.json >/dev/null; echo $? # 1
```

A typical pipeline keeps the envelope as an artifact and branches on the status:

```bash
python sentinel.py --team blue alerts.json --out blue.json
status=$?
if [ "$status" -eq 0 ]; then
  echo "gate passed"
else
  echo "gate denied (status $status); see blue.json"
  exit "$status"
fi
```

## Enforcement and evidence

- Evidence fields are structural keys, not substrings inside a note.
- `open_proof_gap` is unresolved and is flagged as a terminal-state failure.
- Allowlisted tools require `scope_ref`, `approver` and a future `expires_at`.
- Custody manifests verify SHA-256 and size against local files.

## Wazuh bridge

`wazuh_bridge.py` reads the last N alerts from the local Wazuh host over WSL with `sudo -n tail` (read-only), groups them by agent and source, and writes a prioritized queue to `wazuh_queue.json`. Feed the alerts file to Sentinel afterwards:

```bash
python wazuh_bridge.py --count 150 --threshold 6
python sentinel.py --team blue wazuh_alerts.json --out blue.json
```

## Release gate

`releasegate.py` turns a findings JSON array or an envelope into `allow`, `deny` or `indeterminate`:

```bash
python releasegate.py findings.json --rules limits.json
```

- Exit `0` (`allow`), `1` (`deny`), `2` (`indeterminate`): the evidence could not be read or parsed, or a finding carried a severity outside the known vocabulary.
- Unreadable input yields a structured decision with the reason, not a traceback and not a pass. This follows the scan-health rule that an app with no published scan is Unknown and a failed retrieval is Error - neither is ever clean, so a gate that could not evaluate never allows.
- A finding whose severity is not in the scored vocabulary - `critical`, `high`, `medium`, `moderate`, `low`, `info`, `informational` (case-insensitive) - also makes the decision indeterminate, and its counts are kept in the output as evidence. A missing severity counts as `unspecified`, which is likewise indeterminate. This extends the same "Unknown is not clean" rule to classification: a finding that cannot be mapped to a threshold is never silently waved through as `max_total` noise.
- Every decision carries `limits`, the thresholds actually applied, so the output states its own classification rules.
- Teams can extend the vocabulary with a `severities` object in the rules JSON. Each key is a severity name, each value the canonical bucket it maps to (`critical`, `high`, `medium`, `low`, `info`). A custom name is normalized onto its bucket before scoring, so a team's `blocker` mapped to `critical` is measured by `max_critical` and denies exactly like a native critical. Names not in the vocabulary stay indeterminate, and a value outside the bucket set is an input error (exit 2), so a misspelled bucket can never silently downgrade a finding into the unscored `info` bucket.

```bash
# rules.json: {"severities": {"blocker": "critical", "P3": "low"}, "max_critical": 0}
python releasegate.py findings.json --rules rules.json
```

An envelope may carry `reported_total`: the number of findings the upstream
scanner says it produced. If the gate parses fewer than that, the decision is
indeterminate (exit 2) with both counts in the reason. A short parse is pending,
never clean - an upstream format change must not silently shrink the parse into
a false pass. Parsing the claimed count or more scores normally, and a
non-integer or negative `reported_total` is a fail-closed input error.

This borrows from a pull-request PDF report helper: scans that have not reported
show as pending rather than clean, and if fewer rows parse than the tool's own
summary claims, that scan is pending rather than passing. Sentinel applies the
same completeness rule to a release decision.

That same report helper ranks a finding on the higher of its reported severity
and its CVSS band. `releasegate.py` now does too. A score found under `cvss`,
`cvss_score` or `cvssScore` maps to a CVSS v3.1 band (0.0 info, 0.1-3.9 low,
4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical), and the finding is scored at
the higher of that band and its declared bucket. A `low`-labelled finding with
a 9.8 score therefore denies like a critical. The rule never downgrades: a
declared critical stays critical even with a low CVSS. The decision keeps
`buckets` for the declared totals and adds `effective_buckets` plus an
`upgrades` list naming each finding and score that moved, so a reviewer can
reproduce the verdict. A CVSS value that is present but not a number in 0.0-10.0
is a fail-closed input error (exit 2): an unreadable score must not silently
disappear into the unscored bucket.

The decision reports both `counts` (raw severity names seen) and `buckets` (canonical totals that drove the thresholds). Scan-health reports state every rule they apply; this output names the vocabulary in force and the thresholds applied, so a reviewer can reproduce a verdict from the decision alone.

A mature exploitation framework assigns a known reliability Rank before a module can be scored; an unranked module cannot be safely compared against a ranked one. `releasegate.py` applies the same shape to severity: only the known vocabulary can be measured against a threshold, and anything else stops the gate instead of being counted as harmless.

The decision also carries a `prioritized` list - an ordered "where to start" view of the findings so the highest-risk item leads the report, mirroring the action list a multi-organization sync tool produces for its team. Each entry states its original `index`, raw `severity`, `declared_bucket`, effective `bucket` and any `cvss` score that drove an upgrade. Ordering is deterministic and reproducible: effective bucket descending, then the CVSS score descending, then original position so equal findings keep input order. A CVSS-upgraded low therefore leads a declared high. An indeterminate decision carries an empty list - evidence that could not be evaluated yields no ranked work items. Consumers can take `prioritized[0]` as the first item to fix without re-deriving the ranking from the aggregate buckets.

### Triage handoff (--prioritize)

The findings tracker keeps a compact "Needs action" view beside its full report, with a documented schema so a human or a downstream job can act without re-deriving the ranking from the dashboard. `releasegate.py --prioritize` exposes the same handoff: stdout carries only the ranked "where to start" list as CSV, with no JSON envelope and no prose.

```bash
python releasegate.py findings.json --prioritize > triage.csv
```

Columns, in order:

- `index` - the finding's original position in the input array.
- `severity` - its raw severity name (case-normalized, or the team name from the `severities` map).
- `declared_bucket` - the canonical bucket that name maps to.
- `bucket` - the effective bucket after CVSS ranking.
- `cvss` - the score that drove an upgrade, or empty when no score changed the bucket.

Rows keep the decision's deterministic order, so the first data row is the first finding to fix. An indeterminate decision emits the header only: evidence that could not be evaluated yields no ranked work items. Output is UTF-8 with LF endings and a trailing newline, so a committed triage CSV changes only when the findings change and never produces a platform-newline diff. `--out` writes the same bytes to a file instead of stdout. The exit status (`0`/`1`/`2`) is unchanged and still gates on findings, so a caller can branch on the verdict while handing the CSV to a reviewer.

## IOC and timeline

`iocscan.py` extracts typed observables (IPv4, domain, MD5/SHA-1/SHA-256), suppresses private and reserved ranges, dedupes by value and reports source lines. `timeline.py` groups timestamped events into sessions by source with a configurable gap and flags long dwell.

```bash
python iocscan.py capture.txt --out ioc.json
python timeline.py alerts.jsonl --gap 900 --max-span 3600
```

`iocscan.py --expect N` applies the same completeness rule as the release gate's `reported_total`. `N` is the number of observables the source claims to contain. Every pattern hit is counted as parsed before private-range suppression and deduplication, so those legitimate transformations cannot be mistaken for a truncated export. A short parse returns a structured result with `status: incomplete`, the claimed and observed counts, and a reason, and exits `2` - truncated evidence is pending, never clean. Parsing the claimed count or more scores normally (exit `1` with findings, `0` without), and a negative `--expect` or an unreadable file is a fail-closed input error (exit `2`), not a traceback and not a pass.

```bash
# Source summary says 500 observables but only 2 were captured -> pending.
python iocscan.py partial.txt --expect 500; echo $?   # 2
```

### Triage handoff (--prioritize)

Like the findings tracker's compact "Needs action" view, `iocscan.py --prioritize` gives consumers a machine-readable list of observables to pivot on, with a documented schema and no JSON envelope or prose. stdout carries only the typed observables as CSV:

```bash
python iocscan.py capture.txt --prioritize > observables.csv
```

Columns, in order:

- `type` - observable type (`ipv4`, `domain`, `md5`, `sha1`, `sha256`).
- `value` - the normalized (lowercased) observable; private and reserved ranges are suppressed.
- `line` - the 1-based source line where that occurrence appeared.

One row is emitted per (type, value, line) occurrence, so an observable seen on several lines keeps every location even after deduplication. Rows follow the deterministic (type, value, then line) order used by the JSON findings. Output is UTF-8 with LF endings and a trailing newline, so a committed triage CSV changes only when the observables change and never produces a platform-newline diff. `--out` writes the same bytes to a file instead of stdout. The exit status (`0`/`1`/`2`) is unchanged: `1` with findings, `0` without, and `2` for an incomplete parse or an input error, so a caller can still gate on evidence quality while handing the CSV to a reviewer.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request. It executes the
unit tests, then probes the gate twice: `headerscheck` on `sample.txt` must exit
`1` (missing security headers) and on `ci/clean_headers.txt` must exit `0`
(complete header set). Both probes also assert that the JSON envelope is
parseable.

## Limits

Each check reports what its rules can see in the supplied file. A clean result is not proof of safety, and a finding is not a verdict. The bridge reads the alerts log file, not the Wazuh API.
