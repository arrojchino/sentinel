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

### No-argument quick start

A network scanner prints its most common options when invoked with no parameters instead of failing, so a first run teaches the interface without opening the manual. Sentinel applies that progressive-disclosure pattern: `python sentinel.py` with no arguments prints a short quick-start of the common commands to stdout and exits `0`. It is a discovery aid, not a gate result - no input was analyzed and no verdict is implied.

An invocation that supplies arguments but no input file (for example `python sentinel.py --tool headerscheck`) is still a usage error and exits `2`, unchanged. Every invocation that includes a file keeps the exact JSON envelope and the `0`/`1`/`2` contract below. The quick-start is UTF-8 with LF endings and a trailing newline, so its bytes are stable across platforms.

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

### Detection provenance

An open-source IDS separates detection from remediation - logs are analyzed in one place and blocked elsewhere - yet both stages share one reputation layer so a decision can always be traced to the signal that produced it. Sentinel applies that separation: `sentinel.py` detects and `releasegate.py` decides allow/deny, and both now carry the same `source_files` provenance contract so a gate verdict can be tied to the exact bytes detection read. The scanner's JSON envelope adds one `source_files` array with one entry per input:

- `name` - the source file's basename.
- `bytes` - the source size in bytes.
- `lines` - the number of non-blank lines parsed from the source.
- `sha256` - the SHA-256 of the exact bytes read, covering the same single byte read that fed every check.

The hash comes from the one byte read used for analysis, so it always describes the bytes that produced the findings; the source is opened read-only and never rewritten. A hash establishes consistency between a report and its input - not authenticity, completeness or causation - and detection adds no maliciousness verdict to the source. Because the manifest is derived from input bytes, an unchanged source produces identical provenance on every run, and the shape matches the release gate, `iocscan.py` and `timeline.py` so all four tools share one contract. `--prioritize` output is unchanged: the CSV remains the prioritized tool list with no provenance rows.

### Confirmation worksheet (--checks)

A TCP handshake checker reports each step (SYN, SYN-ACK, ACK) as matched True or False, where False means "the capture did not confirm that step" - not that the host is down, and never a reason to discard the step. Sentinel applies the same honesty to its own checks with `--checks`: stdout carries only a per-check confirmation worksheet as CSV, one row for every configured tool, with no JSON envelope and no prose.

```bash
python sentinel.py --team blue wazuh_alerts.json --checks > checks.csv
```

Column contract - the header is always the first line:

- `tool` - a configured tool or rule name. Every tool appears exactly once, in name order, including ones that did not run; a check that was not selected is recorded, never silently dropped.
- `status` - one of a closed vocabulary: `confirmed` (the check ran and produced findings, possibly zero), `not_confirmed` (it ran but errored, so no result could be confirmed from the evidence), or `skipped` (not selected by `--tool`/`--team`).
- `findings` - the integer count for a `confirmed` check, empty for `not_confirmed` and `skipped`, so a genuine zero can never be confused with an error or a check that never ran.

A `confirmed` zero means "no findings detected by this check", not "no risk" - confirmation is about evidence, not absolution. `not_confirmed` is never clean: an errored check is `indeterminate` in the severity ranking and keeps its error as evidence, so "no result" cannot masquerade as "no findings". This is the same distinction the risk-ordered report already makes, now exposed as a compact worksheet a caller can diff between runs to see which checks actually produced evidence. The JSON envelope also carries the worksheet as a `checks` array with the same three statuses and a `findings` count or `null`, so a consumer can read it without invoking the CLI flag.

Output is UTF-8 with LF line endings and a trailing newline, so the bytes are stable across platforms and a committed worksheet shows no spurious diff on a rerun. `--out` writes the same CSV to a file instead of stdout, `--list` still takes precedence, and `--prioritize` takes precedence over `--checks` when both are given. Exit status is unchanged (`0`/`1`/`2`) and still gates on findings.

### Ground-truth fixture (--selftest)

A network scanner such as Nmap ships a canonical safe target so a user can confirm the engine works end-to-end before pointing it at anything real. Sentinel applies the same "known-good invocation" shape to its reporting engine with `--selftest`: it runs the production severity, `must_fix` and ordering functions over a committed set of captured tool results and compares them to a fixed answer, so a silent regression in the ranking is caught once and guards the JSON envelope, `--prioritize` CSV and `--checks` worksheet together.

```bash
python sentinel.py --selftest            # exit 0 on a match, 1 on regression, 2 on unreadable input
python sentinel.py --selftest --out selftest.json
```

`sentinel_fixture.json` is a captured set of six tool results that spans every severity bucket: an errored tool (`indeterminate`), a hash mismatch (`critical`), a disallowed value plus missing fields (`high`), an invalid/unresolved state (`medium`), an informational hash (`info`) and a clean tool (`clear`). `sentinel_expect.json` pins the fixture's SHA-256 (so a byte change is a failure even when the decision is unchanged) and records the exact severity contract, `must_fix` flags and prioritized order that input must produce. The JSON report carries `mode` (`selftest`), `status`, `fixture`, `fixture_sha256`, `tool_results` and a `checks` array. Checks use a closed `pass`/`fail`/`error`/`skipped` vocabulary, deliberately separate from the `confirmed`/`not_confirmed`/`skipped` confirmation worksheet: `fixture` and `expectation` verify the committed files were read, `fixture_hash` compares the bytes to the pinned SHA-256, `parse` records the result count, and `severity_map`, `prioritized`, `must_fix` and `prioritize_csv` compare the reporting engine's output exactly. The pinned hash is a consistency check, not an authenticity or risk claim.

Exit codes mirror the status: `0` for `pass`, `1` for `fail` (a regression in any compared field), `2` for `error` (fixture or expectation unreadable, or an invalid fixture, fail-closed and never a pass). This is a regression check on the reporting engine, not a risk verdict about the fixture: the input is known-noise and the answer is a fixed expectation. `--selftest` needs no file argument, takes precedence over the normal flags, and `--out` writes the same JSON to a file. Without it the default path is byte-identical to before.

#### Kind coverage: every reachable kind is classified

The scan-health report's "How results are classified" section states every rule it applies, and it treats an app with no published scan as Unknown rather than healthy. Sentinel carries that "state the whole classification surface" rule into its severity map. `RULE_KINDS` is the inventory of finding kinds each rule type can emit, and `reachable_kinds()` derives the live set from the rules actually configured in `rules/`; a rule may declare extra kinds in an optional `emits` list for local extensions. The `--selftest` `kind_coverage` check fails closed when a reachable kind is missing from `SEVERITY`: without it, `severity_of()` would silently absorb that kind into the documented `info` default, and a new rule could weaken the ranking without any test noticing.

A missing rules directory, an unreadable or unparsable rule, or a rule type outside the inventory is an `error` (exit 2), never an empty coverage; an undeclared kind is a `fail` (exit 1). The committed rules currently emit 17 distinct kinds, all declared. This is a regression guard on the classification surface, not a risk verdict: the default file run keeps its byte-identical JSON envelope and 0/1/2 gate contract, and `severity_of()` keeps its documented `info` fallback for a kind that reaches it at runtime.

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

### Alert freshness (--max-age-days)

An Internet-wide scanner reports what it did and did not observe in the same progress line - sent, received, dropped and hit rate - so a zero is always stated with its accounting rather than left to look like a clean run. The transferable rule is that silence is not absence: a result must say when the evidence it saw was produced. `wazuh_bridge.py` applies that rule to the bounded alert tail it reads. With `--max-age-days N` it reports the age of the newest alert it actually parsed and adds a fourth `freshness` check to the confirmation worksheet:

```bash
python wazuh_bridge.py --input alerts.jsonl --checks --max-age-days 7 > checks.csv
python wazuh_bridge.py --input alerts.jsonl --max-age-days 7 --out report.json
```

The check uses the shared closed vocabulary: `confirmed` means a parseable newest timestamp was within the limit, `not_confirmed` means it breached the limit or no alert timestamp could be parsed, and a failed read leaves `freshness` out of the worksheet entirely (the existing `tail`/`parse` checks already fail closed). A breach exits `2`, the same fail-closed status as an unreadable source, so a stale or unparseable tail can never be consumed as "no alerts". The JSON report carries `freshness` (with `status`, `newest`, `age_days`, `max_age_days` and a short `detail`), the `newest_alert_timestamp` and `newest_alert_age_days` fields, and the same `checks` array; the stdout summary adds `freshness` when the flag is set.

The flag is opt-in: without `--max-age-days` no freshness field or row is added, so existing consumers keep the same three-check worksheet and byte-stable output. Age is a property of the supplied alerts, not a verdict about the network: a fresh tail with zero queued alerts still only means "nothing detected by this check" in the window that was read.

### Ground-truth fixture (--selftest)

Wireshark ships TShark as a line-oriented front-end that reuses the same dissection and filtering engine as the interactive GUI, so a scripted run sees exactly what a human sees. `wazuh_bridge.py` applies the one-engine-many-front-ends shape to its own pipeline: `--selftest` drives the very same `fetch` -> `parse_lines` -> `triage` -> `checks` functions as a normal run over a committed alert stream and compares the result to a fixed answer, so a silent regression in parsing or grouping is caught once.

```bash
python wazuh_bridge.py --selftest            # exit 0 on a match, 1 on regression, 2 on unreadable input
python wazuh_bridge.py --selftest --out selftest.json
```

`wazuh_alert_fixture.txt` is a small JSON-lines stream: four alerts (a two-event high-level agent group, a below-threshold group and a top-level single alert) plus one malformed line and a blank line. `wazuh_expect.json` pins the fixture's SHA-256 and records the exact line, alert, malformed, group and queue counts, the ordered queue (agent, source, count, max level, first/last timestamps and rules), and the byte-stable `check,status,detail` worksheet that input must produce. The JSON report carries `mode` (`selftest`), `status`, `fixture`, `fixture_sha256`, `observed_counts` and a `checks` array. Checks use a closed `pass`/`fail`/`error`/`skipped` vocabulary, deliberately separate from the `confirmed`/`not_confirmed`/`skipped` confirmation worksheet: `fixture` and `expectation` verify the committed files were read, `fixture_hash` compares the exact bytes to the pinned SHA-256, `counts` checks all five counts at once, and `queue` and `checks` compare the ranking and worksheet exactly. The pinned hash is a consistency check, not an authenticity or risk claim.

Exit codes mirror the status: `0` for `pass`, `1` for `fail` (a coverage regression in any compared field), `2` for `error` (fixture or expectation unreadable, or a failed pipeline read, fail-closed and never a pass). This is a regression check on the bridge pipeline, not a risk verdict about the fixture: the input is known-noise and the answer is a fixed expectation. `--selftest` needs no other argument and takes precedence over the normal flags; `--out` writes the same JSON to a file. Without it the default path is byte-identical to before and carries no `mode` or `observed_counts` field.

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

### Source provenance

A YAML prompt-injection scoring format states the limit of a checksum plainly: a hash establishes consistency, not authenticity, completeness or causation. `releasegate.py` applies that framing to its decision. The JSON report carries a `source_files` array with one entry for the findings file that was parsed, using the same shape as `timeline.py` and `iocscan.py` so all three tools share one provenance contract:

- `name` - the findings file's basename.
- `bytes` - the exact byte size read from disk.
- `lines` - the count of non-blank UTF-8 lines in those bytes.
- `sha256` - the SHA-256 of the exact bytes that were parsed.

The hash is computed from the single byte read that feeds the parser, so it always describes the bytes that produced the verdict; the file is opened read-only and never modified. Provenance is attached whenever the findings file was readable, including an indeterminate decision from unparsable or out-of-vocabulary evidence, because those bytes were still seen. An unreadable file yields no `source_files` entry at all and is a fail-closed exit `2`: the gate cannot tie a verdict to bytes it never read. The manifest establishes that a decision is consistent with a specific copy of the input; it does not prove that copy is genuine or complete, and scoring adds no maliciousness verdict to the source. `--prioritize` output is unchanged - the CSV remains the ranked findings only, with no provenance rows.

### Evidence age is not provenance

An SBOM generator marks an application stale when its last scan is older than 13 months: a stale item cannot be selected silently, a single-item run exits, and a collection run skips it with a warning. A personal visual archive makes the same distinction in a quieter way - it is a record of a moment that has passed, not a claim about the present. A provenance hash is that kind of record. It binds a decision to the exact bytes that were read, but it says nothing about when those bytes were produced: a findings file from fourteen months ago hashes exactly as it did on the day it was written, and re-hashing it today does not make it current.

By default `releasegate.py` does not check scan age: the verdict describes only the evidence supplied, and a `confirmed` check means a value was evaluated against its limit, not that the evidence is fresh. The opt-in `--max-age-days N` below closes that gap. Without it the JSON report carries no freshness field and the worksheet is unchanged, so age stays an input contract the caller enforces upstream - something neither the hash nor the worksheet can prove. In both modes a hash establishes consistency, not authenticity, completeness or causation, and scoring adds no maliciousness verdict to the source.

### Evidence freshness (--max-age-days)

The same SBOM stale-scan rule that blocks a too-old application is now an explicit boundary on findings. `releasegate.py --max-age-days N` reads a first-observed date from each finding under the first available key (`first_found`, `firstFound`, `first_found_date`, `found_date`, `first_seen`, `discovered`, `date`, `timestamp`), accepts ISO-8601 strings (including `Z`, a space separator and a colonless numeric UTC offset) or epoch seconds, and checks the age of the newest observation against the limit:

```bash
python releasegate.py findings.json --max-age-days 30
python releasegate.py findings.json --max-age-days 30 --checks > checks.csv
```

The `freshness` row uses the shared closed vocabulary. `confirmed` means a parseable newest date was within the limit and the verdict is unchanged. `not_confirmed` means the newest date breaches the limit or no finding has a parseable date; the verdict is forced to `indeterminate` with exit `2` even when every finding count is within limits, `prioritized` is cleared, and the reasons lead with `stale evidence:`. An unreadable file keeps its existing input-error `indeterminate` (exit `2`) and reports `freshness` as `not_confirmed` with `input unreadable; freshness not evaluated` - no separate override.

The JSON report gains `freshness` (`status`, `breach`, `newest`, `age_days`, `max_age_days`, `dated`, `total`, `detail`), `newest_finding_date`, `newest_finding_age_days`, and an appended `freshness` row in `checks`; the `--checks` CSV gains that same row as a ninth line. Age is a necessary but not sufficient condition for a pass: a fresh findings file is still denied if its severities breach a threshold. The flag is opt-in - without it the decision, worksheet and JSON are byte-identical to the default gate (no freshness field, seven checks), so existing consumers are unaffected.

### Confirmation worksheet (--checks)

An SBOM generator marks an application whose last scan is too old as stale and never uses it silently: interactive selection is blocked, a single-item CLI run exits, and a collection run skips the stale item with a warning. The transferable rule is that an input which cannot be used gets an explicit status instead of being counted as clean. `releasegate.py` applies that rule to the checks behind its verdict. Every decision carries a `checks` array with one row per gate check in a fixed order, and `--checks` emits only that array as CSV:

```bash
python releasegate.py findings.json --checks > checks.csv
```

Columns, in order:

- `check` - one of `parse`, `completeness`, `severity_vocabulary`, `cvss_validity`, `max_critical`, `max_high`, `max_total`, plus `freshness` as the last row when `--max-age-days` is set.
- `status` - a closed vocabulary: `confirmed` (the check ran and produced a result, which may still breach a limit), `not_confirmed` (the input could not be trusted or parsed, and is never clean), or `skipped` (the check did not apply to this decision).
- `detail` - a short fact: a count, a limit, the unrecognized severity or the CVSS error. Empty for a skipped check.

An unreadable findings file marks `parse` as `not_confirmed` and leaves every downstream check `skipped`, with exit `2`. A short parse marks `completeness` as `not_confirmed`, an unknown severity marks `severity_vocabulary` as `not_confirmed`, and invalid CVSS marks `cvss_validity` as `not_confirmed`; in each case the thresholds are `skipped` because they were never evaluated. A deny still reports each threshold as `confirmed` with its effective count and limit in `detail`, so `confirmed` means evaluated, not passed. The exit status (`0`/`1`/`2`) is unchanged and still gates on the verdict, and `--prioritize` takes precedence when both flags are supplied. Output is UTF-8 with LF endings and a trailing newline, so a committed worksheet changes only when the decision changes.

### Ground-truth fixture (--selftest)

A deliberately vulnerable sample application ships with its known scan results so a detector can be checked against a fixed answer: the input is intentionally flawed and the published findings are the expected output, not a discovery about a real target. `releasegate.py` applies the same shape with `--selftest`: it scores the committed `releasegate_fixture.json` and compares the result to `releasegate_expect.json`, a ground-truth file recording the limits, canonical buckets, effective buckets and verdict that input must produce.

```bash
python releasegate.py --selftest            # exit 0 on a match, 1 on regression, 2 on unreadable input
python releasegate.py --selftest --out selftest.json
```

The fixture is a small findings array whose low-severity finding carries CVSS 9.8, so a correct gate must upgrade it into the critical bucket and return `deny`. The expectation pins the fixture's SHA-256 (so a byte change is a failure even when the decision is unchanged) and scores the fixture with its own `limits`, independent of `--rules`. The JSON report carries `mode`, `status`, `fixture`, `fixture_sha256`, `verdict` and a `checks` array whose status is a closed vocabulary from `SELFTEST_STATUSES`, deliberately separate from the confirmation statuses above:

- `check` - one of `fixture`, `expectation`, `fixture_hash`, `score`, `verdict`, `total`, `buckets`, `effective_buckets`.
- `status` - `pass` (expectation met), `fail` (a coverage regression, including hash drift), `error` (an input could not be read, fail-closed and never a pass), or `skipped` (no pinned hash to compare).
- `detail` - a short fact: a byte count, a match, or an expected-versus-observed difference.

Exit codes mirror the status: `0` for `pass`, `1` for `fail`, `2` for `error`. This is a regression check on the gate's scoring, not a risk verdict about the fixture: the input is known-noise and the answer is a fixed expectation. `--selftest` needs no file argument, takes precedence over the normal flags, and `--out` writes the same JSON to a file.

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

### IOC source provenance

ATT&CK STIX data ships each collection as a traceable, versioned dataset so a consumer can tie a copy back to an exact release. `iocscan.py` applies the traceability half in its JSON report: the `source_files` array holds one entry for the capture that produced the observables, using the same shape as `timeline.py` so both tools share one provenance contract:

- `name` - the capture file's basename.
- `bytes` - the capture size in bytes.
- `lines` - the number of non-blank lines parsed from the capture.
- `sha256` - the SHA-256 of the exact bytes read, covering the same single read that was scanned.

The hash is computed from the one byte read used for extraction, so it always describes the bytes that produced the findings; the source is opened read-only and never modified. Provenance adds no maliciousness verdict: suppression of private ranges and deduplication stay evidence transformations, not judgments. An unreadable capture has no provenance entry and is a fail-closed exit `2`. `--prioritize` output is unchanged - the CSV remains observables only, with no provenance rows.

### Ground-truth fixture (--selftest)

A deliberately vulnerable sample application ships with its known scan results so a detector can be checked against a fixed answer: the input is intentionally flawed and the published findings are the expected output, not a discovery about a real target. `iocscan.py` applies the same shape with `--selftest`: it scans the committed `ioc_fixture.txt` and compares the result to `ioc_expect.json`, a ground-truth file recording the observables that input must produce.

```bash
python iocscan.py --selftest            # exit 0 on a match, 1 on regression, 2 on unreadable input
python iocscan.py --selftest --out selftest.json
```

The check emits one JSON document on stdout (no `--out`) with `status` and a `checks` array. `status` is `pass`, `fail` or `error`, and each check carries a `check`, `status` and short `detail`:

- `fixture` - `pass` with the input's byte count, or `error` if it cannot be read.
- `expectation` - `pass` once the ground-truth file is loaded, or `error` if it is missing or malformed.
- `fixture_hash` - `pass` when the input's SHA-256 matches the hash pinned in `ioc_expect.json`, `fail` on drift even if the observables still match, or `skipped` if no hash is pinned. The pin makes the answer valid for those exact bytes only.
- `count` - `pass` when the observed observable count equals the expected count.
- `observables` - `pass` on an exact match of `(type, value, lines)` sets, otherwise `fail` with the number missing or unexpected.

Exit codes mirror the status: `0` for `pass`, `1` for `fail` (a coverage regression), `2` for `error` (fixture or expectation unreadable, fail-closed and never a pass). This is a regression check on the detector, not a risk verdict about the fixture: the input is known-noise and the answer is a fixed expectation. `--selftest` needs no file argument and takes precedence over the normal scan flags; `--out` writes the same JSON to a file.

### Timeline review handoff (--prioritize)

A local identity-timeline tool keeps a compact worksheet of records that need review beside its full evidence workbook, and never discards a matching record just because it is out of policy: an unusual dwell is flagged for the analyst, still listed in the ordered activity. `timeline.py --prioritize` applies the same shape with a documented schema and no JSON envelope or prose. stdout carries only the session summaries as CSV:

```bash
python timeline.py alerts.jsonl --gap 900 --max-span 3600 --prioritize > sessions.csv
```

Columns, in order:

- `session` - the 1-based session position in chronological order.
- `source` - the source key that grouped the session (`source`, or `srcip` when absent).
- `event_count` - number of events in the session.
- `long_dwell` - lowercase `true` or `false`; `true` when the session span exceeded `--max-span` and needs review.

One row is emitted per session, so a flagged dwell is handed off for review but never dropped: the CSV is a complete view of the grouped evidence, and the JSON report stays the authoritative record. Rows follow the deterministic chronological order of the JSON groups, so the first data row is the earliest session. Output is UTF-8 with LF endings and a trailing newline, so a committed handoff changes only when sessions change and never produces a platform-newline diff. `--out` writes the same bytes to a file instead of stdout. The exit status is unchanged: `1` when any session has a long dwell, `0` otherwise, so a caller can still gate on dwell policy while giving the CSV to a reviewer.

### Source provenance

A local identity-timeline tool keeps a source-files worksheet beside the review worksheets: source metadata and SHA-256 hashes let an analyst tie a finished timeline back to the exact input it was built from, and the tool never modifies the source. `timeline.py` applies the same rule in its JSON report. The `source_files` array holds one entry per input with:

- `name` - the source file's basename.
- `bytes` - the source size in bytes.
- `lines` - the number of non-blank lines parsed from the source.
- `sha256` - the SHA-256 of the exact bytes read, covering the same read that was grouped.

The hash is computed from the single byte read used for parsing, so it always describes the bytes that produced the sessions. The source is opened read-only, and grouping never adds a maliciousness verdict: a long dwell stays a review flag, not a finding. Because the manifest is derived from input bytes, an unchanged source produces identical provenance on every run.

### Confirmation worksheet (--checks) across all five tools

An open-source IDS exposes one uniform CLI over a single detection engine: the same front-end verbs inspect events and enforce decisions, and its scenario hub states explicitly which rules were selected. The transferable piece is a consistent command-line contract, not a shared implementation. Every sentinel detection tool now exposes the same `--checks` verb: `sentinel.py`, `releasegate.py`, `iocscan.py`, `timeline.py` and `wazuh_bridge.py` each emit a per-check confirmation worksheet on stdout with no JSON envelope and no prose, and each adds the same array to its JSON report.

```
python iocscan.py capture.txt --checks > checks.csv
python timeline.py alerts.jsonl --gap 900 --checks > checks.csv
python wazuh_bridge.py --input alerts.jsonl --checks > checks.csv
```

The normalizer and timeline use the `check,status,detail` shape already defined by `releasegate.py` (the tool-oriented `sentinel.py` worksheet stays `tool,status,findings`). `status` is always from the same closed vocabulary:

- `confirmed` - the check ran and produced a result; a zero count is still confirmed and means nothing was detected by that check, not that no risk exists.
- `not_confirmed` - the check's input could not be read or trusted; never clean, and it cannot be confused with a confirmed zero.
- `skipped` - the check did not apply; `detail` records why, so an absent check is never silently dropped.

`iocscan.py` reports `parse`, `completeness` and `provenance`: an unreadable capture marks `parse` `not_confirmed` and `provenance` `skipped`, a short `--expect` parse marks `completeness` `not_confirmed`, and no claimed total marks it `skipped`. `timeline.py` reports `parse`, `dwell` and `provenance`, with the long-dwell count stated even when it is zero. `--prioritize` takes precedence over `--checks` when both are given, exit status is unchanged (`0`/`1`/`2`) and still gates on findings, and the `--prioritize` CSV stays observables-only or session-summaries-only with no check rows. Output is UTF-8 with LF endings and a trailing newline, so a committed worksheet changes only when the checks change.

`wazuh_bridge.py` reports `tail`, `parse` and `grouping`, mirroring the Wazuh collect/decode/analyze path: a readable alert source makes `tail` and `parse` `confirmed` and `grouping` `confirmed` with its group and queue counts, while an unreadable source makes `tail` and `parse` `not_confirmed`, leaves `grouping` `skipped` and exits `2`. `--input` reads a local UTF-8 JSON-lines file instead of the WSL tail so the worksheet can be produced and tested offline; without it a failed WSL read is also fail-closed. Its JSON report carries the same `checks` array, and the default JSON path still writes the full triage result to `wazuh_queue.json` while the summary goes to stdout.

### Observed window (--coverage)

A read-only investigation console reports a status for each lookup and states plainly that a result is bounded by the objects visible to the current security context; an OU-derived department is labelled inferred, never authoritative. The transferable rule is that a result must carry the boundary of what it actually observed. `timeline.py --coverage` applies it to session grouping: it records the oldest and newest parseable event and the whole-second span between them, and appends a fourth `coverage` row to the confirmation worksheet so a zero long-dwell count is stated beside the window it was counted over.

```
python timeline.py alerts.jsonl --coverage --checks > checks.csv
```

The JSON report gains `oldest_event`, `newest_event` and `observation_span_seconds` (all null when no event timestamp could be parsed). The `coverage` row uses the shared closed vocabulary: `confirmed` when a newest event and span were observed, with `detail` as `newest <timestamp>; span <seconds>s`; `not_confirmed` when the input was read but no event timestamp parsed; `skipped` when the input was unreadable, where the existing `parse` and `provenance` checks already fail closed. The flag is opt-in: without `--coverage` the JSON report and the three-check worksheet are byte-identical to the default, so existing consumers are unaffected. A confirmed zero long dwell still means nothing was detected by that check over that window, not that no dwell risk exists.

### Ground-truth fixture (--selftest)

ILSpy exposes one decompiler engine through several front-ends - a desktop UI, editor extensions, the `ilspycmd` CLI, a dotnet tool, PowerShell cmdlets and NuGet packages - all consuming the same core, so a regression in the engine shows up through every one of them. `timeline.py` applies the one-engine-many-front-ends shape with a fixed ground truth: `timeline_fixture.txt` is a known event stream and `timeline_expect.json` records the limits and sessions it must produce. `--selftest` groups the committed fixture and compares the result to that answer, so a silent regression in grouping, long-dwell flags or counts is caught once and guards the JSON report, `--prioritize` and `--checks` together.

```
python timeline.py --selftest            # exit 0 on a match, 1 on regression, 2 on unreadable input
python timeline.py --selftest --out selftest.json
```

The JSON report carries `mode` (`selftest`), `status`, `fixture`, `fixture_sha256`, `gap_seconds`, `max_span_seconds`, `expected_sessions`, `observed_sessions` and a `checks` array. Checks use a closed `pass`/`fail`/`error`/`skipped` vocabulary, deliberately separate from the `confirmed`/`not_confirmed`/`skipped` confirmation worksheet: `fixture` and `expectation` verify the committed files were read, `fixture_hash` compares the exact bytes to a pinned SHA-256, `parse` records the event count, and `sessions`, `long_dwell` and `groups` compare the grouping exactly (source, event count, span seconds and long-dwell flag per session). The pinned hash is a consistency check, not an authenticity or risk claim. Exit codes mirror the status: `0` for `pass`, `1` for `fail` (a coverage regression), `2` for `error` (fixture or expectation unreadable, or invalid JSON, fail-closed and never a pass). This is a regression check on the grouping engine, not a risk verdict about the fixture. `--selftest` needs no file argument, takes precedence over the normal flags, and `--out` writes the same JSON to a file. Without it the default path is byte-identical to before.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request. It executes the
unit tests, then probes the gate twice: `headerscheck` on `sample.txt` must exit
`1` (missing security headers) and on `ci/clean_headers.txt` must exit `0`
(complete header set). Both probes also assert that the JSON envelope is
parseable.

## Limits

Each check reports what its rules can see in the supplied file. A clean result is not proof of safety, and a finding is not a verdict. The bridge reads the alerts log file, not the Wazuh API.

### Scope and limits

A personal music server states its reach in one place - what it serves locally, what changes when it runs elsewhere, and plainly what it does not provide (no login, no built-in HTTPS, so anyone who can reach the port can listen). The transferable rule is to put the boundary beside the capability, in the terms a user needs to decide whether the tool fits. Sentinel states the gate's boundary in the same terms:

- **Input scope:** the gate reads only the findings file it is given. It makes no network calls, contacts no scanner or ticketing system, and stores no credentials. Its view is limited to the bytes it was handed; the Wazuh bridge reads the alerts log file, not the Wazuh API.
- **Meaning of a result:** an `allow`, or a `confirmed` zero in a worksheet, is a limit evaluation over exactly that input, not an assertion that no risk exists in the system the findings came from. A threshold can only measure the evidence supplied.
- **What the boundary excludes:** a clean result cannot speak to findings the file omits, findings produced after it was written, or severities the vocabulary could not map - those make the decision indeterminate, never a pass. Stale or truncated evidence is pending, not clean.

These limits are properties of the input contract, not defects to fix in code. Supplying a complete, current findings file is the caller's responsibility. The gate reports the limits it applied so a reviewer can see exactly what was, and was not, evaluated.

### Evidence level is not an effect

An agent-action verification tool draws a line between a requested action, a reported execution and an observed effect, and confirms only at the evidence level the scenario requires: a reported action need not establish an effect, and a negative result does not prove security. It also states that a hash and a recomputation check a record's consistency, not authenticity, real-world events or causation. Sentinel applies the same ladder to what its checks can establish:

- **Observed by the tool:** a `confirmed` check means the tool read its input and computed a result over those bytes. The parse, grouping and hash it reports are effects the tool itself produced from the supplied file.
- **Reported by upstream:** the findings, observables and events in that file are claims from a scanner, log or operator. Sentinel does not execute them, contact a target or replay them, so it cannot promote a reported finding into an observed real-world effect.
- **Bounded verdict:** an `allow`, a `pass` or a confirmed zero is a negative result at the tool's own evidence level - it means no matching evidence was found in the input, not that no risk exists. Like a "no breach observed" verdict, it is limited to the evidence level the input could support.

This is an interpretation rule behind the outputs, not a change to any exit code or field. It is why a provenance hash establishes byte consistency rather than authenticity, and why a check can be `confirmed` while the finding behind it stays reported rather than observed.
