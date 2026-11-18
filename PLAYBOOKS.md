# Blue Team Coverage Audit

## Scope

Reviewed the 69 focused check repositories and the local appsec finding ledger. Every repository runs one stdlib engine: a single local input file, a `rules.json`, and a fixed JSON envelope. Across the set there are seven rule modes: regex (26), jsonfields (19), headers (11), csvcols (9), states (2), hash (1), allowlist (1).

The blue-team-relevant subset is small: the alert-field checker, the detection-rule validators, the IOC matcher, the timeline builder, the evidence manifest checker, the trace verifier, the evidence-state checker, the firewall and connection parsers, the message hash/header tool, and the finding ledger.

Common pattern: all are offline, single-file, structural validators. None correlate across inputs, recompute integrity, or assign priority. That pattern is the root cause beneath the five gaps below.

Ranking is value vs cost. Every fix is low cost (stdlib Python only, no new packages, no network calls). Order reflects operational value for detection and response.

## Ranked gaps and testable improvements

### 1. Alerts are shape-checked, never triaged - High value / Low cost

Gap: The alert-field checker only confirms that required JSON fields exist. A high-severity alert and a low-severity alert look identical to downstream tooling; repeated alerts from one agent or source address are not grouped. There is no severity mapping, no priority order, and no dedup, so the detection-to-response handoff stays manual and slow.

Improvement: Add a small stdlib script that reads the alert JSON array, maps each rule level to a priority number held in `rules.json`, groups alerts by (agent, source address), and prints a prioritized queue with repeat counts plus first and last timestamps.

Test: Feed three alerts (one high level, two low level from one source); assert the high-level alert ranks first and the two low-level alerts collapse into one entry with count 2.

### 2. IOC matching is noisy and unnormalized - High value / Low cost

Gap: The IOC matcher runs two raw regexes (IPv4 and 32-hex strings) and reports every hit. There is no deduplication, no normalization, no suppression of private or reserved ranges, no line numbers, and no support for domains, URLs, or longer hashes. Analysts get repeated, low-context hits, which drives alert fatigue and missed true positives.

Improvement: Extend the matcher config with a suppression list (private/reserved ranges and known benign values) and emit deduplicated, typed hits with source line numbers. Keep the same JSON envelope and add a `type` (ip, hash, domain) to each finding.

Test: Feed text with one private address, one repeated public address, and one hex string; assert the private address is suppressed, the public address appears once with two line numbers, and the hash is typed correctly.

### 3. Evidence integrity is asserted, not verified - High value / Low cost

Gap: The evidence manifest checker only verifies that path, hash, size, and role columns exist. It never recomputes the SHA-256 of the referenced files, so a tampered or missing file still passes. The trace verifier checks state and required fields but does not re-hash observed artifacts. For response and forensics this is a broken chain of custody: the manifest proves structure, not integrity.

Improvement: Add a stdlib verifier that walks each manifest row, computes SHA-256 of the file at the recorded path, compares it to the stored hash and size, and reports mismatch, missing file, and unexpected extra file as distinct findings.

Test: Create a temp dir with one matching file, one modified file, and one missing file; assert exactly one mismatch and one missing finding, with zero findings for the matching file.

### 4. Timeline building stops at sorting - Medium value / Low cost

Gap: The timeline builder sorts timestamped events into readable order but performs no analysis. There is no grouping by actor, no session or incident windowing, no deduplication of repeated events, and no dwell-time or gap detection. An analyst still has to read every line to find the attack sequence.

Improvement: Add a stdlib correlation pass over the sorted events that groups them by a configurable key (for example source address), splits groups when the gap exceeds a threshold, and flags groups whose span or event count exceeds a limit.

Test: Feed five events (three close together from one source, two an hour later from another); assert two sessions, the correct split point, and one long-dwell flag.

### 5. Rule validators check shape, not detection coverage - Medium value / Low cost

Gap: The detection-rule validators check for a handful of top-level keys and for rule, strings, and condition markers. Neither checks whether a rule can actually detect anything: empty selections, missing level or technique tags, conditions that reference no field, and dead rules all pass. Weak detections ship as valid rules.

Improvement: Add a stdlib coverage check that parses rule text for an empty selection block, a missing level or technique tag, and a condition that names no selection, then reports each as a finding in the existing envelope.

Test: Feed one complete rule and one rule with an empty selection and no technique tag; assert zero findings for the complete rule and two for the weak one.

## How to use this ranking

Items 1 through 3 directly shorten detection-to-containment time and need only a few dozen lines each. Items 4 and 5 improve analysis quality and rule health but pay off over longer investigations. All five can be added as sibling scripts beside the existing tools, reusing the same rules.json and JSON envelope, so they stay consistent with the current design and can be tested with the same unittest pattern already in use.


# Red Team Coverage Audit — Focused Check Repository Set

## Purpose and scope
Audit of the 69 focused security-check repositories at C:/Users/Garza/repo69_quality/.
Each repo contains README.md, rules.json and tool.py. All 69 tool.py files are byte-identical:
one stdlib engine with seven rule modes (headers, regex, jsonfields, csvcols, hash, states,
allowlist). No tool makes network calls. This is an assurance audit for authorized offensive
work; it adds no exploitation capability and emphasizes authorization and evidence integrity.

## Verification method
Every gap below was reproduced by invoking the checked-in tools with crafted local inputs and
reading the JSON envelope (count/findings) and process exit code. No finding is speculative.

## Ranked gaps and small testable improvements

### G1 — Evidence fields are verified by substring, not by structure  (Value: high / Cost: trivial)
Affected: traceverify, evidencestate (rule mode `states`).
Gap: the engine tests `if key not in str(obj)`. Any occurrence of a required field name inside
an unrelated value (a note or comment) satisfies the check.
Repro: {"state":"ruled_out","note":"mentions reported_execution and observed_effect and tool_call"}
       -> count 0 (false negative); none of the three evidence fields exists as a field.
Why it matters: a trace can be reported as evidence-complete without a recorded observed effect.
Improvement: replace the substring test with a recursive key-presence walk over the parsed object
       (def has_key(obj, k): ...). Test: the payload above must yield three missing_evidence findings.

### G2 — No exit-code gating on findings  (Value: high / Cost: trivial)
Affected: all 69 tools. main() always executes `return 0`.
Repro: outputschema on `{}` -> count 4, exit code 0.
Why it matters: an authorization gate or CI job cannot fail when scope or evidence checks fail;
       findings are advisory only and a failed check looks like a pass to automation.
Improvement: `return 1 if findings else 0`, keeping the JSON envelope on stdout unchanged.
       Test: outputschema on `{}` must exit 1; on a complete envelope must exit 0.

### G3 — Chain of custody records hashes but never verifies them  (Value: high / Cost: low)
Affected: chaincustody (csvcols), emlhash (hash).
Gap: chaincustody only checks that four CSV columns exist; emlhash rules carry no expected hash.
Repro: rows with sha256 "NOT-A-HASH", size -5, nonexistent paths -> count 0.
       emlhash rules keys = [note, type, name], so there is no baseline to compare against.
Why it matters: tampered or substituted evidence is not detected; custody is asserted, not proven.
Improvement: add optional `verify_sha256`/`verify_size` flags to csvcols; when set, validate a
       64-character hex shape, recompute sha256 of each `path`, and compare against `size`.
       Test: flip one byte of a real evidence file and expect a finding.

### G4 — Tool allowlist checks a name, not an authorization decision  (Value: high / Cost: medium)
Affected: toolallow (allowlist), scoperules (jsonfields).
Repro: {"tool":"read_file","target":"production-db","justification":""} -> count 0.
       scoperules with {"type":"domain","value":"*"} -> count 0 (no owner, expiry or target check).
Why it matters: an allowed tool name says nothing about whether the specific target is in scope,
       who approved it, or whether approval is current; offensive actions can drift out of scope.
Improvement: require `scope_ref`, `approver`, `expires_at` fields and validate `expires_at` > today
       with stdlib datetime; for scope_ref, check the target string against a checked-in scope
       file before reporting allowed. Test: a missing or expired approver must produce a finding.

### G5 — Unresolved findings pass the state gate  (Value: medium / Cost: trivial)
Affected: evidencestate (states).
Gap: `open_proof_gap` is listed in `states`, so it is accepted as valid alongside `confirmed`.
Repro: {"state":"open_proof_gap"} -> count 0.
Why it matters: a finding that is explicitly unproven can be reported as complete.
Improvement: add rule key `terminal_states` (default ["confirmed","ruled_out"]) and flag any
       state not in it as `unresolved_state`, while still accepting open_proof_gap as a value.
       Test: open_proof_gap must yield exactly one unresolved_state finding.

## Ranking summary (value vs cost)
1. G1 evidence substring — highest value, cheapest fix; corrects false evidence passes.
2. G2 exit-code gating — one change enables enforcement across the whole set.
3. G3 custody verification — closes the evidence-tamper blind spot at low cost.
4. G4 scope and authorization — greatest protection, needs a scope file and date logic.
5. G5 state gating — small change that prevents false completion of findings.

All proposed changes use only the Python standard library and the existing checked-in inputs;
none requires network access or new offensive capability.


# Yellow Team / AppSec-DevOps Coverage Audit

## Scope and evidence
- Corpus: 69 focused check repos at `repo69_quality/` plus `index.json` (name, purpose, source).
- Each repo ships `README.md`, `tool.py`, `rules.json`, `sample.txt`, `tests/`. Tools are stdlib Python, rule-driven, and emit a JSON envelope.
- "Yellow team" here means governance, architecture, controls, policy-as-code and secure delivery.
- Method: reviewed all 69 indexed purposes and the `rules.json` of decisionlog, outputschema, evidencestate, chaincustody and budgetcheck, then mapped coverage to the governance/delivery lifecycle.

## What is already covered (so gaps are not duplicate work)
- Structured evidence: `outputschema`, `chaincustody`, `traceverify`, `evidencestate`, `decisionlog`.
- Agent and scope guardrails: `budgetcheck`, `toolallow`, `scoperules`, `redactioncheck`, `skilllint`.
- Identity/access controls: `authzmatrix`, `passwordpolicy`, `mfacheck`.
- Detection-as-code and normalization: `sigmacheck`, `yaracheck`, `trivyparse`, `semgrepparse`, `banditparse`, `gitleaksparse`, `manifestcheck` (SARIF).
- Perimeter rules: `firewallparse`, `ruletraceparse`.
- Conclusion: detection and parsing are strong. The missing layer is enforcement, coverage visibility, and delivery provenance.

## Ranked gaps (value vs cost)
| # | Gap | Value | Cost | Ratio |
|---|-----|-------|------|-------|
| 1 | No finding-to-release admission gate | High | Low | Best |
| 2 | No control-to-check coverage map | High | Low | High |
| 3 | No SBOM / dependency provenance check | High | Medium | Good |
| 4 | No fleet-wide conformance/drift check | Medium | Low | Good |
| 5 | No IaC pre-deploy policy lint | Medium | Medium | Lower |

## Gap 1 — No finding-to-decision enforcement (policy-as-code gate)
- Gap: scanners are parsed and envelopes validated, but nothing converts normalized findings into a release decision. Every gate is manual.
- Improvement: `releasegate.py` + `rules.json` with thresholds (`max_critical=0`, `max_high=2`, `max_total=20`). Read a findings JSON array keyed on `severity`, count, compare, emit `{verdict, counts, reasons}`, exit 0 (allow) or 1 (deny). Stdlib `json` only.
- Test: one critical finding -> `verdict=deny`, exit 1; clean/within-threshold fixture -> `allow`, exit 0. Feed it real `trivyparse`/`semgrepparse` output.

## Gap 2 — No control coverage visibility
- Gap: `authzmatrix` checks role decisions, but no inventory links governance controls (e.g. ASVS/NIST-style IDs) to the checks that implement them. "Which controls are untested?" is unanswerable.
- Improvement: `controlmap.py`; `controls.json` = `[{id, tags:[...]}]`. Match tags against `index.json` names and `rules.json` types, compute coverage %, per-control status and uncovered IDs; exit 1 if below a policy floor. Stdlib `json`, `re`.
- Test: two controls, one tag matching an existing check and one matching none -> 50% coverage, one uncovered ID, exit 1 at floor=100.

## Gap 3 — No SBOM / dependency provenance check (secure delivery)
- Gap: `chaincustody` and `traceverify` protect evidence; nothing verifies the build/dependency inventory, so third-party component claims stay unverified.
- Improvement: `sbomcheck.py`; parse a CycloneDX JSON SBOM; `rules.json` requires `bomFormat` >= 1.4 and each component `name`, `version`, `purl` and a non-empty license; flag missing fields and malformed JSON as an explicit error state. Stdlib `json`.
- Test: minimal valid SBOM -> pass; same file with one `purl` removed -> finding; truncated JSON -> error state, not a crash.

## Gap 4 — No fleet-wide conformance/drift check
- Gap: no check that the 69 repos still conform to the standard layout after edits; governance assumes conformance instead of verifying it.
- Improvement: `fleetconform.py`; walk a root dir, require `README.md`, `tool.py`, `rules.json` per repo, parse each `rules.json` and require `name` + `type`; emit a per-repo table and summary, exit 1 on any drift. Stdlib `os`, `json`, `pathlib`.
- Test: run on the real corpus -> 69/69 conform; copy one repo, delete its `rules.json` -> that repo flagged, exit 1.

## Gap 5 — No IaC pre-deploy policy lint (devops)
- Gap: runtime perimeter is covered (`firewallparse`, `ruletraceparse`), but nothing scans Terraform/CloudFormation/YAML text before deploy for public ingress, public buckets or unencrypted storage.
- Improvement: `iacpolicy.py` + `rules.json` regex patterns (e.g. `0\.0\.0\.0/0`, `public-read`, `encrypted\s*=\s*false`); scan text files with `re.I|re.M`, emit findings with file and line number, exit 1 on any match. Stdlib `re`, `pathlib`. Label output as a heuristic text scan, not a full IaC parser.
- Test: fixture with an open security group -> one finding, exit 1; hardened fixture -> zero findings, exit 0.

## Shared conventions for all five
- Follow the existing pattern: one `tool.py`, rule data in `rules.json`, deterministic JSON envelope, stable exit codes, no third-party packages.
- Validate every tool with one pass fixture and one fail fixture; treat inputs as data, never execute content from them.
- Sequence: ship Gap 1 and 2 first (high value, low cost, no new dependencies), then 3 and 4, then 5 last with its heuristic caveat.
