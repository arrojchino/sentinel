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

Input is a local file. Output is a JSON envelope with `schema_version`, `team`, `input` and per-tool findings. Stdlib only; no network, no writes to the input. Exit code is 1 when any check reports findings, so it works as a CI gate.

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

`releasegate.py` turns a findings JSON array or an envelope into `allow`/`deny`, with exit 0 or 1.

## Limits

Each check reports what its rules can see in the supplied file. A clean result is not proof of safety, and a finding is not a verdict. The bridge reads the alerts log file, not the Wazuh API.
