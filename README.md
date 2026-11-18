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
```

Input is a local file. Output is a JSON envelope with `schema_version`, `team`, `input` and per-tool findings. Stdlib only; no network, no writes to the input.

## Limits

Each check reports what its rules can see in the supplied file. A clean result is not proof of safety, and a finding is not a verdict.
