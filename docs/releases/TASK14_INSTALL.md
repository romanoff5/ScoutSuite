# ScoutSuite fork — install from origin/master and read-only acceptance

Requires Windows 11, PowerShell 7, Git and Python 3.11. There are no release candidates or GitHub releases any more (removed 2026-11-03 at the owner's request): every install is built from the commit that `origin/master` of `romanoff5/ScoutSuite` points to at install time. Each commit installs side by side into `.venv-scout-fork-main-<first 12 SHA characters>`; Stable .venv-scout untouched, and RC environments stay selectable for rollback.

## Install the current origin/master

```powershell
$toolkit = Join-Path $HOME 'Documents\\Security Tools\\aws-audit-newclient-starter'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\install-fork.ps1 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --help
```

The installer confirms that `origin` is `romanoff5/ScoutSuite`, fetches `master`, checks that the fetched SHA equals `git ls-remote origin refs/heads/master`, and builds a wheel with the pinned build frontend from `git archive` of that exact commit (tracked files only; local uncommitted edits never enter the build). It then installs the wheel with `constraints/combined-py311.txt`, runs `pip check`, checks the installed version and `scout --help` / `scout aws --help`, writes `fork-install.json` (commit, wheel, constraints and `scout.exe` SHA256) and selects the new install as `Fork`. Pass `-NoSelect` to keep the current selection. Rerunning on an unchanged `origin/master` only reselects the existing install. A failed install removes only its own new directory.

The installer does not wait for GitHub CI. Run the local offline gates before pushing (see `MODERNIZATION_PROGRESS.md`); CI on `master` remains a post-push check.

## Rollback

```powershell
# Newest origin/master install, or a specific earlier commit (7–40 hex characters):
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode Fork -GitSha 1a2b3c4 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode ForkRc9 -ToolkitRoot $toolkit
```

| Mode | Environment | Note |
| --- | --- | --- |
| `Fork` | `.venv-scout-fork-main-<sha12>` | origin/master build; newest by default, `-GitSha` pins one |
| `ForkRc9` | `.venv-scout-fork-rc9` | Last published RC; records Redshift/ElastiCache VPC-only answers as incomplete (fixed on master in `f62cdbb0`) |
| `ForkRc8` | `.venv-scout-fork-rc8` | Stores raw EC2 user data and Lambda environment values, no Secrets Manager or ALB WAF rules |
| `ForkRc7` | `.venv-scout-fork-rc7` | Security Hub not-subscribed and IAM-limited Macie disabled states stay UNKNOWN |
| `ForkRc6` | `.venv-scout-fork-rc6` | Misses S3 backup gap findings in Regions without AWS Backup; comparison only |
| `ForkRc5` | `.venv-scout-fork-rc5` | Known RDS defect; historical use only |
| `ForkRc4` | `.venv-scout-fork-rc4` | Prior candidate |
| `ForkRc3` | `.venv-scout-fork-rc3` | Prior field baseline |
| `ForkRc2` | `.venv-scout-fork-rc2` | Earlier candidate |
| `ForkRc1` | `.venv-scout-fork` | RC1/hotfix |
| `Stable` | `.venv-scout` | Unmodified stable |

A selection file written before this change (`"schema": 1, "mode": "fork"`) still launches RC9. The selector does not change any external launcher hardcoded to an executable; the selected invoker checks provenance, the selected commit and the executable hash before startup. Old `.venv-scout-fork-main-*` directories are never removed automatically; delete ones you no longer need by hand.

## Authorized non-mutating AWS preflight and field run

No real client AWS scanning is performed by CI or installer. Run only authorized read-only AWS assessments: confirm written authorization, account and Region explicitly. Example under the existing assessed profile:

```powershell
aws sts get-caller-identity --profile newclient-scanners
$report = Join-Path $toolkit 'reports\\scout-fork\\main-manual'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --profile newclient-scanners --regions eu-central-1 --no-browser --report-dir $report --report-name fork-aws
```

Optional, only with the client's agreement that its domain names may be sent to the local DNS resolver: add `--external-waf-dns` (ACM certificate names) and/or `--waf-domains <names>` to list what fronts each public domain. Air-gapped runs add `--no-cdn-range-update`.

Record the installed commit (`fork-install.json`), exit code, collector issue identities, incomplete/UNKNOWN status, service coverage, new and lost rule-resource findings versus the previous field run, the start-up CDN range source per provider (live or bundled), and report consistency via `tools/audit_scan_evidence.py --fail-on-discrepancy`. Exit 0 does not establish completeness; `--strict-completeness` optionally returns 201 when evidence is incomplete. Never publish raw client evidence to GitHub.
