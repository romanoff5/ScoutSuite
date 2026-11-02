# ScoutSuite RC6 — side-by-side install and read-only acceptance

Requires Windows 11, PowerShell 7 and Python 3.11. Use published `fork-v5.14.0-m10-rc6` only after successful exact-master CI and release publication. RC6 changes only `.venv-scout-fork-rc6`; Stable .venv-scout untouched.

## Install RC6

```powershell
git checkout master
git pull --ff-only origin master
$toolkit = Join-Path $HOME 'Documents\\Security Tools\\aws-audit-newclient-starter'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\install-fork.ps1 -FromRelease -ReleaseTag fork-v5.14.0-m10-rc6 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --help
```

Installer verifies SHA256SUMS, manifest, exact wheel/constraints hashes, installed package version, `pip check`, CLI help and records `fork-install.json`. Co-hosted checksums are not independent signatures. A failed install removes only its new RC6 directory.

## Rollback

| Mode | Environment | Note |
| --- | --- | --- |
| `Fork` | `.venv-scout-fork-rc6` | Latest RC6 candidate |
| `ForkRc5` | `.venv-scout-fork-rc5` | Published RC5 has known RDS defect; historical use only |
| `ForkRc4` | `.venv-scout-fork-rc4` | Prior candidate |
| `ForkRc3` | `.venv-scout-fork-rc3` | Prior field baseline |
| `ForkRc2` | `.venv-scout-fork-rc2` | Earlier candidate |
| `ForkRc1` | `.venv-scout-fork` | RC1/hotfix |
| `Stable` | `.venv-scout` | Unmodified stable |

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode ForkRc3 -ToolkitRoot $toolkit
```

Selector does not change any external launcher hardcoded to an executable; selected invoker checks provenance and executable hashes before startup.

## Authorized non-mutating AWS preflight and field run

No real client AWS scanning is performed by CI or installer. Run only authorized read-only AWS assessments: confirm written authorization, account and Region explicitly. Example under the existing assessed profile:

```powershell
aws sts get-caller-identity --profile newclient-scanners
$report = Join-Path $toolkit 'reports\\scout-fork\\rc6-manual'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --profile newclient-scanners --regions eu-central-1 --no-browser --report-dir $report --report-name rc6-aws
```

Record exit code, RDS snapshot counts, collector issue identities (RC5 hotfix had 41), incomplete/UNKNOWN status, service coverage, new and lost rule-resource findings, and report consistency via `tools/audit_scan_evidence.py --fail-on-discrepancy`. Exit 0 does not establish completeness; `--strict-completeness` optionally returns 201 when evidence is incomplete. Never publish raw client evidence to GitHub.
