# ScoutSuite RC7 — side-by-side install and read-only acceptance

Requires Windows 11, PowerShell 7 and Python 3.11. Use published `fork-v5.14.0-m10-rc7` only after successful exact-master CI and release publication. RC7 changes only `.venv-scout-fork-rc7`; Stable .venv-scout untouched.

## Install RC7

```powershell
git checkout master
git pull --ff-only origin master
$toolkit = Join-Path $HOME 'Documents\\Security Tools\\aws-audit-newclient-starter'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\install-fork.ps1 -FromRelease -ReleaseTag fork-v5.14.0-m10-rc7 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --help
```

Installer verifies SHA256SUMS, manifest, exact wheel/constraints hashes, installed package version, `pip check`, CLI help and records `fork-install.json`. Co-hosted checksums are not independent signatures. A failed install removes only its new RC7 directory.

## Rollback

| Mode | Environment | Note |
| --- | --- | --- |
| `Fork` | `.venv-scout-fork-rc7` | Latest RC7 candidate |
| `ForkRc6` | `.venv-scout-fork-rc6` | Published RC6 misses S3 backup gap findings in Regions without AWS Backup; comparison only |
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
$report = Join-Path $toolkit 'reports\\scout-fork\\rc7-manual'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --profile newclient-scanners --regions eu-central-1 --no-browser --report-dir $report --report-name rc7-aws
```

Record exit code, RDS snapshot counts, collector issue identities (RC5 hotfix had 41), incomplete/UNKNOWN status, service coverage, new and lost rule-resource findings (versus RC6, S3 buckets in Regions without AWS Backup should regain `m10q-s3-backup-evidence-gap`), and report consistency via `tools/audit_scan_evidence.py --fail-on-discrepancy`. Exit 0 does not establish completeness; `--strict-completeness` optionally returns 201 when evidence is incomplete. Never publish raw client evidence to GitHub.
