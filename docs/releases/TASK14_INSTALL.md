# ScoutSuite RC9 — side-by-side install and read-only acceptance

Requires Windows 11, PowerShell 7 and Python 3.11. Use published `fork-v5.14.0-m10-rc9` only after successful exact-master CI and release publication. RC9 changes only `.venv-scout-fork-rc9`; Stable .venv-scout untouched.

## Install RC9

```powershell
git checkout master
git pull --ff-only origin master
$toolkit = Join-Path $HOME 'Documents\\Security Tools\\aws-audit-newclient-starter'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\install-fork.ps1 -FromRelease -ReleaseTag fork-v5.14.0-m10-rc9 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --help
```

Installer verifies SHA256SUMS, manifest, exact wheel/constraints hashes, installed package version, `pip check`, CLI help and records `fork-install.json`. Co-hosted checksums are not independent signatures. A failed install removes only its new RC9 directory.

## Rollback

| Mode | Environment | Note |
| --- | --- | --- |
| `Fork` | `.venv-scout-fork-rc9` | Latest RC9 candidate |
| `ForkRc8` | `.venv-scout-fork-rc8` | Field-accepted RC8; stores raw EC2 user data and Lambda environment values, no Secrets Manager or ALB WAF rules |
| `ForkRc7` | `.venv-scout-fork-rc7` | Field-accepted RC7; Security Hub not-subscribed and IAM-limited Macie disabled states stay UNKNOWN |
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
$report = Join-Path $toolkit 'reports\\scout-fork\\rc9-manual'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\invoke-selected-scout.ps1 -ToolkitRoot $toolkit aws --profile newclient-scanners --regions eu-central-1 --no-browser --report-dir $report --report-name rc9-aws
```

Optional, only with the client's agreement that its domain names may be sent to the local DNS resolver: add `--external-waf-dns` (ACM certificate names) and/or `--waf-domains <names>` to list what fronts each public domain. Air-gapped runs add `--no-cdn-range-update`.

Record exit code, RDS snapshot counts, collector issue identities (RC5 hotfix had 41), incomplete/UNKNOWN status, service coverage, new and lost rule-resource findings (versus RC8, expect services with an empty, fully collected inventory to show "Not in use", Secrets Manager rotation/unused/policy findings, masked user-data and Lambda/ECS environment secret detections instead of raw values, and `elbv2-internet-facing-alb-without-waf` for ALBs open to the internet without AWS WAF), the start-up CDN range source per provider (live or bundled), and report consistency via `tools/audit_scan_evidence.py --fail-on-discrepancy`. Exit 0 does not establish completeness; `--strict-completeness` optionally returns 201 when evidence is incomplete. Never publish raw client evidence to GitHub.
