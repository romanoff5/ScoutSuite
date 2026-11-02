# ScoutSuite RC4 — Ridgepay install, non-mutating preflight and rollback

RC1/RC2/RC3 published GitHub releases are immutable. RC4 adds candidate
CIS AWS Foundations v7.1.0 rules, reviewed against RC3 private field
evidence. Requirements: Windows 11, PowerShell 7, Python 3.11.

## Install RC4 side by side

From an updated trusted local clone of `romanoff5/ScoutSuite`:

```powershell
git checkout master
git pull --ff-only origin master
$toolkit = Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-fork.ps1 `
  -FromRelease -ReleaseTag fork-v5.14.0-m10-rc4 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 `
  -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-selected-scout.ps1 `
  -ToolkitRoot $toolkit aws --help
```

The installer verifies release SHA256SUMS, pinned wheel, manifest and
runtime-py311 constraints, version, `pip check` and CLI help, and writes
`fork-install.json` with package/executable provenance. Release assets use
a distinct RC4 tag; the existing `.venv-scout-fork-rc3` remains untouched.
Checksums co-hosted on GitHub do not establish third-party signatures.

The explicit rollback targets are:
- `Fork`: new RC4, `.venv-scout-fork-rc4`
- `ForkRc3`: prior RC3, `.venv-scout-fork-rc3`
- `ForkRc2`: prior RC2, `.venv-scout-fork-rc2`
- `ForkRc1`: prior RC1/hotfix, `.venv-scout-fork`
- `Stable`: existing stable, `.venv-scout`

Example rollback without uninstalling or modifying existing reports:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 `
  -Mode ForkRc3 -ToolkitRoot $toolkit
```

The launcher validates matching provenance, scanner version and
executable SHA256 for RC4/RC3/RC2. The separate external Ridgepay
launcher must be explicitly configured to invoke
`scripts/invoke-selected-scout.ps1`; the selector does not magically
replace a hardcoded path to scout.exe.

## Authorized AWS read-only preflight

Only authorized, explicitly scoped assessment operations may access the
client account; these steps do not grant cloud access to CI or the installer.

1. Validate the expected client account using
   `aws sts get-caller-identity --profile <audit-profile>` and a
   separately approved cross-account IAM role. Do not log credentials.
2. Run an approved single-Region AWS scan with `--no-browser`
   into a unique private output directory. Do not interpret exit 0 as
   complete collection.
3. Compare collected service/Region coverage, API exceptions, all
   `collection_status.issues`, evidence statuses and resolved findings.
4. Verify RDS instance vs DB cluster deletion protection separately.
   RC3 evidence showed Aurora member instances; RC4 assesses the DB
   cluster once via `rds:DescribeDBClusters`. Missing access is
   partial/UNKNOWN, never a clean pass.
5. Run the offline consistency audit against local RESULTS:
   ```powershell
   python -B .\tools\audit_scan_evidence.py `
     "C:\private\path\scoutsuite_results.js" --fail-on-discrepancy
   ```
   It performs no cloud calls and outputs only aggregate rule identifiers
   and counts, not account IDs, ARNs or resource identifiers.
6. For CIS v7.1.0 candidate crosswalks, optionally use
   `--ruleset cis-foundations-7.1.0-partial` in a separate approved
   scan or local assessment, while remembering that 94 control IDs
   include manual/partial/unimplemented items. Do not compute CIS
   compliance percentage from the candidate profile.

The remaining 40 collection issues in the RC3 Ridgepay scan were
predominantly Organizations/Identity Center/Macie/Backup/SSM/Bedrock,
Security Hub/Inspector and S3 permissions/incomplete evidence. They
are not remedied by installing RC4. A verified ECR BASIC registry
configuration with zero repositories is an informational observation,
not proof of unscanned images.

No real client AWS scanning is performed by CI or installer. No
credential files or private client evidence are bundled into wheel.
Stable .venv-scout untouched.
