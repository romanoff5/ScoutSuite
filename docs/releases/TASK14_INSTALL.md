# ScoutSuite RC3 — Ridgepay install, read-only preflight and rollback

The published RC1 and RC2 releases are immutable. RC3 is a new candidate
including a real-scan ECR false-negative correction and offline report
consistency utility. Requirements: Windows, PowerShell 7, CPython 3.11.

## Install the verified RC3 release side-by-side

From the trusted `romanoff5/ScoutSuite` clone:

```powershell
git checkout master
git pull --ff-only origin master
$toolkit = Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-fork.ps1 `
  -FromRelease -ReleaseTag fork-v5.14.0-m10-rc3 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 `
  -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\invoke-selected-scout.ps1 `
  -ToolkitRoot $toolkit aws --help
```

The installer verifies SHA256SUMS, manifest, pinned Python 3.11 constraints
and the wheel before creating `<ToolkitRoot>\.venv-scout-fork-rc3`.
It performs `pip check`, CLI smoke and records provenance and executable
SHA256. Hashes distributed by the same publisher are not cryptographic
signatures. Windows Group Policy may prohibit an execution-policy override.
No credentials, AWS API calls or scans are performed by installation.

Existing environments are preserved:
- RC3: `.venv-scout-fork-rc3`
- RC2: `.venv-scout-fork-rc2`
- RC1/hotfix: `.venv-scout-fork`
- Stable: `.venv-scout`

To explicitly change scanner or roll back without deleting reports:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode ForkRc2 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode ForkRc1 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode Stable -ToolkitRoot $toolkit
```

`Fork` selects RC3; `ForkRc2` selects existing RC2. Invalid configuration
or missing provenance is rejected rather than silently switching versions.
The external Audit Toolkit must be deliberately wired to
`scripts/invoke-selected-scout.ps1` if its existing hardcoded invocation
otherwise bypasses selection.

## Authorized Ridgepay preflight

1. Check source Identity Center authentication and configured profile, region
   and expected cross-account role. Do not print credentials. Confirm the
   read-only role and any ExternalId.
2. Verify `aws sts get-caller-identity --profile <audit-profile>` and
   expected account context before scanning.
3. Run a **single approved Region** with `--no-browser` into a separate
   output directory; avoid concurrent scans writing the same report files.
4. Inspect account/region identity, collection status, exceptions and
   service-level API gaps. Exit code 0 is not complete collection.
5. Run the postscan offline evidence integrity checker against the local
   RESULTS JS file:

   ```powershell
   python -B .\tools\audit_scan_evidence.py `
     "C:\path\to\private\scoutsuite-results\scoutsuite_results_<id>.js" `
     --fail-on-discrepancy
   ```

6. Review JSON/SQLite/HTML, especially ECR BASIC/ENHANCED rule alignment,
   Inspector2 coverage stats, SSM Patch Baselines, Identity Center,
   Organizations, Security Hub, Macie, Bedrock, advanced S3 and Backup.
   AccessDenied and unsupported/partial are neither PASS nor evidence of
   absent security controls.

The offline checker writes no report or other files, makes no network calls
and prints only rule names and numeric counts. Keep full reports and any
manual validation results local. All cloud calls require an authorized
read-only invocation; no credential use is part of CI.

## Troubleshooting and recovery

The default selection is stable if no selection file exists.
`ForkRc2` is the recommended explicit rollback to the preceding fixed fork.
RC1 was known to have missing evidence-policy evaluators unless the separate
runtime hotfix is installed. Do not delete virtual environments, credentials,
client reports or preexisting assets in an automated fallback.

Detailed evidence: [RIDGEPAY_RC1_FIELD_FEEDBACK.md](RIDGEPAY_RC1_FIELD_FEEDBACK.md).
