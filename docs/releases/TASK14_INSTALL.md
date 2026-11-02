# ScoutSuite RC2 — Ridgepay installation, preflight and rollback

**Fork-only RC2:** 5.14.0+romanoff5.m10rc2. Published RC1 and the local RC1
hotfix remain immutable. Default RC2 runtime: Windows PowerShell 7+ and Python 3.11.

## Isolated installation

The installer creates only `<ToolkitRoot>\.venv-scout-fork-rc2`.
It never replaces `<ToolkitRoot>\.venv-scout` (stable) or
`<ToolkitRoot>\.venv-scout-fork` (RC1/hotfix).
It refuses to overwrite an existing RC2 installation; do not delete or
replace a working scanner automatically. A failed first installation removes
only the newly created RC2 environment.

From a trusted clone of `romanoff5/ScoutSuite` on Windows:

```powershell
$toolkit = Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'
# Scope execution-policy override to this new PowerShell process (never LocalMachine).
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-fork.ps1 `
  -FromRelease -ReleaseTag fork-v5.14.0-m10-rc2 -ToolkitRoot $toolkit
```

The release installer fetches wheel, `manifest.json`, `SHA256SUMS` and
`runtime-py311.constraints.txt` from this fork's pinned release. It
checks hashes and metadata before installing, performs `pip check` and
CLI help smoke, then records SHA/provenance and executable hash. Independently
verify release SHA256SUMS through a trusted channel; cohosted hashes are not
signatures. Group Policy enforcement can override process execution policy.

For a locally built wheel use the **matching** reviewed source revision:

```powershell
$wheel = (Get-ChildItem .\dist\scoutsuite-5.14.0+romanoff5.m10rc2-*.whl |
    Select-Object -First 1).FullName
$hash = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash
$commit = git rev-parse HEAD
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-fork.ps1 `
  -WheelPath $wheel -CommitSha $commit -ExpectedSha256 $hash -ToolkitRoot $toolkit
```

Local installs use the checkout's `constraints/combined-py311.txt` by
default. The caller must audit and trust the specified source and wheel.

## Explicit selection

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
# Explicit rollback: choose old installed fork, or stable.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode ForkRc1 -ToolkitRoot $toolkit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\select-scanner.ps1 -Mode Stable -ToolkitRoot $toolkit
```

`Fork` selects RC2, `ForkRc1` selects the existing old fork installation,
and `Stable` selects stable ScoutSuite. A missing config defaults to stable;
invalid config refuses to launch. The wrapper checks RC2 executable hash,
package version and provenance before launching. It does not hash-verify every
installed library on each invocation. Use the installed-wheel verification
gate for complete package-byte checks.

To use selection, **explicitly integrate** `scripts/invoke-selected-scout.ps1`
into the external AWS Audit Toolkit. This repository does not silently modify
the toolkit launcher. Without that one-time integration, an existing toolkit
script can continue using its hardcoded scanner.

## Ridgepay read-only preflight (authorized user action)

1. Confirm the configured AWS profile and target role, including ExternalId,
   source Identity Center login and target account. Do not print credentials.
2. Confirm expected Regions, partition, role permissions and any
   `AccessDenied`/SCP restrictions. Use the existing audit scripts and
   `aws sts get-caller-identity --profile <audit-profile>`.
3. Execute a **single authorized read-only smoke scan**, with
   `--no-browser`, isolated report output and no production mutations.
4. Verify account and Region identity, scan exit code, and any
   `collection_issues` or partial service status in JSON/SQLite/HTML.
   Specifically check ECR/Inspector, SSM, Backup, WAFv2, CloudTrail,
   Organizations, Macie and Bedrock when those services are in scope.
5. Review throttling, API access and unsupported services, then run only the
   agreed full scope. Keep client report files local and confidential.

Neither the installer nor CI invokes AWS APIs or looks up credentials. All
cloud preflight actions require authorized user execution.

## Recovery

If the RC2 scanner fails a preflight, switch to `ForkRc1` or `Stable`
with `select-scanner.ps1`; never delete reports, credentials or venvs
automatically. RC1 was known to lack the fixed evidence policies, so the
stable path is preferable to uncorrected RC1 for a fallback assessment.
Do not run two simultaneous scans to the same output directory.

Release notes: [fork-v5.14.0-m10-rc2.md](fork-v5.14.0-m10-rc2.md).
