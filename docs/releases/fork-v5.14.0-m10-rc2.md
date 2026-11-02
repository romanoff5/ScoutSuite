# ScoutSuite fork RC2 — Ridgepay stabilization candidate (2026-11-02)

Repository: romanoff5/ScoutSuite (fork only).
Tag: fork-v5.14.0-m10-rc2
Version: 5.14.0+romanoff5.m10rc2

## Changes against immutable RC1
- Includes the integrated RC1 runtime hotfix (13 formerly unsupported
  Network Firewall/Macie/Bedrock evidence policies and bounded SSM/Network
  Firewall issue codes), with regression tests and installed distribution gate.
- RC2 is installed in `.venv-scout-fork-rc2`, leaving both stable
  `.venv-scout` and existing RC1/hotfix `.venv-scout-fork` unchanged.
  Failed RC2 install removes only the newly created RC2 environment.
- RC2 release includes a pinned `runtime-py311.constraints.txt` in the
  manifest and checksums. The installer verifies wheel, manifest and dependency
  closure hashes before creating the environment, then verifies metadata,
  `pip check` and both CLI help commands.
- Scanner selection supports `Stable`, `Fork` (RC2) and
  `ForkRc1` (retained for explicit rollback). The wrapper rejects invalid
  provenance, missing binaries, mismatched package versions and modified RC2
  executable hashes before scanning.
- Release CI is gated on successful master Windows/Ubuntu Python 3.11/3.14
  offline jobs and independent installed-wheel smoke. No existing tag or
  published release assets are mutated.

## Security and evidence boundaries
- This is a candidate for operational acceptance, **not** proof of a complete
  client assessment. None of the synthetic tests verify the actual AWS role,
  available permissions, service-region coverage, runtime throttling or successful
  collection of all Ridgepay resources.
- Before an authorized Ridgepay production audit, perform an explicit read-only
  identity/permission preflight, test one Region end-to-end, inspect collection
  issues and JSON/SQLite/HTML outputs, then select the required scan Regions.
- Absence of a successful ECR scan, live Backup RPO confirmation, WAF traffic
  measurement or per-member CloudTrail delivery evidence must remain UNKNOWN,
  incomplete or a finding, never a compliant PASS.
- Existing assessments remain confidential and local. No real account IDs,
  contacts, object contents, credentials, test reports or images are packaged.
- SHA256SUMS and Git provenance are integrity records, not independently signed
  attestations. The bundled constraints pin versions, not wheel hashes.
- Windows installer is designed for PowerShell 7 and CPython 3.11; Python 3.14
  is validated in source CI but is not the default end-user installer runtime.
- AWS GovCloud/China partitions and individual regions are not live validated.
  Azure/GCP SDK modernization and container runtime certification are deferred.

Installation/selection and rollback: docs/releases/TASK14_INSTALL.md
Runtime hotfix history: docs/releases/RC1_RUNTIME_HOTFIX1.md

**Release acceptance criteria:** four offline OS/Python jobs green on the exact
release SHA, Windows PowerShell syntax/selection gate green, installed-wheel
distribution verification green, successful release asset checksum validation.
Production readiness additionally requires the authorized Ridgepay read-only
preflight and a successful real scan with complete evidence.
