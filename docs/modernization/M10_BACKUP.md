# M10-K — AWS Backup (default AWS scan)

Read-only regional inventory, included in the ordinary AWS scan. No AWS SDK
mutations, recovery-point payloads, secret retrieval, tag masking, or AWS account
authentication during CI. Existing AWS region filtering/skip-services applies.

## API permissions

- `backup:ListBackupVaults`, `backup:DescribeBackupVault`
- `backup:ListBackupPlans`, `backup:GetBackupPlan`

Current scope is vault inventory, lock state, KMS key/type, retention range,
creation/lock dates, recovery-point count, vault type/state/source ARN; plus
plan ID/ARN/version, timestamps, schedules, retention/copy rules, advanced
backup settings and rule-level tags. Original diagnostic identifiers and
configurations are preserved in JSON/SQLite; the offline HTML viewer escapes
untrusted strings. No plan selections, protection status of individual
resources, vault access policies, vault tags, recovery-point contents or
restore-test coverage are assessed by this first vertical slice.

Each paginated list requests 100 objects per page (up to 1000 pages and 100,000
items per region/API). Exhaustion, errors, invalid tokens, malformed pages,
duplicates, identity mismatches and failed detail calls emit explicit
collection issues. Truncated inventories are never asserted clean. A
successful empty inventory is not proof of backup compliance.

## Evidence rule

`backup-vault-lock-disabled` flags only explicit `Locked=false` for
individual vaults. `Locked=true` verifies only this narrow control.
Absent/invalid lock state is unknown. Vault Lock is an optional security
capability depending on retention requirements; this is a review warning, not
a claim of AWS or CIS non-compliance.

## Validation and rollback

Run `tests/test_m10_backup.py` with offline credentials/network isolation,
then the standard Ubuntu/Windows matrix and AWS/Azure/GCP preservation gates.
This task does not inspect any live account. Disable with
`--skip-services backup`. Revert the additive M10-K commit for full rollback;
prior reports require no migration.

## M10-N — AWS Backup depth (2026-11-02)

Default AWS scan additionally calls read-only `ListBackupSelections`,
`GetBackupSelection`, `ListProtectedResources`,
`GetBackupVaultAccessPolicy`, `ListBackupJobs`, `ListRestoreJobs`,
`ListRestoreTestingPlans`, and `ListRestoreTestingSelections`.
Grant corresponding `backup:` permissions to cross-account audit roles as
needed. Bounded pagination and explicit issues cover denied APIs, invalid
pagination, incomplete inventories and identity mismatches. All diagnostic
identifiers, role ARNs, exact selection patterns, vault policies, timestamps
and job/validation messages are retained in JSON/SQLite.

Selection assignment is NOT proof of backup execution. A protected resource
only proves AWS Backup reports a recovery point, regardless of point status.
A completed job with `CreatedBy.BackupPlanId` is stronger but only covers
the recent job history (ListBackupJobs ordinarily returns 30 days). Tag-based
selections cannot be resolved by this inventory alone. Without completed
inventory, explicit ARN absence is unknown. Restore testing jobs are joined
using `CreatedBy.RestoreTestingPlanArn`, with independent `Status` and
`ValidationStatus`; no observed job is not proof of restore failure.
