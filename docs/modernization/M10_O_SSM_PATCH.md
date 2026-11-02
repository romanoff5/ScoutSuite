# M10-O — AWS Systems Manager patch posture

Standard, read-only AWS service name: `ssm` (enabled in ordinary `scout aws`).
Use `--services ssm` to target only SSM or `--skip-services ssm`
to exclude. The optional legacy/proprietary SSM module is not used as the
default collection/report implementation. AWS CLI/cross-account SecurityAudit
may need **additional read-only SSM/EC2 permissions**.

## API inventory

- SSM `DescribePatchBaselines` + `GetPatchBaseline`: baseline identity,
  OS, rules, approved/rejected patch IDs, compliance level, source, dates.
- SSM `DescribePatchGroups`: patch groups to associated baseline identities.
- SSM `DescribeInstanceInformation`: all visible managed nodes including
  hybrid `mi-*`, SSM registration and agent status/version/last ping.
- SSM `DescribeInstancePatchStates`: most recent patch operation, snapshot,
  baseline, critical/security/other/missing/failed/pending reboot counts.
- SSM `DescribeInstancePatches` with non-compliant state filters:
  per-patch KB ID/title/classification/severity/status. Bounded to
  1,000 patch detail records per node; truncation records a collection issue.
- SSM `ListCommandInvocations` + `ListCommands`: independently verify a
  **successful per-node** AWS-RunPatchBaseline invocation whose operation
  parameter is exactly `Scan`. An Install, command created without success,
  or patch-state `OperationEndTime` alone does not verify a scan.
- EC2 `DescribeInstances`: independent, paginated region-wide EC2 inventory
  to determine which **running** instances are observed in SSM. Stopped
  instances are not classified as missing agents.

## Interpretation and evidence

`patch_health=observed_current` requires an online/recent agent ping
(24h), a patch snapshot not older than **7 days**, independent successful
scan evidence within 7 days, all relevant numeric patch counts zero, complete
patch state/details/scan-lookup enumeration, and a resolvable patch baseline.
It means *observed current against the configured baseline*, NOT proof that
every vendor CVE is patched. Approval rules may exclude available updates.

`last_successful_scan_at` uses the latest successful plugin completion time
where available. If the plugin completion time is not returned by AWS, it
uses the matching invocation *request* time as a lower-fidelity estimate, with
`scan_timestamp_source=successful_invocation_request`. When invocation
and command parameter correlation is unavailable, the field is null and
`scan_evidence=unverified`. Do not present `latest_patch_operation_ended_at`
as an independently confirmed successful scan.

A running EC2 instance missing from a **fully enumerated** SSM node roster
has `ssm_coverage_status=unmanaged_unverified_agent`. That is a
registration/coverage finding, NOT proof that SSM Agent is absent. Check
the instance profile, AWS Systems Manager endpoints, network, DNS, agent
service and registration. If SSM listing was denied or truncated, the status
is `unknown` instead, never PASS/healthy.

Agent `ConnectionLost` is distinguishable from a missing registration.
Unknown agent ping time, missing patch state, stale scan, incomplete API
pagination or denied permissions are not reclassified as up-to-date systems.
Security and critical non-compliant patch counts may refer to overlapping
patches, so their totals must **not** be added together.

## Collection guardrails and limits

Read-only, bounded AWS calls; full pagination up to 2,000 pages /
100,000 items per top-level collection; up to 20 pages / 1,000
non-compliant patches and 3 pages / 150 recent command invocations per node.
Per-node work bounded to eight simultaneous jobs and regions to three.
Any API failures, malformed records, repeated pagination tokens or limits
must report `partial`; successfully retrieved evidence remains in report.
No file contents, patch binaries, SSM Parameter Store values, command output,
login secrets or credential material are collected.

## Required read actions

`ssm:DescribePatchBaselines`, `ssm:GetPatchBaseline`,
`ssm:DescribePatchGroups`, `ssm:DescribeInstanceInformation`,
`ssm:DescribeInstancePatchStates`, `ssm:DescribeInstancePatches`,
`ssm:ListCommandInvocations`, `ssm:ListCommands`,
`ec2:DescribeInstances`.

## Tests, findings and rollback

Tests: `tests/test_m10_ssm_patch.py` (strict botocore Stubber,
real SDK response models, pagination, stale snapshots/scan proof,
`AccessDenied`, non-managed running EC2 and offline HTML escaping),
default AWS service/fixture catalog regression, full guarded CI
Windows + Ubuntu.

Default findings: observed critical and security patch counts, stale or
unverified scan, reported agent disconnection and running EC2 not managed
through SSM. Incomplete evidence stays unknown. Roll back by reverting
M10-O changes, or skip SSM through `--skip-services ssm`.
