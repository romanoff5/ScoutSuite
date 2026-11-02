# M10-O — AWS Systems Manager Patch Manager

Native, read-only AWS service in the standard AWS scan. Collects patch baseline
configurations and registrations, managed-node health, patch state, and missing
patch details. Compares SSM registrations with the regional EC2 inventory.

## Read permissions

- ssm:DescribeInstanceInformation
- ssm:DescribePatchBaselines
- ssm:GetPatchBaseline
- ssm:DescribePatchGroups
- ssm:DescribeInstancePatchStates
- ssm:DescribeInstancePatches
- ssm:ListCommands
- ssm:ListCommandInvocations
- ec2:DescribeInstances

The role can use AWS-managed SecurityAudit plus extra read-only actions where
needed. A denied call produces partial/denied coverage. No mutation, patch
installation or SendCommand is performed.

## Evidence semantics

- Running EC2 without SSM registration is flagged only when both source
  inventories are complete. It may mean missing agent, IAM, networking or
  missing registration; its root cause remains unknown.
- Only PingStatus=Online and a reported Operation=Scan with OperationEndTime
  within seven days are recent *reported* patch-scan evidence. Additionally,
  a matching per-node successful AWS-RunPatchBaseline Run Command invocation
  with an Operation=Scan parameter and a plugin completion timestamp confirms
  the latest successful scan (when command history is accessible). A recent
  Install operation does not prove a recent scan.
- CriticalNonCompliantCount, SecurityNonCompliantCount, MissingCount,
  FailedCount, InstalledPendingRebootCount, InstalledRejectedCount and
  OtherNonCompliantCount are preserved individually.
- KB, CVE, severity and classification are reported for missing/failed patch
  details when AWS supplies them. OS-specific classification is not normalized
  into an invented security finding; AWS aggregate severity counts are kept.
- Collection is bounded, preserves diagnostic details, and marks denied, malformed
  and truncated source results as incomplete. No empty response implies PASS.
- A reported completed Scan operation is not independent proof of successful
  command execution, comprehensive OS update coverage or all patches installed.

## Limitations

Patch Manager evaluates compliance against assigned baselines, which may
exclude available security updates. EC2 comparison does not cover all
managed compute services, accounts or regions. Seven-day freshness is
the assessment policy, not an AWS-defined universal compliance requirement.

## M10-O evidence reconciliation hardening

A previously merged implementation has been hardened in place rather than
introducing a second SSM collector. The report now requires a **fresh agent
ping (within 24 hours)**, recent independently corroborated successful Scan
(within 7 days), zero reported noncompliant counts, resolved baseline details,
complete patch/command enumeration, and current patch state before using
`patch_compliant_evidence=true`. Otherwise the evidence is incomplete/unknown
and must not be presented as a clean machine.

Patch detail enumeration is explicitly bounded to 20 pages and 1,000
non-compliant patch records per node. Truncation records a collection
issue and prevents a clean posture. The five default SSM findings now use
specific registered evidence classifiers; absence of SSM Agent is **not**
inferred from a missing SSM registration. An offline or unresponsive agent,
an unverified scan, and missing/critical patches remain separate cases.
