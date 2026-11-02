# M10-B — GuardDuty detector inventory (opt-in)

A second standalone read-only AWS vertical slice. Explicit
`--services guardduty` is required; the previous default scan remains unchanged.

## API/permission contract

Regional APIs: `guardduty:ListDetectors` and
`guardduty:GetDetector` only. Existing region discovery may call
`ec2:DescribeRegions`. No writes, no GetFindings, no member account
enumeration, no sensitive payloads.

Bounded to 1000 listing pages and 50,000 detector IDs per region
(former arbitrary caps of 5 pages/100 detectors). All API
requests use per-run throttling/executor limits. Denied/unsupported API
errors, duplicate IDs, bad tokens, malformed pages, limits, and partial
detail retrieval mark the collection explicitly incomplete.
A failed/denied listing is never interpreted as a verified detector absence.
An empty successfully enumerated account/region has no detector objects,
but this slice does not yet create an absence-of-detector finding.

## Findings and report

`guardduty.regions.<region>.detectors.<stable-id>` includes
`detector_id`, `status`, `disabled`,
`finding_publishing_frequency`, `region`, creation/update dates,
service-role ARN, enabled protection features with nested configurations,
data-source status, and tags. These details allow configuration remediation;
actual GuardDuty findings and credential values are not retrieved.
The `guardduty-detector-disabled` rule flags only confirmed DISABLED,
with UNKNOWN evidence for malformed or missing status. Does not claim
organization-wide coverage or validate enablement of each GuardDuty
protection feature. No CIS control verification is asserted.

HTML partial and offline fixtures cover API paging, failures, normalized
data, rule evaluation, renderer and installed wheel/sdist. Azure/GCP
preservation remains a blocking CI gate.

## Rollback

Revert the M10-B commits. No migrations and no AWS changes.
Do not select `guardduty` to avoid all new API calls.
