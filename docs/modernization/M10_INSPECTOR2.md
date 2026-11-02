# M10-D — Amazon Inspector v2 own-account scan-state inventory

## Scope

**Opt-in only**: `--services inspector2`. The legacy default scan remains
unchanged. The only new service request is regional
`inspector2:BatchGetAccountStatus`, with `accountIds` explicitly set to the
single currently authenticated STS account ID. Existing region discovery can
call `ec2:DescribeRegions`. No Inspector findings, vulnerabilities, personal
data, org members, repository source or live coverage inventory are fetched.

The API is single-call (no pagination); client construction, SDK retries and
timeouts use the bounded existing AWS facade. The collector rejects unexpected
accounts, malformed shapes, empty responses and `failedAccounts`. Permission
denials and unsupported endpoints are recorded explicitly; absence is never
represented as a verified healthy account.

Each region's `accounts` collection has one normalized current account
with the account state and exactly five *potential* scan-type labels: EC2,
ECR, Lambda, Lambda code and code repositories. Absent optional API scan
types are `null` (unknown), not inactive/disabled. Actual resource-level scan
coverage and applicability are **not verified**.

## Rules

Two scoped rules flag only confirmed `DISABLED`/`SUSPENDED` states:
regional account and individual scan-type statuses. `ENABLED` is secure
**only for the relevant status check**; transitional and absent states remain
unknown/incomplete. A disabled scan type is not automatically a vulnerability
in a workload without that resource type. These rules carry no CIS control
claim and do not score vulnerability coverage or remediation maturity.

## Validation

AWS SDK model and synthetic Stubber tests cover current-account scoping,
denied/partial/malformed responses, account/scan-type status combinations,
normalization, rule evidence, catalog drift, HTML escaping and packaging.
AWS/Azure/GCP preservation and the Windows/Ubuntu offline gates remain
required. No live AWS tenant evidence has been collected.

A future **M10-D2** should add bounded `ListCoverage` with safe summary
aggregation and a distinct incomplete/denied status. It is not part of this
slice and must not be advertised as implemented.

## Rollback

Revert this slice without migrations, or omit `inspector2` from the
explicit `--services` list to avoid the new SDK request.
