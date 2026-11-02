# M10-C: AWS Organizations global read-only vertical slice

Status: integrated M10-C slice; **M10 overall remains incomplete**.

## AWS API and permissions

The collector participates in the default AWS scan. Use
`--skip-services organizations` to exclude it. It uses only:

- `organizations:DescribeOrganization` (any account in an organization)
- `organizations:ListRoots` (management account or delegated administrator)
- `organizations:ListAccounts` (management account or delegated administrator)

AWS Organizations is a **global** service; request it once per assessment,
not once per selected region. Partition endpoints are `us-east-1` for
`aws`, `us-gov-west-1` for `aws-us-gov`, and `cn-northwest-1`
for `aws-cn`. Unknown partitions are unsupported (never silently
routed to a commercial endpoint). These choices follow the AWS Organizations
endpoint directory: https://docs.aws.amazon.com/organizations/latest/userguide/region-support.html .

No `DescribePolicy`, effective policy evaluation, SCP documents, OU tree,
assume-role traversal, member enumeration, tagging or AWS writes.

## Data and status contract

Report schema:

- `services.organizations.organizations.<organization-id>`: feature_set,
  organization ARN, management account ID, ARN, e-mail and a deprecated policy-type diagnostic
- `services.organizations.roots.<root-id>`: name, ARN, SCP status,
  nullable enabled state, full available root policy types and states
- `services.organizations.accounts.<account-id>`: name, ARN, **e-mail**,
  **State** (authoritative), optional deprecated legacy status,
  joined_method, joined_timestamp and organization OU paths. Contact e-mail
  and paths are essential for identifying the affected account and owner.
- `services.organizations.collection`: per-API complete, partial,
  denied, unsupported, failed or not_collected indicators.

A member account may read `DescribeOrganization` but be denied
`ListRoots` and `ListAccounts`. In that case the organization summary
is retained and both inventories are explicitly marked incomplete.
`AWSOrganizationsNotInUseException` is treated as unsupported/not-member,
**not** as a proof that the organization is compliant.

`ListAccounts` follows `NextToken` even after an empty page.
MaxResults=20 per call; maximum 5000 pages/100000 accounts; roots
maximum 500 pages/10000 roots. These are safety budgets above the former
arbitrary caps, not routine report truncation. A token cycle, duplicate/invalid id, malformed page, failure,
or bound triggers incomplete status; no unbounded fan-out. No global
business-as-usual success is claimed on truncated results.

## Rules (warning, not certification)

- `organizations-features-not-enabled`: `FeatureSet=CONSOLIDATED_BILLING`
  is confirmed insecure for organization-level policy governance, `ALL`
  secure, unknown remains incomplete.
- `organizations-root-scp-not-enabled`: verified ALL-feature root with
  absent SCP policy type or confirmed DISABLED type is flagged. Confirmed
  ENABLED is secure. Missing/malformed PolicyTypes or transitional status is
  unknown; consolidated-billing-only roots are not applicable to this
  *separate* root rule.

These are **configuration signals**, not effective policy analysis. They do
not establish whether attached SCPs enforce good restrictions, whether RCPs
exist, or whether each member account is governed. AWS account state
`State` supersedes deprecated `Status` (retired September 2026):
https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html .

## Acceptance and rollback

Synthetic Botocore Stubber tests must exercise each endpoint, pagination
including an empty page with token, authorization, member-account behavior,
partial result preservation, sovereign endpoint selection, bounds,
normalization with actionable account/contact evidence, rules and escaped report modal. Windows/Ubuntu
guarded offline tests, AWS/Azure/GCP preservation, wheel/sdist, XSS and
installed-package verification must all pass before a non-forced merge.

No live AWS call or customer identity used during implementation. Rollback
by reverting the slice commits. Existing JSON/SQLite report schema remains
backward-compatible; no migrations and no AWS writes.
