# M10-D — Amazon Inspector2 read-only vertical slice

Implementation: `modernization/m10d-inspector2-vertical-slice-20261102`.
This inventory and status check is included in ordinary AWS scans, but is
not a complete Inspector service assessment or a vulnerability scan.
Azure/GCP collectors and existing report IDs remain unchanged.

## API and permission contract

The scanner uses **only** these Inspector2 API actions:

- `inspector2:BatchGetAccountStatus` — current AWS account only, explicit
  12-digit account ID, one call per selected Region.
- `inspector2:ListCoverage` — account-filtered resource/scan status, with at
  most 5 pages of 100 rows (500 per Region).

Existing region discovery may require `ec2:DescribeRegions`. The installed
boto3/botocore model supplies supported endpoints for the selected AWS
partition, and existing explicit Region selection still applies. No account discovery
from an organization, no delegated admin inference, no `ListFindings`, no
vulnerability details, no raw resource metadata, no error messages, no AWS
writes, no enable/disable/scan-trigger actions. Collection runs through the
existing run-scoped executor and throttler.

## Report contract

- `services.inspector2.regions.<region>.accounts.<scoutid>` stores account
  state, Region, and EC2/ECR/Lambda/Lambda-code/code-repository resource states.
- `services.inspector2.regions.<region>.coverage.<scoutid>` stores each
  distinct resource ID + resource type + scan type + account ID combination,
  its ACTIVE/INACTIVE/UNKNOWN scan status and a short reason code.
- `inspector2-account-disabled` flags only confirmed DISABLED/SUSPENDED.
  ENABLING/DISABLING/SUSPENDING/missing is UNKNOWN, never clean.
- `inspector2-coverage-inactive` flags only explicitly INACTIVE scans.
  Missing/unrecognized scan statuses are UNKNOWN. Successful empty coverage
  means zero records, **not** proof that Inspector covers every resource.
- The rules attach versioned, non-certifying evidence summaries using the
  existing M04/M08 evidence classifier contract. Partial, AccessDenied,
  unsupported, bad pagination and result caps are recorded as collection issues.
  The static default ruleset evaluates these definitions when Inspector2 is
  in scope, including in the ordinary AWS scan.

## Validation

Tests use isolated botocore models and Stubber/Mock, checking permitted API
calls, expected filter names, two-page pagination, empty vs AccessDenied,
partial follow-up pages, duplicate/cross-account rows, malformed tokens,
cap/loop protection, stable normalized IDs, classification and report
rendering. CI must pass both Ubuntu Python 3.11 and Windows Python 3.11,
guarded offline tests, packaging, rule catalogs and Azure/GCP preservation.

Live AWS correctness and multi-account delegated-organization behavior have
**not** been verified. This slice makes no CIS compliance or account-wide
security claim. The next Inspector slice can add deeper coverage summaries
and dedicated account/resource-state checks only with new scoped tests.

## Rollback

Revert the M10-D commits and related fixture changes; no migrations or
cloud resource modifications are involved. Exclude `inspector2` from selected
services to restore pre-slice AWS calls.


## Consolidation of independent Inspector2 implementations — 2026-11-02

The earlier branch `modernization/m10d-inspector2-vertical-slice-20261102`
is already merged in `master`, whereas the separate
`modernization/m10d-inspector2-account-state-20261102` introduced
valuable account **scan-type** checks but also repeated account-level
facade/collector/rule definitions. This version retains a **single**
`Inspector2Facade`, a **single** `InspectorAccounts` resource, the
existing `InspectorCoverage` collection, and the two preexisting finding IDs.

The account object now also has `scan_types`, containing normalized
individual states for EC2, ECR, Lambda, Lambda Code and Code Repository.
Each entry has `status` (an AWS state or `UNKNOWN`) and
`inactive`, only true for confirmed DISABLED/SUSPENDED.
The existing `resource_states` mapping is retained, including old
known states; missing optional entries are represented by `null` there.
EC2 and ECR are required by the Inspector2 ResourceState model; their
absence/malformed status records partial collection. Missing optional
resource categories are **unknown**, not considered disabled or healthy.
`failedAccounts` now rejects even an otherwise apparently successful
account record to prevent a false clean result.

The **only new rule** is `inspector2-scan-type-inactive.json`. It checks
`inspector2.regions.id.accounts.id.scan_types.id` using the existing
account state classifier, not a duplicated implementation.
Account and resource-level coverage checks remain
`inspector2-account-disabled.json` and
`inspector2-coverage-inactive.json` with unchanged finding IDs.
Display renders the five states with escaped Handlebars expressions.
No CIS mapping or compliance rating is inferred.

The historical scan-type branch is **not merged wholesale**: its
parallel facade, account resource, default ruleset and historical test
fixtures would conflict with the already merged service and lose
the bounded `ListCoverage` implementation. Instead the additional
behavior is incorporated with tests for SDK stub contract, missing
EC2/ECR, optional UNKNOWN, failedAccounts, preserved data shapes,
independent scan-type finding, existing coverage finding, and XSS-safe
renderer. All five categories are potential scan capabilities rather
than a guarantee of workload applicability. This is enabled by default,
read-only and restricted to the current AWS account.

AWS source contracts:
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_BatchGetAccountStatus.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ResourceState.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListCoverage.html

## M10-E — scalable coverage and delegated-administrator visibility (2026-11-02)

This enhancement retains explicit `inspector2` service selection support,
the three preexisting rule IDs and the same read-only SDK boundaries. It does
not collect Inspector vulnerability findings or retrieve customer payloads.
The changes are additive to versioned JSON/SQLite reports.

### Full Inspector inventory pagination

- `inspector2:ListCoverage` requests 200 results per page, the documented
  AWS maximum, and continues until AWS returns no `nextToken`. The safety
  circuit breaker is now 2,500 pages / **500,000 records per selected
  account and Region**, rather than 5 pages / 500 records. A safety limit,
  bad page, duplicate, unexpected account, denied call or token loop produces
  an explicit **partial** collection, never a verified empty inventory.
- Preserve full `resourceId`, `accountId`, resource/scan types, status
  reason code, last scan timestamp and available provider identifiers/Region.
  Deliberately exclude sensitive raw `resourceMetadata` and vulnerability
  finding bodies; this inventory does not request them separately.
- `inspector2:ListCoverageStatistics` with the same account ID filter and
  `groupBy=SCAN_STATUS_CODE` independently enumerates Inspector's count.
  Per-Region `coverage_summary` records list completion, statistical
  completeness, collected and reported totals, group counts and pagination.
  A mismatch records `CoverageCountMismatch`. Missing statistics, failed
  calls or pagination truncation make the summary partial.
- **Important boundary:** comparison with `ListCoverageStatistics` verifies
  consistency of **Inspector's own resource inventory only**, not coverage
  of every AWS EC2/ECR/Lambda resource. `aws_resource_inventory_compared`
  and `resource_applicability_verified` are explicitly `false`. Further
  independent AWS inventory reconciliation is required before asserting
  estate-wide coverage or compliance.

### Regional delegated administrator and members

- `inspector2:GetDelegatedAdminAccount` first identifies the delegated
  administrator for the selected Region. Only when it matches the current
  authenticated AWS account and has relationship status `ENABLED` do
  additional admin-scoped requests occur.
- `inspector2:ListMembers` uses `onlyAssociated=false` and paginates
  all returned relationships (50/page, safety bound 1,000 pages / 50,000
  members). Member accounts and relationship statuses remain unmasked,
  including disassociated or disabled relationships. Denied, malformed,
  repeated tokens, unexpected IDs or safety limits mark incomplete.
- `inspector2:DescribeOrganizationConfiguration` records EC2/ECR/Lambda/
  Lambda Code/Code Repository auto-enable settings and account-limit state.
  `inspector2:BatchGetAccountStatus` queries listed member accounts in
  chunks of at most 100, recording individual account and scan-type statuses,
  and tracks failures/missing data as unknown rather than PASS.
- `inspector2-member-account-disabled` is a new rule and fires only for
  confirmed DISABLED/SUSPENDED member account statuses. The region's
  `organization` record carries the observed member inventory, member
  scan states, administrator role, and independent completeness flags.
  Member IDs, relationships and diagnostic status codes remain available
  in the report. The new HTML partial uses escaped Handlebars values.
- **Organization boundary:** an Inspector member list is not automatically
  the full AWS Organizations account roster. `organization_roster_verified`
  stays `false`, and organization-region/account membership and eligibility
  must be reconciled with AWS Organizations and current service scopes before
  claiming organization-wide security coverage. A member account receives
  `not_authorized_as_admin`, not a misleading zero-member success.

The same Windows and Ubuntu guarded offline CI, Azure/GCP preservation,
SDK Stubber pagination and negative tests, rule evidence, packaged wheel
and offline/XSS checks are required before merge. No live AWS scan or
credentialed cloud access was performed.

API docs:
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListCoverage.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListCoverageStatistics.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_GetDelegatedAdminAccount.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListMembers.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_BatchGetAccountStatus.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_DescribeOrganizationConfiguration.html


### Optional independent inventory reconciliation

When the user explicitly selects `inspector2` together with other AWS
services in **the same assessment**, M10-E also correlates already collected
resource identifiers without issuing any extra AWS API requests:
- `ec2`: EC2 instance IDs vs Inspector `AWS_EC2_INSTANCE` coverage.
- `ecr`: repository ARNs vs `AWS_ECR_REPOSITORY` coverage.
- `awslambda`: function ARNs vs `AWS_LAMBDA_FUNCTION` coverage.
- `organizations`: active account IDs vs Inspector regional member accounts
  and the delegated administrator ID, but only when both source inventories
  are explicitly complete.

The per-region `resource_reconciliation` section preserves the full
identifiers not seen in Inspector, counts and explicit source scope.
`comparison_verified=false` and `source_inventory_complete=false` remain
until independent enumeration completeness and resource eligibility can
actually be established. Missing coverage **does not** automatically prove a
vulnerability: a resource might not be eligible for that Inspector scan type.
The mismatch is reported as `ResourceInventoryGapUnverified`, not PASS.
The organization report separates `organization_roster_compared`,
`organization_roster_verified` and the full list
`aws_org_accounts_missing_from_inspector_members`; a mismatch records
`OrganizationRosterGap` and never claims organizational completeness.

No code in the cross-service reconciliation requests credentials, AWS
secrets, vulnerability findings or additional cloud API permissions.
