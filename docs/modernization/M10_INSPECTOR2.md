# M10-D — Amazon Inspector2 read-only vertical slice

Implementation: `modernization/m10d-inspector2-vertical-slice-20261102`.
This is an **opt-in** inventory and status check, not a full Inspector service
assessment and not a vulnerability scan. `--services inspector2` is required.
Existing default services, Azure and GCP collectors, and old report IDs are
unchanged.

## API and permission contract

The scanner uses **only** these Inspector2 API actions:

- `inspector2:BatchGetAccountStatus` — current AWS account only, explicit
  12-digit account ID, one call per selected Region.
- `inspector2:ListCoverage` — account-filtered resource/scan status, with at
  most 5 pages of 100 rows (500 per Region).

Existing region discovery may require `ec2:DescribeRegions`. The installed
boto3/botocore model supplies supported endpoints for the selected AWS
partition, and existing Region opt-in handling applies. No account discovery
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
  The static default ruleset adds these definitions but never executes them
  unless `inspector2` was explicitly selected.

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
cloud resource modifications are involved. Omit `inspector2` from selected
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
than a guarantee of workload applicability. This remains opt-in,
read-only and restricted to the current AWS account.

AWS source contracts:
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_BatchGetAccountStatus.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ResourceState.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListCoverage.html
