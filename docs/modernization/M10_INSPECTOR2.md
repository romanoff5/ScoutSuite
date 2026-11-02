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
