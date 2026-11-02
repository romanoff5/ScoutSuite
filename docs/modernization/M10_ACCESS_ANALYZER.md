# M10-A — IAM Access Analyzer vertical slice

This is a read-only M10 service included in the ordinary AWS scan by default; it does not constitute full AWS service coverage.

## Scope and risk boundaries

The normal `scout aws` scan includes Access Analyzer. Use
`--skip-services accessanalyzer` to exclude it. Only `accessanalyzer:ListAnalyzers` is used; it does not fetch access findings, raw policy contents or secret values.
ListAnalyzers already returns metadata including tags, creation time and
last-analyzed resource; all available diagnostic fields are now retained.
Selected partition/regions use the existing SDK endpoint metadata and region
opt-in discovery (`ec2:DescribeRegions`). An organization analyzer visible
from another delegated administrator is not implied or inferred.

The collector makes at most 500 calls and accepts at most 50,000 analyzers
per region. Limits are explicit safety budgets (formerly 20/2,000).
Denied, unsupported, malformed, looped-token or truncated
collections record explicit incomplete status rather than presenting an
empty/clean result. The `DISABLED` and `FAILED` statuses are flagged;
`CREATING` is not flagged and is labeled partial.

Normalized path:
`services.accessanalyzer.regions.<region>.analyzers.<scoutid>`.
Additive metadata, a static escaped Handlebars partial, and a service-specific
rule keep JSON/SQLite report compatibility. No CIS certification is claimed.

## Validation and future work

Synthetic tests cover API contract, empty/multipage/denied/malformed/limit
responses, normalization and reporting. Windows and Ubuntu full offline
checks, including Azure/GCP preservation, packaging and XSS must pass
before integration. AWS live-cloud behavior has not been verified.

Future independent M10 slices: Organizations and org logging,
GuardDuty/Security Hub/Inspector, ECR/ECS/EKS, SSM/Backup/WAFv2, and
selected services such as Bedrock. Never advertise unimplemented support.

## RC8: region-level configuration

`accessanalyzer-analyzer-inactive` only evaluates existing analyzers. RC8 records a per-Region analyzer census (`complete` only when `ListAnalyzers` finished on every path and all rows normalised) and adds `accessanalyzer-not-configured` (`accessanalyzer.regions.id`, evidence policy `accessanalyzer-region-configured-v1`). A complete, empty census is flagged; any denial or partial inventory stays UNKNOWN. An organization analyzer owned by another account is not visible to a member account, so the finding text asks the reviewer to verify organization-level coverage before closing it.

## Rollback

Revert this slice's commits. No changes to customer resources or migrations
are performed. Excluding `accessanalyzer` with `--skip-services` restores
pre-slice AWS requests.
