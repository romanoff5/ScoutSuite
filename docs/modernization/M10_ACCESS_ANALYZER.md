# M10-A — IAM Access Analyzer vertical slice

This is an **opt-in first slice of M10**, not full AWS service coverage.

## Scope and risk boundaries

Explicit `--services accessanalyzer` is required. Legacy default scans do not
collect this service. Only `accessanalyzer:ListAnalyzers` is used; it does
not fetch policies, access findings, tags or sensitive resource contents.
Selected partition/regions use the existing SDK endpoint metadata and region
opt-in discovery (`ec2:DescribeRegions`). An organization analyzer visible
from another delegated administrator is not implied or inferred.

The collector makes at most 20 calls and accepts at most 2,000 analyzers
per region. Denied, unsupported, malformed, looped-token or truncated
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

## Rollback

Revert this slice's commits. No changes to customer resources or migrations
are performed. Omitting `accessanalyzer` from the service selection restores
pre-slice AWS requests.
