# M06 — AWS collection correctness (2026-11-01)

Base: `6799c9a3` (validated M05 master). No Azure/GCP SDK, collectors,
rules or severities changed. Each correction has separate offline tests.

## M06-A RDS

Cross-account **class-scoped** resource caches and asyncio locks
(`instances`, `snapshots`, `subnet groups`) are now owned by the
individual RDS facade. This prevents scanning account B from reusing account
A's inventory for the same region. Existing `EC2-Classic` sentinel and
normalized ID format are preserved. Missing Aurora `MultiAZ` does not
erase the instance's prior value. An unused STS lookup before every RDS
tag request has been removed.

## M06-B AWS Config

Paged `ListConfigurationRecorders` now discovers customer and
service-linked recorder summaries. Each is described by ARN and its
status requested by ARN. Missing status is **unknown** (`enabled=None`),
not disabled. The existing resource name/ID and fields are preserved;
additive fields include recorder ARN, recording mode/scope/strategy,
service principal, and status completeness. If `ListConfigurationRecorders`
is denied, an older customer-recorder fallback remains available but the
assessment records partial/incomplete coverage.

**IAM delta:** add `config:ListConfigurationRecorders` to read-only
assessment roles. Existing `config:DescribeConfigurationRecorders`
and `config:DescribeConfigurationRecorderStatus` are still needed.
https://docs.aws.amazon.com/config/latest/APIReference/API_ListConfigurationRecorders.html

## M06-C KMS

Customer symmetric encryption keys with `AWS_KMS` material support
automatic rotation; asymmetric/HMAC/imported/external keys do not.
Ineligible keys now have `rotation_enabled=None` and
`rotation_status=not_supported`, rather than being incorrectly marked
True. Customer-managed eligible keys retain the actual API rotation status,
plus `RotationPeriodInDays` and `NextRotationDate` when returned.
Only supported AWS-managed symmetric keys receive
`rotation_enabled=True`. Missing or inaccessible rotation data remains
unknown. Existing ID/name/ARN and aliases remain unchanged.

**IAM:** `kms:GetKeyRotationStatus` unchanged. SDK model validation and
synthetic key-state tests included.
https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html

## M06-D S3 ownership/public access

Adds read-only `GetBucketOwnershipControls` and
`GetBucketPolicyStatus` queries to the existing bucket collector.
The new fields `object_ownership` and `policy_is_public`
are additive. Both bucket- and account-level public-access-block queries
now distinguish a confirmed `NoSuchPublicAccessBlockConfiguration`
from AccessDenied/other errors. Unknown state is represented by None
and a `collection_status` issue, never by fabricated all-false settings.
Account S3 Control probe uses a region in the AWS commercial, GovCloud,
or China partition as appropriate.

**IAM delta:** `s3:GetBucketOwnershipControls` and
`s3:GetBucketPolicyStatus`. Existing
`s3:GetBucketPublicAccessBlock` and
`s3:GetAccountPublicAccessBlock` remain needed.
No write calls; directory buckets remain excluded from this collector.

## M06-E Regions/partitions

SDK metadata lookup uses the correct partition bootstrap region:
commercial us-east-1, GovCloud us-gov-west-1, China cn-north-1.
The EC2 DescribeRegions opt-in probe uses the same partition.
If `ec2:DescribeRegions` is denied, candidate regions are retained
with explicit `RegionOptInUnverified` rather than marking all omitted
or falsely verified. Removed a hard-coded stale EKS commercial region
list fallback. This does not provide exhaustive disabled-account
proof and cannot substitute for live region access validation.

**IAM:** `ec2:DescribeRegions` required for authoritative opt-in status;
otherwise incomplete status is recorded.

## Acceptance and limitations

Offline Windows/Ubuntu Python 3.11 CI must pass before merge.
There is **no** live AWS credential/API test. Legacy public report
structures have additive fields but no intentional finding-ID/severity
change. Not covered: all direct AWS calls, historical Classic endpoint
availability, extended RDS/Aurora snapshot consistency, all
KMS key-store variants, opt-in region provenance in HTML, full AWS
API-permission census and post-M05/06 Python 3.14. Those require separate
validated follow-up and are not silently claimed complete.
