# M10-Q — Cross-service AWS coverage reconciliation

M10-Q is a **report-postprocessing-only** step inside the ordinary AWS
scan. It is not a separate SDK service, and it never makes new AWS API
calls, changes customer AWS resources or consumes object/image content.

During AWS `preprocessing()` after selected collectors complete,
`reconcile_m10q_coverage(services, service_list, account_id)` annotates
the original resources and adds a compact `m10q_reconciliation` summary.
It is safe under `--local`, `--services` and `--skip-services`.

## Sources, evidence and limitations

| Existing resource | Independent source | Observable cross-service conclusion |
| --- | --- | --- |
| EC2 instance | Inspector2 ListCoverage, reconciled by region, account ID and instance ID | `active_observed`, `inactive_reported`, `mixed_reported`, `not_reported`, `unknown` or `not_applicable` |
| ECR repository | Inspector2 ListCoverage + ECR registry scan type and repository rules / basic scanOnPush | Inspector enrollment status and candidate configuration gaps. **Individual image scan completion is not proved** without image-level scanning results. |
| S3 bucket | AWS Backup ListProtectedResources and completed backup jobs for the bucket region | `recovery_and_job_observed`, `partial_evidence`, `not_reported` or `unknown`. A completed job/recovery point does not verify an ongoing schedule, backup age, recovery quality, or alternate backup tools. |
| WAFv2 Web ACL | WAF associations, plus independently enumerated ALBs/CloudFront distributions when selected | WAF association, independent target existence, or no association in the supported inspected scope. A configured association does **not** verify routed traffic. API Gateway is not independently inventoried by this stage. |

S3 bucket ARNs are normalized to `arn:{partition}:s3:::{bucket_name}`
for joining with AWS Backup. The existing `bucket.arn` field is left
untouched for backward compatibility.

**Never claim absence from a partial inventory.** In particular:
- Inspector coverage must have a complete account/region summary before
  lack of an instance or repository becomes a `not_reported` observation.
- ECR scan-on-push/enhanced filter configuration and Inspector ACTIVE are
  configuration/coverage evidence, *not* a per-image security result.
- S3 backup must have both complete protected-resources and backup-job
  sources in the bucket's region before absence becomes an evidence gap.
  A bucket in an uncollected region remains `unknown`. Cross-region copies
  and third-party backups may not appear in that region's collection.
- WAFv2 no-association candidates are already covered by
  `wafv2-web-acl-unassociated.json`; **do not emit a duplicate M10-Q
  finding**. Cross-service target correlation enriches that Web ACL's
  original report.
- No inference is made about scan eligibility, tenant/org-wide coverage,
  current patch vulnerabilities, retention SLA, effective traffic
  protection or other compliance. Evidence-classifier results always
  carry `compliance_verified=false`.

## Default rules

1. `m10q-ec2-not-reported-by-inspector2.json` — instance ID absent from a
   complete same-account Inspector2 coverage listing.
2. `m10q-ecr-image-scanning-gap.json` — candidate scan enrollment gap
   (absent/inactive Inspector enrollment combined with ECR scanning config
   not enabling that repository).
3. `m10q-s3-backup-evidence-gap.json` — no corroborated AWS Backup
   resource and completed job, or only partial evidence, on a complete
   region collection.

Previously integrated `wafv2-web-acl-unassociated.json` remains the
single default WAF unused-ACL finding.

## Validation and operational constraints

Regression test: `tests/test_m10_cross_service_coverage.py`. Covers
complete/partial enumeration, cross-account false matches, S3 ARN
normalization, BASIC/ENHANCED ECR config, no-image-success claims,
backup completed-job correlation, Web ACL independent ALB presence,
no-network/single-source scans and offline HTML report evidence.

All four resource reports use Handlebars escaped values. Normal
Windows/Ubuntu CI must pass before merge. The implementation is
deliberately additive; removal can be accomplished by reverting M10-Q
or excluding the upstream collector from a focused scan.


## M10-Q v2 deep revalidation — 2026-11-02

The original M10-Q checks were rerun against the new S3 advanced collector
(including Access Points, directory Access Points, S3 Express directory
buckets, Multi-Region Access Points and Access Grants).

The second pass adds the following **non-mutating** correlations:

- **S3 inventory integrity:** `ListBuckets` now reports explicit
  `bucket_inventory_status` so an API denial or incomplete pagination
  cannot be mistaken for an empty bucket list.
- **Standard Access Points:** match their target bucket by exact S3 name and
  owner, preserving `BucketAccountId`. A reference is marked missing only
  when both account ownership is confirmed and bucket enumeration succeeded.
  Cross-account and unavailable owner metadata remain unknown.
- **S3 Express directory buckets and Access Points:** use a separate
  per-Region directory bucket inventory. Do **not** confuse them with classic
  S3 buckets or declare that AWS Backup supports them. Backup support and
  recovery remain `not_evaluated`.
- **Multi-Region Access Points:** correlate the regional backing-bucket list
  to discovered classic buckets and retain the entire target list. Missing
  targets remain unknown without an owner/scope verification.
- **Access Grants:** join grants to their locations by exact
  `AccessGrantsLocationId`, derive only unambiguous `s3://bucket/prefix`
  references, and avoid linking contradictory grant/location scopes. IAM
  grant permissions and identities stay intact; no credentials are accessed.
- **S3 ↔ Backup:** join bucket to explicit plan selections and distinguish
  tag/conditional selectors; preserve restore-testing job evidence without
  claiming restore validation. Also search successfully enumerated other
  AWS Backup Regions for recovery points and avoid a local no-backup finding
  when a copy is visible elsewhere. A plan assignment is not a backup.
- **EC2 ↔ Inspector:** stopped instances not in Inspector coverage are now
  `unknown` rather than an automatic gap; an explicitly disabled own-account
  Inspector enrollment cannot yield a confident good/negative scan outcome.
- **ECR:** retain registry/repository configuration separately from per-image
  scan execution. Without image-level scan results, effective image scan
  freshness is always `unknown`, even with Inspector ACTIVE.
- **WAF:** ALB/CloudFront target *existence* is not independent proof that
  WAF is attached or that real requests traverse the ACL. Original
  `wafv2-web-acl-unassociated.json` is retained without duplicate rules.

Two new **default warning** findings report references to nonexistent
same-account S3 bucket targets only when bucket census is explicitly
complete (standard and directory Access Points separately). Absent,
denied, malformed or cross-account inventories never generate a claimed
target-not-found finding.

The original M10-Q rules remain active. Versioned `summary.version=2`
and `summary.deep` expose per-pair reconciliation status without performing
additional AWS calls.

The S3 advanced API pager now bounds pages (1000) and items (100000), and
preserves partial records with an explicit collection issue on invalid
records, item cap or page cap instead of looping indefinitely.

**Testing:** `tests/test_m10_cross_service_coverage.py` and
`tests/test_m10_q_deep_coverage.py` plus existing AWS/S3 advanced and
full offline preservation suite. No live AWS credentials or object data used.
