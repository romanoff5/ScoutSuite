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
