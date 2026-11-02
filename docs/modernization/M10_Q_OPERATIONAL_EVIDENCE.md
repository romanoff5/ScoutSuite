# M10-Q operational evidence: ECR image scans, AWS Backup RPO and WAF requests

These collectors run in the **normal AWS scan** for ECR, Backup and WAFv2. They use **read-only AWS APIs**, not synthetic events, active requests, security findings, data payloads, or S3/ECR image contents. The existing M10-Q report reconciliation remains SDK-free.

## ECR — each image digest
- Enumerate private ECR repositories via the existing collector, then `ecr:DescribeImages` across pages and request `ecr:DescribeImageScanFindings` per digest (`maxResults=1`; vulnerability entries are discarded).
- `verified` requires a complete image census and a completed scan timestamp for every applicable image, plus an API status `COMPLETE` or `ACTIVE` and consistent digest/account/repository identity. `ACTIVE` alone never passes. Archived images are marked not applicable.
- `FAILED`, `UNSUPPORTED_IMAGE`, `LIMIT_EXCEEDED`, etc. are explicit gaps. Denied API access, cyclic pagination, unknown statuses and incomplete timestamps are `unknown`.
- Bound: up to 100 repository image pages of 100 entries per repository; exceeding a bound is **partial**, not a clean scan. SDK throttling can increase execution time.

## AWS Backup — RPO evidence boundary
- For observed protected resources request `backup:ListRecoveryPointsByResource`, including recovery-point ARN, status, creation time and vault. Correlate existing `ListBackupJobs` for failed jobs.
- Set a deliberately **explicit** audit objective before scanning:
  `SCOUTSUITE_BACKUP_RPO_MINUTES=1440` for a 24-hour target, for example. **No default RPO exists**, and a plan cron is not an SLA.
- Calculate observed snapshot age and maximum spacing between available/completed recovery points. `fresh_point_observed` is **not** continuous RPO assurance; `rpo_review_candidate` requires follow-up (especially PITR, where creation timestamp does not represent the most recent recoverable transaction). A `STOPPED` continuous recovery point is an observed service gap, subject to checking whether a newer recovery point supersedes it.
- API responses show point-in-time inventory; job history is limited to 30 days. True historical RPO compliance requires periodic independent evidence from monitoring/event pipelines and recovery verification. `continuous_compliance_verified` remains **false**.
- Limits: up to 10,000 observed protected resources per Region, 100 pages of up to 100 recovery points each. Hitting limits is partial.

## WAFv2 — evidence of request processing
- Request `cloudwatch:GetMetricData` in the AWS/WAFV2 namespace, with WebACL/Rule=ALL/Region dimensions, for a 60-minute window ending 15 minutes before scan (CloudFront metrics in us-east-1, without Region).
- Query AllowedRequests, BlockedRequests, CountedRequests, CaptchaRequests and ChallengeRequests. A nonzero completed series proves that **some** requests were evaluated by this Web ACL during the time window. It does not prove every target's traffic was routed through WAF or that all requests passed the expected rules. Zero/missing telemetry, disabled metrics, incomplete series or denied calls remain `unknown`.
- Do not collect sampled requests (source IP, URI, headers), raw WAF logs or CloudWatch log messages. Dashboard uses escaped Handlebars fields.

## Required additional IAM read permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ecr:DescribeImages", "ecr:DescribeImageScanFindings",
                 "backup:ListRecoveryPointsByResource", "cloudwatch:GetMetricData"],
      "Resource": "*"
    }
  ]
}
```
Tighten resource scope where supported by AWS; CloudWatch GetMetricData generally requires `Resource: "*"`. Existing SecurityAudit permissions may already include some actions, so avoid unnecessary duplication. No write permissions are required.

## Validation
`python -m pytest -q tests/test_m10_q_operational_evidence.py tests/test_m10_cross_service_coverage.py`
Run the guarded Offline CI (Windows and Ubuntu) and review real AWS evidence on an authorized read-only account before interpreting operational coverage as assurance.
