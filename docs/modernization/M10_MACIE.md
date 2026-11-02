# M10-P — Amazon Macie (default AWS scan)

Read-only AWS Macie service posture, jobs and S3 bucket coverage, with no
sensitive information retrieval. The `macie` service is included in default
AWS scans; `--skip-services macie` disables it.

## Regional AWS API surface
- `macie2:GetMacieSession`: verified ENABLED, PAUSED or NOT_ENABLED
  (404 ResourceNotFoundException **or** 403 AccessDeniedException containing
  the explicit service message `Macie is not enabled.`). A generic IAM
  AccessDenied or any other error is UNKNOWN, **not** NOT_ENABLED.
  The service-disabled result has `session_verified: true`, triggers
  `macie-session-not-enabled`, and does not attempt jobs/buckets collection.
  `session_status_source` records which call established the state.
- `macie2:ListFindings` (RC8, classify-only): called with `maxResults=1`
  **only** when IAM denies `GetMacieSession`. Field audit roles were denied
  `GetMacieSession` and `ListClassificationJobs` while `ListFindings` returned
  `AccessDeniedException: Macie is not enabled.`; that exact message yields a
  verified NOT_ENABLED with `session_status_source: ListFindings`. The response
  is discarded: no finding IDs are kept, logged, returned or written to the
  report. A successful call, another denial, throttling or any other error
  leaves the state UNKNOWN with the original `GetMacieSessionDenied` issue.
- `macie2:GetAutomatedDiscoveryConfiguration` and
  `macie2:GetClassificationScope`: automated discovery and bucket exclusions.
- `macie2:ListClassificationJobs` and
  `macie2:DescribeClassificationJob`: job IDs/ARNs, schedules, status, errors,
  last execution, statistics, bucket definitions and dynamic criteria.
- `macie2:DescribeBuckets`: bucket/account/region identity, automated
  monitoring, job coverage, last activity timestamps, classifiable count and
  error codes/messages.

No `GetFindings`, `GetSensitiveDataOccurrences`, `GetResourceProfile`,
S3 `GetObject`, classification-result retrieval, object keys, samples, or
sensitive data are accessed or stored. Full diagnostic identifiers remain
in JSON/SQLite and HTML fields are escaped.

Both list APIs use 100 items/page with 500 pages / 50,000 items safety
limits; broken tokens, invalid records, SDK errors and denied access produce
explicit collection issues. Account/region coverage is incomplete whenever
any required source is denied or incomplete. Macie inventory is *not*
necessarily equivalent to a full independent S3 inventory.

`RECENT_ACTIVITY` means a timestamp within 45 days, **not successful
classification**. `STALE_ACTIVITY` and `NO_RECENT_ACTIVITY_EVIDENCE` are
review flags only; a brand-new bucket or a one-time job is not automatically
a compliance failure. The 45-day threshold is a configurable code constant
(review heuristic), not an AWS requirement. One-time jobs are excluded
from stale recurring-job checks. `jobDetails.isMonitoredByJob` and automatic
discovery monitoring are configuration/coverage signals, not guarantees that
objects were examined or that no sensitive data is present.

Jobs with an explicit `lastRunErrorStatus.code=ERROR`, `CANCELLED`,
`PAUSED` or `USER_PAUSED` status are reported for review. Explicit
`NO_MONITORING_CONFIGURED` bucket state is also a review condition when
both discovery is disabled and job monitoring flags are false.

A separate regional warning identifies an ENABLED Macie session where
both automated discovery is verified DISABLED and the **complete**
classification-job inventory contains zero jobs. Unknown/denied job lists
never trigger this rule.
