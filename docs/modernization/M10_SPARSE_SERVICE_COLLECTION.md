# M10: bounded discovery-first collection in sparse AWS accounts

This is a general AWS collector improvement, not a Ridgepay-specific suppression
or an account-level security certification. It ships as part of **default AWS**
collection. No account IDs, credentials, private evidence, or resource ARNs
are embedded in source or tests.

## Evidence-driven decision model

| Service | Preconditions observed in region | Restricted API behavior | Accurate interpretation |
| --- | --- | --- | --- |
| SSM Patch Manager | Complete empty managed-node census **and** complete empty patch-group census | Retain all default baseline summaries, defer `GetPatchBaseline` for all baselines | Full baseline-detail review not necessary for an empty managed fleet. **Running EC2 absent from SSM remain findings**, never patched PASS. |
| AWS Backup | Verified complete/empty plan and vault discovery plus complete/empty protected-resource discovery | Defer `ListBackupJobs`, `ListRestoreJobs`, `ListRestoreTestingPlans` and descendant selections | No **current** AWS Backup inventory observed. Job history / independent restore-testing plans **not assessed**, never proven nonexistent. Native RDS PITR and EBS snapshots are separate. |
| S3 Express | Owned directory-bucket inventory complete/empty | Defer `ListAccessPointsForDirectoryBuckets` | **UNKNOWN for cross-account directory access points**. AWS supports access points in this account referring to a directory bucket in another account; no false complete/secure claim. |
| Bedrock | Complete customer resource discovery and invocation-logging configuration, but no customer workloads or enabled logging observed | Defer `ListEnforcedGuardrailsConfiguration` | Account-level enforcement **UNKNOWN**, not absent; on-demand foundation-model inference without registered workloads is possible. |
| Macie | Explicit service-not-enabled response for a region | No jobs/bucket API calls | Verified `NOT_ENABLED`; generic AccessDenied stays UNKNOWN. Implemented separately in PR #25. |

RC8 field correction for Bedrock: in Regions where AWS does not offer model
customization (for example `eu-central-1`), `ListModelCustomizationJobs`
returns `UnknownOperationException`. RC7 treated that as incomplete discovery,
so the deferral above never applied and the denied enforced-guardrail call
still ran. RC8 records `regional_availability.model_jobs:
operation_not_available_in_region` and counts that inventory as verified empty
- only for this operation; `UnknownOperationException` elsewhere and any
denial remain incomplete.

Deferred AWS Backup job history does not hide the M10-Q S3 backup evidence
gap. With a complete, empty plan/vault/protected-resource census no AWS Backup
recovery point can exist for a bucket in that Region, so
`m10q-s3-backup-evidence-gap` still reports it (`not_reported`,
`job_history_status: not_assessed`). Cross-Region recovery points still clear
the gap; partial or denied inventory remains UNKNOWN.

These guards do **not** operate from a bare empty list. They require
collector-specific completeness evidence. The normal deep path continues if a
plan, managed node, configured patch group, customer Bedrock workload, or
directory bucket is found, or discovery fails.

Skipping a dependent API is not a permission grant. The scan report must
distinguish `complete`, `deferred`, `incomplete`, and `not_configured`.
Neither a 0 process exit code nor an empty finding list establishes complete
account/region coverage.

## Live assessment facts that motivated the change

In the authorized regional CLI evidence:

- AWS Backup showed zero current plans, zero vaults and zero protected
  resources in `eu-central-1`; native Aurora cluster PITR exists separately.
- SSM had zero managed nodes while nine running EC2 instances were returned;
  querying 18 unused AWS default baseline details added denial noise.
  Absence from SSM is a real management visibility gap, not evidence that OS
  updates are missing.
- Macie was explicitly disabled in 17 queried regions.
- Owned S3 directory buckets were empty for 16 successful regional queries;
  one region had an endpoint connectivity error and remains UNKNOWN.
- Bedrock had no observed customer guardrails, provisioned throughput or
  recent CloudWatch `Invocations` metrics in the inspected region. This does
  not establish absence of every Bedrock invocation or account guardrail.
- Native Aurora cluster backup retention was observed as one day with a PITR
  window. EBS had one manual snapshot and nine attached volumes. No restore
  test or RPO proof was established by these snapshots.

An unrelated `sts:AssumeRole` explicit SCP deny during local credential
refresh is not a denied AWS service-collection API; it must be tracked as an
authentication/session problem, with separate provenance.

## Validation and regression

Offline synthetic tests verify:
- No redundant patch-baseline lookups on a fully verified empty managed-node
  census, while all running unmanaged EC2 remain flagged.
- Patch-group usage triggers normal baseline detail calls.
- Verified empty AWS Backup current inventory defers restricted APIs but
  preserves explicit historical-evidence uncertainty.
- Partial/positive AWS Backup discovery triggers original deep APIs.
- Empty owned S3 directory buckets do not produce an unverified clean PASS.
- Bedrock enforced-guardrail absence is never silently inferred from no
  customer resource evidence.

The collector does not activate Macie, alter AWS IAM or download any
sensitive classification/object data.
