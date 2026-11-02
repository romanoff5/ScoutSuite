# M10-Q — consolidated M-10 service verification (2026-11-02)

## Purpose and status

This pass audits the **integrated master** contract, rather than introducing a new
AWS collector. The 15 M-10 services must be included in a normal AWS scan unless
explicitly selected out with `--services` / `--skip-services`. M10-Q and M10-S
are postprocessors; neither is a separately selected AWS service.

The production/default inventory, metadata navigation, rule catalog, offline
reconciliation and supported operational evidence form different layers of
assurance. A rule present in a file is not evidence that it ran on real AWS
resources.

## M-10 integration matrix

| Service | Default collector / independent check | Primary evidence limitation |
| --- | --- | --- |
| Access Analyzer | Analyzer inventory, inactive-analyzer rule | Analyzer coverage and effective access are not automatically proved |
| GuardDuty | Detector inventory / configuration | Presence of a detector does not prove all accounts are monitored |
| Security Hub | Hub and standards configuration | Enabled standards do not prove remediation or member-account coverage |
| Organizations | Accounts, roots, SCP inheritance | SCP policy context is not complete effective IAM authorization |
| Inspector v2 | Account enrollment / ListCoverage, EC2/ECR reconciliation | ACTIVE coverage does not prove a recent successful scan of every resource |
| ECR | Registry/repository settings, per-image scan API | Image digests require complete, authorized, current scan evidence |
| ECS | Cluster / task definition checks | No end-to-end verification of actual runtime isolation |
| EKS | Cluster API exposure / control-plane audit logging | Control-plane log configuration is not evidence of log ingestion |
| WAFv2 | Web ACL associations, target correlation, CloudWatch metrics | Observed requests do not prove that every intended resource/request is protected |
| AWS Backup | Plans, selections, vaults, recovery points, jobs and restore testing | Snapshot age and a completed job do not establish continuous RPO or recovery success |
| IAM Identity Center | Instances, identities, groups, permission sets and assignments | Organization authority and effective permissions may be unavailable |
| AWS Network Firewall | Policies / rule groups / route references / logging | A deployed firewall does not establish transit inspection of traffic |
| Macie | Session, jobs, S3 coverage and execution evidence | An error-free job is not proof all objects were successfully classified |
| Systems Manager | Managed-node patch states / EC2 census reconciliation | Unmanaged/stale/offline nodes never represent verified patch compliance |
| Bedrock | Guardrails, agents, invocation logging and control-plane settings | Presence of guardrails does not verify invocation-time enforcement |

The S3 advanced controls (Access Points, MRAP, Access Grants and S3 Express
directory buckets) are part of the normal S3 collector, not a new service.
M10-S CloudTrail organization-wide account/Region reconciliation runs after
M10-Q; absent organizational privileges or restricted Region scans must remain
partial/unknown.

## Concrete consolidation defect corrected

The `detailed.json` ruleset contained **35 fewer M-10 findings** than
`default.json` (including Security Hub, Inspector, Macie, Network Firewall,
Identity Center, Bedrock and M10-S). A user running the detailed ruleset
therefore silently omitted default-enabled M-10 checks. This change copies
only those 35 default M-10 rules into `detailed.json`, preserving their
enabled flags, levels and arguments. Existing non-M10 rules are untouched.

`tests/test_m10_q_consolidation.py` now verifies:
- All 15 production AWS service registrations (not just a mocked list).
- Catalog inclusion and report navigation for each service.
- M10 rule presence and configuration parity across both rulesets,
  including the six dedicated M10-Q/M10-S rules and their finding files.
- The M10-Q / M10-S preprocessing order and single postprocessing invocation.
- That an EC2 instance without selected Inspector inventory is reported as
  **unknown**, not incorrectly flagged as unscanned.

Run with the full offline test suite, rule-engine catalog checks, HTML/XSS
isolation, Windows/Ubuntu and Python 3.11/3.14. A successful CI result is
**not** evidence that a real AWS tenant's security coverage was verified.

## Remaining verification gates

1. Real read-only AWS account validation, across chosen Regions and
   Organization/delegated-admin scope. Record exact account IDs, resource
   identities and service collection errors for remediation, without
   retrieving customer object contents or image vulnerability finding bodies.
2. Negative tests for throttling, AccessDenied, unsupported Regions, stale
   results, explicit skips, empty inventory and bounded pagination.
3. Per-image ECR scan completion, bounded recovery history versus an explicit
   RPO and WAF action metrics should remain observational, never be converted
   into a blanket continuous/compliant PASS.
4. Optional metadata nodes without dedicated report partials should be
   rendered through the normal report fallback or receive escaped dedicated
   partials before HTML coverage is declared complete.

There are no newly introduced mutating AWS API calls in this consolidation.
