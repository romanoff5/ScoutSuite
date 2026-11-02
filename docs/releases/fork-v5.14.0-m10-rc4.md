# ScoutSuite fork RC4 — CIS AWS Foundations v7.1.0 and RC3 field-evidence review

Fork: romanoff5/ScoutSuite
Tag: fork-v5.14.0-m10-rc4
Version: 5.14.0+romanoff5.m10rc4

## Scope and evidence provenance

RC4 is based on the independently verified RC3 real-cloud report and the
maintainer-provided CIS AWS Foundations Benchmark v7.1.0 (2026-10-02).
The supplied client ZIP passed its 117-file SHA256 manifest verification:
RC3 produced 121 flagged rule/resource pairs (one more than RC1),
zero evidence/flag count discrepancies, 40 unchanged collection issues and
80 incomplete rule assessments. ECR BASIC was independently verified with
zero repositories; this is a configuration observation, not evidence of
missed image vulnerability scans. The source archive, private account ID,
AWS resource identifiers, ARNs, CLI credentials and raw AWS API responses
are **not** included in the git repository or this wheel.

## Changes since immutable RC3

- Full machine-readable, noncertifying implementation inventory for the
  **94** recommendation IDs of CIS AWS Foundations v7.1.0, with **33**
  opt-in candidate rule associations covering **30** unique IDs.
  The remaining recommendations retain partial, manual or unimplemented
  statuses; no computed CIS compliance percentage or certification claim.
- Five new normal (default and detailed) AWS findings:
  * S3 effective account/bucket Block Public Access configuration (3.1.4).
  * RDS standalone instance deletion protection (3.2.5).
  * RDS Aurora/Multi-AZ **cluster-level** deletion protection (3.2.5).
  * EFS encryption at rest (3.3.1).
  * Security Hub regional subscription (5.16).
- The RDS standalone rule explicitly excludes cluster member instances.
  The new bounded read-only regional DescribeDBClusters inventory evaluates
  each cluster once, including Aurora and Multi-AZ DB clusters. A denial,
  missing field or malformed response remains UNKNOWN/partial, not PASS.
  The field review caught a real false-positive risk: Aurora members'
  instance-level DeletionProtection must not be used to judge database
  cluster data protection.
- The opt-in CIS profile uses a 45-day unused-IAM-credentials threshold,
  without changing ordinary-scan IAM defaults.
- Preserves already-correct RC3 ECR BASIC finding contract, existing rule IDs,
  report schema, offline HTML/SQLite protections, Python 3.11/3.14 runtime
  contracts, pinned dependency closure, and legacy CIS 1.2.0 ruleset.
- RC4 installs side-by-side in `.venv-scout-fork-rc4`.
  Explicit rollback modes preserve RC3 (`ForkRc3`), RC2
  (`ForkRc2`), RC1/hotfix (`ForkRc1`) and Stable.

## Scope limitations

- The release does **not** show organization-wide CIS compliance.
  Read-only AWS API denials in Organizations, Security Hub, Identity
  Center, Macie, Backup, SSM, Bedrock, Inspector and advanced S3 remain
  incomplete until independent evidence/permissions are available.
- ECR Basic vs Enhanced is not proof of missed image scans; repository
  inventory and scanning success must be independently verified.
- RDS and EFS empty inventory can mean no in-scope resources only when
  collection is complete. Service-wide data, cluster protection, backup
  restore testing and IAM privileges are distinct assessments.
- S3 effective BPA flags are a preventative configuration check, not proof
  that access points, object ACLs and every policy layer are safe.
- Security Hub AccessDenied and InvalidAccessException are not treated as
  explicit `ResourceNotFoundException` / not-subscribed states.
- No real client AWS scanning is performed by CI or installer.
  No container image is published.
  Azure/GCP SDK modernization remains deferred.
  Stable .venv-scout untouched.
- Release checksums verify asset integrity but are not cryptographic
  signatures or independent supply-chain provenance.

## Gates

Build only from validated fork master; four Windows/Ubuntu Python 3.11/3.14
offline jobs must succeed including synthetic rule-engine tests and actual
Windows wheel installation. Separate release CI validates wheel and sdist,
installed distribution, manifest/SBOM, runtime pins and SHA256SUMS, with
prerelease tag matching the merged master SHA.

See `docs/modernization/CIS_FOUNDATIONS_V7_1_RC4_GAP_REVIEW.md` and
`docs/releases/TASK14_INSTALL.md` for crosswalk, installation,
verification and rollback.
