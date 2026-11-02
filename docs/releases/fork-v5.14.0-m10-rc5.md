# ScoutSuite fork RC5 — evidence-integrity corrective candidate (2026-11-02)

**Tag:** `fork-v5.14.0-m10-rc5`  
**Version:** `5.14.0+romanoff5.m10rc5`  
**Repository:** romanoff5/ScoutSuite only (not NCC Group/upstream/PyPI).

## Changes since immutable RC4

- Fix Security Hub's confirmed ResourceNotFound/NOT_SUBSCRIBED path calling
  `record_collection_issue('not_applicable', ...)` even though the collection-issue
  schema accepts only denied/unsupported/failed/partial. Keep negative
  subscription evidence without inventing a collection failure.
- Record unexpected RDS instance, snapshot, subnet, parameter and security-group
  retrieval/enrichment failures as explicit partial issues, instead of silently
  returning empty resources. Publish RDS instance/snapshot caches only after
  enrichment succeeds, so a failed initial attempt cannot poison later VPC reads.
- Preserve UNKNOWN (rather than standalone RDS) for malformed empty/whitespace
  cluster identifiers; avoid a false instance-level deletion-protection finding.
- Reject all non-finite WAF metric values (including positive infinity) to avoid
  treating malformed CloudWatch data as evidence of real WAF traffic.
- Add offline regression tests with active RunContext and retry/unknown cases.
- Bump isolated release wheel, package version, manifest, installer, SHA256 and
  Windows/Ubuntu 3.11/3.14 acceptance gates to RC5; preserve previous candidates
  and Stable for explicit rollback. No schema or finding IDs changed.

## Required validation and known limitations

Publish only from a successful exact-master offline CI SHA (Windows/Ubuntu
Python 3.11/3.14, installed wheel, lint, report/SQLite/XSS, PowerShell launcher)
and independent release-asset verification. CI uses synthetic evidence and no
AWS credentials. No real client AWS scanning is performed by CI or installer.

RC3 customer field evidence remained incomplete (40 collection issues);
RC4's CIS AWS Foundations v7.1.0 crosswalk is candidate-only and cannot
be treated as a compliance score. RC5 does not establish successful scanning
of every ECR image, continuous backup RPO, organization-wide coverage, WAF
request protection effectiveness or Azure/GCP modernization. These require
separately authorized live evidence. No container image is published.
Azure/GCP SDK modernization remains deferred. Stable .venv-scout untouched.

SHA256SUMS and manifest are integrity records, not cryptographic signatures
or third-party supply-chain provenance.

See `docs/releases/TASK14_INSTALL.md` for side-by-side install, authorized
read-only AWS preflight, report completeness checks and rollback (RC4–RC1, Stable).
