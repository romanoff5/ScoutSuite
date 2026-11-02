# ScoutSuite fork RC7 — S3 backup evidence gap correction

**Version:** `5.14.0+romanoff5.m10rc7`  
**Tag:** `fork-v5.14.0-m10-rc7`  
**Scope:** `romanoff5/ScoutSuite` fork only; no upstream, PyPI, or production-cloud mutation.

## Included changes since RC6

- Fixes an RC6 false negative (commit `409b07570b690cce67612e729718a6178a6d020a`). When a Region's AWS Backup plan, vault and protected-resource census was complete and empty, RC6 deferred job history and the M10-Q S3 correlation turned every bucket in that Region into UNKNOWN, so `m10q-s3-backup-evidence-gap` stopped firing. RC7 reports these buckets as `not_reported` with reason `no_current_backup_inventory_job_history_not_assessed` and an additive `job_history_status` field (`complete`, `not_assessed`, `unknown`).
- The deferred marker is honoured only with a complete, empty protected-resource inventory and `backup_service_activity: no_current_resources_observed`. Partial, denied or contradictory Backup inventory stays UNKNOWN; a recovery point in another Region still clears the gap.
- The Bedrock Region view now shows `enforced_guardrails_evidence_status` next to the enforced-guardrail count, so a deferred or incomplete census is not read as zero enforced guardrails.
- No AWS API call, IAM permission, rule ID, report path or other provider changes. RC6 contents (RDS snapshot-cache fix, M10 sparse collection, Macie explicit-state handling) are otherwise unchanged.
- Adds isolated RC7 wheel, runtime constraints and separate venv; `ForkRc6` through `ForkRc1` and `Stable` remain explicit rollback choices. Published RC6 is kept immutable despite this defect.

## Release and acceptance gates

- All four exact-commit Offline CI jobs: Ubuntu/Windows Python 3.11/3.14; AWS/Azure/GCP synthetic contracts, XSS, SQLite, report and Windows installer/selection tests.
- Independently built wheel/sdist from the final master SHA, installed smoke, distribution-byte verification, SBOM/manifest and verified SHA256SUMS; the release workflow also refuses a SHA that does not contain the RC7 fix commit. GitHub prerelease not overwritten.
- Client field gate is distinct: new authorized single-account/Region scan. Compared with RC6, Regions with no AWS Backup inventory are expected to regain `m10q-s3-backup-evidence-gap` findings for their S3 buckets; any other rule-resource delta must be investigated. No real client AWS scanning is performed by CI or installer.
- Incomplete/denied/unsupported evidence must never become clean PASS. Organization-wide coverage, successful ECR image scans, tested backup RPO, WAF processing, Macie classification and Bedrock account-level controls are unverified.
- CIS AWS Foundations v7.1.0 is a partial candidate mapping, not certification. Azure/GCP SDK modernization remains deferred. No container image is published. Stable .venv-scout untouched.
- SHA256SUMS and manifest are co-hosted integrity metadata, not independent cryptographic signatures.

See [installation and rollback](TASK14_INSTALL.md). No confidential customer reports, AWS account IDs or credentials are included.
