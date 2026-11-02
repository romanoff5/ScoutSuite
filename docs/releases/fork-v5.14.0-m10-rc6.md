# ScoutSuite fork RC6 — RDS-corrected, sparse-collection release candidate

**Version:** `5.14.0+romanoff5.m10rc6`  
**Tag:** `fork-v5.14.0-m10-rc6`  
**Scope:** `romanoff5/ScoutSuite` fork only; no upstream, PyPI, or production-cloud mutation.

## Included changes since RC5

- Includes merged RDS snapshot-cache fix `849a73a096da9da72e95bbf9a8bebaa9c57c51e2`. Published RC5 had exit 200 from missing regional cache; separately built RC5 local hotfix completed with two RDS snapshots and 41 collection issues. RC6 must be independently accepted with a new live scan.
- Incorporates M10 Macie explicit-state handling and conditional discovery-first collection for SSM, AWS Backup, S3 Express and Bedrock in sparse AWS accounts. Deferral is allowed only when prerequisite discovery is complete and empty; missing historical or account-wide evidence remains UNKNOWN.
- Preserves M10 default service collection, prior rule IDs and existing report formats. A reduced API-denial count is not automatically improved security posture or complete AWS coverage.
- Adds isolated RC6 wheel, runtime constraints and separate venv; `ForkRc5` through `ForkRc1` and `Stable` remain explicit rollback choices. Published RC5 is kept immutable despite known RDS failure.

## Release and acceptance gates

- All four exact-commit Offline CI jobs: Ubuntu/Windows Python 3.11/3.14; AWS/Azure/GCP synthetic contracts, XSS, SQLite, report and Windows installer/selection tests.
- Independently built wheel/sdist from the final master SHA, installed smoke, distribution-byte verification, SBOM/manifest and verified SHA256SUMS; GitHub prerelease not overwritten.
- Client field gate is distinct: new authorized single-account/Region scan, RDS snapshot evidence, full inventory status, rule-resource preservation versus RC5 hotfix, consistency audit and investigation of all 41 prior collection issues. No real client AWS scanning is performed by CI or installer.
- Incomplete/denied/unsupported evidence must never become clean PASS. Organization-wide coverage, successful ECR image scans, tested backup RPO, WAF processing, Macie classification and Bedrock account-level controls are unverified.
- CIS AWS Foundations v7.1.0 is a partial candidate mapping, not certification. Azure/GCP SDK modernization remains deferred. No container image is published. Stable .venv-scout untouched.
- SHA256SUMS and manifest are co-hosted integrity metadata, not independent cryptographic signatures.

See [installation and rollback](TASK14_INSTALL.md). No confidential customer reports, AWS account IDs or credentials are included.
