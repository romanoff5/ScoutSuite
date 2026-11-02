# ScoutSuite fork RC8 — disabled-service evidence that matches real AWS responses

**Version:** `5.14.0+romanoff5.m10rc8`  
**Tag:** `fork-v5.14.0-m10-rc8`  
**Scope:** `romanoff5/ScoutSuite` fork only; no upstream, PyPI, or production-cloud mutation.

## Included changes since RC7

The RC5, PR #25 and PR #26 disabled-service handling did not trigger in the RC7 field run, because the expected AWS responses differ from what AWS returns to an IAM-limited audit role. RC8 aligns each with the observed responses (fix tip `dfdc5ebfc0688a3cdb7f79e004804d1eb001b784`):

- **Security Hub:** `DescribeHub` answers an unsubscribed account with `InvalidAccessException` "Account <id> is not subscribed to AWS Security Hub [CSPM]", not `ResourceNotFoundException`. That exact message is now verified `not_subscribed`, so `securityhub-region-not-subscribed` reports it instead of UNKNOWN. Any other `InvalidAccessException` stays a denial.
- **Macie:** when IAM denies `GetMacieSession`, a classify-only `ListFindings(maxResults=1)` probe accepts only `AccessDeniedException: Macie is not enabled.` as verified `NOT_ENABLED` (`session_status_source: ListFindings`). The probe response is discarded; no finding IDs are kept, logged or reported. Any other outcome stays UNKNOWN. This adds the read-only `macie2:ListFindings` call to the documented Macie API surface.
- **Bedrock:** `ListModelCustomizationJobs` returns `UnknownOperationException` where AWS does not offer model customization (for example `eu-central-1`). That inventory now counts as verified empty (`regional_availability.model_jobs: operation_not_available_in_region`), so the sparse-account deferral of `ListEnforcedGuardrailsConfiguration` applies. The exemption covers only this operation; enforced-guardrail status remains explicitly UNKNOWN/deferred.
- Inspector2 per-instance attribution is intentionally unchanged: when an account's Inspector enrollment is disabled, `inspector2-account-disabled` reports it and per-resource evidence stays UNKNOWN to avoid double counting.
- No rule IDs, report paths or other providers change. JSON/HTML additively expose `session_status_source` (Macie) and `regional_availability` (Bedrock).
- Adds isolated RC8 wheel, runtime constraints and separate venv; `ForkRc7` through `ForkRc1` and `Stable` remain explicit rollback choices. Published RC7 is kept immutable.

## Release and acceptance gates

- All four exact-commit Offline CI jobs: Ubuntu/Windows Python 3.11/3.14; AWS/Azure/GCP synthetic contracts, XSS, SQLite, report and Windows installer/selection tests.
- Independently built wheel/sdist from the final master SHA, installed smoke, distribution-byte verification, SBOM/manifest and verified SHA256SUMS; the release workflow also refuses a SHA without the RC7 and RC8 fix commits. GitHub prerelease not overwritten.
- Client field gate is distinct: new authorized single-account/Region scan. Compared with RC7, where AWS reports these states, `securityhub-region-not-subscribed` and `macie-session-not-enabled` should move from UNKNOWN to flagged, and the Bedrock enforced-guardrail denial and model-customization issue should disappear. No real client AWS scanning is performed by CI or installer.
- Incomplete/denied/unsupported evidence must never become clean PASS. Organization-wide coverage, successful ECR image scans, tested backup RPO, WAF processing, Macie classification and Bedrock account-level controls are unverified.
- CIS AWS Foundations v7.1.0 is a partial candidate mapping, not certification. Azure/GCP SDK modernization remains deferred. No container image is published. Stable .venv-scout untouched.
- SHA256SUMS and manifest are co-hosted integrity metadata, not independent cryptographic signatures.

See [installation and rollback](TASK14_INSTALL.md). No confidential customer reports, AWS account IDs or credentials are included.
