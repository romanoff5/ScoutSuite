# ScoutSuite fork RC8 — disabled-service evidence that matches real AWS responses

**Version:** `5.14.0+romanoff5.m10rc8`  
**Tag:** `fork-v5.14.0-m10-rc8`  
**Scope:** `romanoff5/ScoutSuite` fork only; no upstream, PyPI, or production-cloud mutation.

## Included changes since RC7

The RC5, PR #25 and PR #26 disabled-service handling did not trigger in the RC7 field run, because the expected AWS responses differ from what AWS returns to an IAM-limited audit role. RC8 aligns each with the observed responses and fixes how incomplete evidence is drawn in the HTML report (fix tip `8c9f2d0dab2e11c17820c8dd0d6e9bebae37917c`):

- **HTML report status:** a finding with zero flagged items was drawn green ("good") even when its evaluation was incomplete or UNKNOWN. In the RC7 field report 24 findings and the Bedrock, Macie, Organizations and Security Hub service icons looked passed while the JSON said incomplete. RC8 draws them as unknown (grey), shows "Assessment status" and the unknown-evidence count in the finding details, and adds the additive `last_run.summary.<service>.incomplete_rules` counter for the service icon. A pre-existing `TypeError` from the filter click handler on expand buttons is fixed.

- **Security Hub:** `DescribeHub` answers an unsubscribed account with `InvalidAccessException` "Account <id> is not subscribed to AWS Security Hub [CSPM]", not `ResourceNotFoundException`. That exact message is now verified `not_subscribed`, so `securityhub-region-not-subscribed` reports it instead of UNKNOWN. Any other `InvalidAccessException` stays a denial.
- **Macie:** when IAM denies `GetMacieSession`, a classify-only `ListFindings(maxResults=1)` probe accepts only `AccessDeniedException: Macie is not enabled.` as verified `NOT_ENABLED` (`session_status_source: ListFindings`). The probe response is discarded; no finding IDs are kept, logged or reported. Any other outcome stays UNKNOWN. This adds the read-only `macie2:ListFindings` call to the documented Macie API surface.
- **Bedrock:** `ListModelCustomizationJobs` returns `UnknownOperationException` where AWS does not offer model customization (for example `eu-central-1`). That inventory now counts as verified empty (`regional_availability.model_jobs: operation_not_available_in_region`), so the sparse-account deferral of `ListEnforcedGuardrailsConfiguration` applies. The exemption covers only this operation; enforced-guardrail status remains explicitly UNKNOWN/deferred.
- **Report usability:** the HTML report now opens in a dark theme by default with a palette tuned for it (neutral surfaces, readable text, status colours that keep their meaning, muted grey for incomplete/unknown); the viewer can still switch to light and the choice is remembered. Since M09-B the report sanitizer had silently disabled the settings menu (Execution Details, Resources Details, Export Exceptions, Export Summary, About Scout), the dark-theme switch and the S3 ACL grantee toggle; these are restored with allowlisted argument-free actions and delegated handlers instead of inline `on*` attributes.
- Inspector2 per-instance attribution is intentionally unchanged: when an account's Inspector enrollment is disabled, `inspector2-account-disabled` reports it and per-resource evidence stays UNKNOWN to avoid double counting.
- No rule IDs, report paths or rule semantics change; Azure/GCP reports render as before (no assessment status means the previous colours). JSON/HTML additively expose `session_status_source` (Macie), `regional_availability` (Bedrock) and `incomplete_rules` (all providers, 0 without evidence status).
- Adds isolated RC8 wheel, runtime constraints and separate venv; `ForkRc7` through `ForkRc1` and `Stable` remain explicit rollback choices. Published RC7 is kept immutable.

## Release and acceptance gates

- All four exact-commit Offline CI jobs: Ubuntu/Windows Python 3.11/3.14; AWS/Azure/GCP synthetic contracts, XSS, SQLite, report and Windows installer/selection tests.
- Independently built wheel/sdist from the final master SHA, installed smoke, distribution-byte verification, SBOM/manifest and verified SHA256SUMS; the release workflow also refuses a SHA without the RC7 and RC8 fix commits. `tools/verify_report_xss.py` additionally checks that incomplete evidence never renders as "good". GitHub prerelease not overwritten.
- Client field gate is distinct: new authorized single-account/Region scan. Compared with RC7, where AWS reports these states, `securityhub-region-not-subscribed` and `macie-session-not-enabled` should move from UNKNOWN to flagged, and the Bedrock enforced-guardrail denial and model-customization issue should disappear. Rules and services with incomplete evidence must no longer appear green. No real client AWS scanning is performed by CI or installer.
- Incomplete/denied/unsupported evidence must never become clean PASS. Organization-wide coverage, successful ECR image scans, tested backup RPO, WAF processing, Macie classification and Bedrock account-level controls are unverified.
- CIS AWS Foundations v7.1.0 is a partial candidate mapping, not certification. Azure/GCP SDK modernization remains deferred. No container image is published. Stable .venv-scout untouched.
- SHA256SUMS and manifest are co-hosted integrity metadata, not independent cryptographic signatures.

See [installation and rollback](TASK14_INSTALL.md). No confidential customer reports, AWS account IDs or credentials are included.
