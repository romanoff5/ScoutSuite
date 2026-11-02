## Post-RC6 review: S3 backup evidence gap with deferred AWS Backup history (2026-11-02)

- Review of the last three days of `master` found one changed-feature false
  negative from PR #26 (M10 sparse collection). In a Region whose AWS Backup
  plan, vault and protected-resource census is complete and empty, job history
  is deferred (`deferred_no_current_backup_inventory`), but the M10-Q S3
  correlation still required `backup_jobs == 'complete'`. Every S3 bucket in
  that Region therefore moved from `not_reported` (rule
  `m10q-s3-backup-evidence-gap` flagged) to `unknown` (not flagged) - exactly
  the motivating field case with zero plans, vaults and protected resources.
- Fix: the correlation accepts the deferred marker only together with a
  complete, empty protected-resource inventory and
  `backup_service_activity == 'no_current_resources_observed'`; it reports
  `not_reported` with reason
  `no_current_backup_inventory_job_history_not_assessed`. An additive
  `job_history_status` field (`complete`, `not_assessed`, `unknown`) records
  whether job history was actually enumerated. Partial/denied history,
  contradictory inventory and a missing activity marker stay UNKNOWN;
  cross-Region recovery points still clear the gap. No AWS API calls,
  permissions, rule IDs or other providers change. Rollback: revert the fix
  commit. The Bedrock region partial now also displays
  `enforced_guardrails_evidence_status` beside the enforced-guardrail count.
- Published RC6 is immutable and still contains this defect. Its field
  acceptance comparison against the RC5 hotfix will show these S3 findings
  missing in Regions without AWS Backup; that delta is this defect, not
  improved posture. A later release needs fresh packaging and acceptance.
- Reviewed without change: PR #26 SSM, S3 Express and Bedrock deferrals keep
  coverage `incomplete`/UNKNOWN rather than PASS; RC5 Security Hub, RDS cache,
  WAF metric and Macie disabled-state corrections.
- Local guarded suite (reused M02-B test environment with exact AWS pins but
  older Azure/GCP SDKs): 707 passed before the change; the 4 failures are
  environmental (three M11 Azure/GCP SDK contract tests and one Windows
  `WinError 1314` symlink-privilege test), matching the RC5 note.

## RC6 release preparation (2026-11-02)

- RC6 derives from master `0955f56e65665c6eb54f14f37267a4b1eb3466ae`; RDS cache hotfix and conditional M10 collection are already merged. No customer evidence or credentials are included.
- The new version installs in `.venv-scout-fork-rc6`; RC5 through RC1 and Stable remain selectable without overwriting previous environments.
- Release gates: offline CI across Python 3.11/3.14 on Windows/Ubuntu; installed distribution, PowerShell integrity and report tests; immutable exact-master release and SHA256SUMS. Fresh authorized field acceptance is separate.
- RC5 published wheel failed with code 200 due to RDS snapshot cache. Local hotfix completed with two snapshots and 41 collection issues. RC6 must be scanned anew to verify collection/error and finding deltas; unknown evidence never becomes PASS merely because an API is conditionally deferred.

## RC5 corrective release — 2026-11-02

- Security Hub `DescribeHub ResourceNotFoundException` is confirmed negative subscription evidence, not an invalid `not_applicable` collection issue; regression runs under an active `RunContext`.
- RDS unexpected inventory errors now register partial collection issues. Instance and snapshot cache entries are published only after enrichment succeeds, preventing a failed first attempt from poisoning subsequent VPC queries. Malformed empty cluster membership remains UNKNOWN.
- WAF CloudWatch evidence rejects non-finite metric values instead of treating positive infinity as observed traffic.
- RC5 uses its own wheel/venv/immutable tag. RC4/RC3/RC2/RC1 and Stable remain explicit rollback choices. These fixes have synthetic/offline gates; customer AWS scans and organization-wide coverage remain separately unverified.

# Solo-maintainer modernization progress

## CIS Foundations v7.1.0 — RC4 candidate after RC3 evidence review (2026-11-02)

- Based on immutable RC3 master at `487580203269e864665589f7ddb756c0334976b5`.
  Branch: `feature/cis-foundations-v7.1.0-rc4-staging`.
- Maintainer-supplied PDF verified: **94 CIS v7.1.0 recommendations**;
  recorded 30 candidate-mapped IDs (33 rules), 43 manual-review IDs,
  13 partial existing checks not mapped, 8 not implemented.
- Analyzed RC3 authenticated field evidence: 42 services, 207 rules, 121
  triggered rule/resource pairs, zero evidence/finding mismatches; 40 unchanged
  collection issues. Verified archive SHA-256 manifest. ECR BASIC with zero
  repositories is a confirmed configuration observation only, not evidence
  of missing image scans. No private customer data uploaded to git.
- Corrected the RDS deletion-protection stage implementation: RC3 API evidence
  shows Aurora member instances; evaluate cluster-level DeletionProtection
  once per DB cluster, exclude member instances from standalone rule, and
  preserve UNKNOWN/partial for inaccessible DescribeDBClusters.
- Added five normal AWS checks: S3 effective Block Public Access,
  standalone RDS deletion protection, Aurora/Multi-AZ DB cluster deletion
  protection, EFS encryption at rest and Security Hub regional subscription. UNKNOWN/denied evidence
  is never compliant. Added synthetic rule/evidence tests and profile
  crosswalk validation with benchmark-specific IAM aging thresholds.
- Existing CIS v1.2.0 ruleset and published RC3 remain untouched. Full
  source PDF, customer logs, account IDs and raw AWS evidence are not in git.
- RC3 archive review is complete. **Release gate:** four-way branch CI,
  merged-master CI, independently verified RC4 wheel/sdist/SBOM and immutable
  tag. Never claim CIS certification or organization-wide compliance.


## RC3 field-evidence follow-up (2026-11-02; CI/release validation pending)

- Real authorized read-only scan of the prior RC1 hotfix was inspected locally,
  without uploading customer data: 42 services, 207 rules, 80 incomplete
  assessments, 40 collection issues and 120 flagged rule/resource pairs.
- One independently confirmed false negative: ECR registry BASIC scanning
  produced `evaluation_summary.counts.insecure=1` but zero findings because
  the condition read an uncollected `basic_scanning` field. The rule now
  checks `scan_type=BASIC`. No rule ID/schema change.
- Added an offline RESULTS consistency tool that reports only rule names
  and counts, plus synthetic tests for the ECR rule, unknown evidence and
  absence of customer data in diagnostic output.
- Kept S3 MRAP control-plane routing (already uses the documented us-west-2
  endpoint); do not infer a scanner defect from a manual regional redirect.
- Inspector2 stats raw API response was not captured, so the malformed
  statistics issue is unresolved rather than falsely classified as a confirmed
  collector bug.
- RC2 release remains immutable; successor RC3 has a separate tagged wheel,
  pinned environment and reversible installer selection, preserving RC2.
- No additional AWS APIs, credential use, network scans or customer report
  assets are included. Acceptance requires four offline CI variants and
  successful installed RC3 release smoke after integrating into master.



## M12 — Ridgepay RC2 stabilization (2026-11-02; release gate pending)

- Branch `stabilization/ridgepay-rc2-20261102`, based on the corrected
  `bd21ca1` master; fork PR #22.
- Fork RC2 `5.14.0+romanoff5.m10rc2` includes immutable RC1 runtime corrections.
  Installer uses side-by-side `.venv-scout-fork-rc2`, pinned 3.11 release
  constraints and full wheel/manifest/constraints SHA validation; preserved
  stable and old fork environments, explicit rollback through selection.
- Windows CI exercises PowerShell parsing, fail-closed selected-runner integrity,
  actual pinned wheel installation from offline cached artifacts, CLI smoke.
- Operational AWS evidence now records partial collection issues for invalid ECR
  scan identity/client, incomplete WAF metric data and malformed or truncated
  AWS Backup recovery-point collection; synthetic API negative cases added.
- RC2 prerelease publication is **conditional** on all four offline CI jobs and
  independent distribution verification for the integrated master SHA.
- **Not yet demonstrated:** live Ridgepay role permission preflight, authorized
  single-region read-only scan, client inventory completeness, final JSON/SQLite/
  HTML delivery. Do not report operational readiness until those gates pass.
- No upstream or PyPI publication, no credentials, live cloud calls, resource
  changes or stable installer updates are part of this branch.


## RC1 runtime correction — Task 14 / M10 (2026-11-02)

- Implemented the 13 published Network Firewall/Macie/Bedrock evidence policies
  missing from RC1's evaluator; normalized SSM/Network Firewall diagnostic codes
  without relaxing report metadata validation. Unknown collection stays partial.
- Added 38 synthetic regressions and installed-wheel policy execution checks.
  Final focused Windows/Python 3.11.9 gate: **159 passed**, no warnings, including
  AWS/Azure/GCP contracts and JSON/SQLite preservation; flake8 and diff checks pass.
  Full guarded suite on RC1 dependencies: **672 passed, 1 failed**, 34 subtests;
  unrelated failure is OS symlink privilege (`WinError 1314`), not suppressed.
- Local wheel build 1 is used by the external user launcher with a pinned hash,
  explicit repair provenance and offline installed-byte/runtime checks. Published
  RC1 assets and stable installation remain unchanged. No cloud run was made.
- Implementation branch: `fix/rc1-scanner-runtime`; implementation, pushed branch
  and verified default-branch integration:
  `70cf29d5579864543b6363e7a271a84216bb6837` (origin is `romanoff5/ScoutSuite`).
- Installed validation passed outside the checkout with the fork interpreter:
  `python -I -B tools/verify_distribution.py --source <checkout> --profile combined
  --output <local-evidence.json>`: 1,560 packaged files byte-verified, 50 runtime
  requirements, guarded AWS/Azure/GCP rules and reports, all evidence policies.
  Repair wheel SHA256:
  `bcf9ca2e419f6f745cdf9ee14c1f0186074f6d07c85ab8a8987c940f00970c0e`.
- External launcher `-SkipGitSync -InstallOnly` passed installation and a second
  reuse invocation, verifying 55 AWS evidence policies and denied API handling
  with a scoped allowance only for Windows asyncio's internal socketpair.
  Stable scanner executable SHA256 was unchanged before/after. No assessment
  was rerun. See [repair details and rollback](docs/releases/RC1_RUNTIME_HOTFIX1.md).

Current policy: local implementation and offline validation, commit/push only to
`romanoff5/ScoutSuite`, then automatic integration of passing assigned slices into
the fork's actual default branch. No upstream PR, mandatory human review or
per-task sign-off. Azure/GCP modernization is deferred. Stable scanner installations
and unrelated workspaces remain unchanged; no credentials/customer data/live cloud
calls are used. See [development rules](AGENTS.md) and [roadmap](docs/modernization/ROADMAP.md).

## Resumed work, not restarted

| Task | Verified implementation commits / pushed branch | Validation and limitations |
| --- | --- | --- |
| M01 | `222de9ec`, `14344de3`; `origin/feat/m01-offline-harness` | Offline guard, executing CLI tests, fixture manifest, provider characterization; [evidence](docs/modernization/M01_PROGRESS.md) |
| Task 01 / M02-A | `fbb4747a`, `07aa46fc`; `origin/feat/m02-a-packaging` | Clean wheel/sdist and AWS/core dependencies pass; Docker execution M02A-D01 remains unverified, not an AWS/core runtime blocker; [evidence](docs/modernization/M02_A_PACKAGING.md) |
| Task 02 / M02-B | `6ac9d1da`, `1db49cd9`, `41d98b66`, `7e4f6136`, `81ef88e3`; `origin/feat/m02-b-offline-ci` | Windows 3.11.9 / Ubuntu 3.11.18: 146 tests + 22 subtests, 161 visible warnings each; 31 fixtures and six CLI bodies verified, six dependency environments per OS; [full evidence](docs/modernization/evidence/M02_B_RESULTS.json) |

## Task 03 / M03 — Python 3.11+ runtime and sync/async contracts

**Implementation commit:** `942202db0afa04358cec2a82ff130aad96f86e76`
**Pushed to:** `origin/master`
**Remote SHA verified:** `942202db0afa04358cec2a82ff130aad96f86e76`

### Implementation summary

1. **RunContext class** (`ScoutSuite/core/run_context.py` - new file, 223 lines)
   - Manages loop, executor, throttler lifecycle per run
   - Tracks loop ownership via `_owns_loop` flag
   - `cleanup()` only closes loop if we own it
   - `cancel_all_tasks()` for proper cancellation handling
   - `lifecycle()` context manager for automatic setup/cleanup

2. **CollectionStatus** (`ScoutSuite/core/run_context.py`)
   - Dataclass with statuses: success, denied, unsupported, failed, partial, not_applicable
   - Factory methods and helper functions
   - `to_dict()` for serialization

3. **CLI refactoring** (`ScoutSuite/__main__.py`)
   - `run_from_cli()`: Uses `asyncio.run()` for fresh loop per run
   - `run_async()`: Explicit awaitable programmatic entry point
   - `_run_sync()`: Internal sync wrapper
   - `run()`: Backward-compatible wrapper preserved
   - `--local` mode skips authentication and SDK calls

4. **AWS Provider support** (`ScoutSuite/providers/aws/provider.py`)
   - Handles empty/missing credentials gracefully
   - Sets defaults without API calls in local mode

5. **Tests** (`tests/test_main.py`)
   - `TestRunContext`: Loop ownership, cleanup behavior
   - `TestAsyncAPI`: Async from existing loop, fresh process
   - `TestCollectionStatus`: Status metadata
   - `TestLocalModeIsolation`: --local skips auth
   - `TestCancellationHandling`: KeyboardInterrupt handling
   - `TestEmptyResources`: Empty collection is success
   - `TestUnexpectedChildExceptions`: Error code propagation
   - `TestFreshProcessNoImplicitLoop`: CLI from fresh process

### Acceptance criteria status:

- [x] Two consecutive sync runs work correctly
- [x] Async API from existing event loop works
- [x] Cancellation/KeyboardInterrupt handling
- [x] Empty resources handled correctly
- [x] Cleanup and no leaked tasks/executors
- [x] Fresh Python 3.14 process works with `asyncio.run()`
- [x] Python 3.11 behavior preserved
- [x] Separate client contexts for different accounts

### M03 corrective follow-up and validation (2026-11-01)

The historical implementation receipt above refers to the earlier revision,
not the final checked code. Corrected lifecycle commits `1deaf552`,
`1c2e3e73` and `15bcb1bc` were fast-forwarded into `origin/master`
at `15bcb1bc8301d82f48ab413d1a9e65cab8f3217f`.
GitHub Actions [offline run 41303798662](https://github.com/romanoff5/ScoutSuite/actions/runs/41303798662)
passed on Windows Python 3.11.9 and Ubuntu Python 3.11.18.
A master-branch rerun also passed. Local Python 3.14 (with
`pkg_resources` compatibility shim) previously passed 168 guarded tests;
the later M04 changes are not yet confirmed on Python 3.14.

Fake-clock bounded retry tests and structured incomplete collection fixtures
are added in later M04 increments below. These must not be backdated to the
original `942202db` implementation.

## Task 00 — fork workflow migration and accumulated integration

The owner assigned the modernization batch and authorized validated default-branch
integration. Confirmed `origin` is `https://github.com/romanoff5/ScoutSuite.git`;
`upstream` is read-only reference. The actual default branch is `master`.
GitHub reports it unprotected, with no repository rulesets. No security setting
was changed or bypassed. All existing implementation branches form one ancestor
chain, so their complete commits can be retained through fast-forward integration.

Changes: ignored the two local owner task documents by exact root names; updated
AGENTS/CONTRIBUTING and the roadmap for solo-maintainer batch execution; converted
reviewer roles to automated verification areas; deferred M07; retained technical
test/license/no-credential/rollback gates. Existing fork PRs #1–#3 will be reconciled
with the actual integrated commits; no upstream PR is created.

### Verified integration receipt — 2026-10-31

- Task 00 local implementation commit: `1a91b6811332a8c5b264341c0ff9b9189d4c7997`.
- Pushed branch: `origin/feat/task00-fork-workflow`, confirmed at that same SHA.
- Integrated default: `origin/master`, confirmed by `git ls-remote` at
  `1a91b6811332a8c5b264341c0ff9b9189d4c7997` after fast-forward integration.
- M01 source `14344de3`, M02-A source `07aa46fc` and M02-B source `81ef88e3`
  are all ancestors of that default SHA.
- GitHub confirms fork PRs [#1](https://github.com/romanoff5/ScoutSuite/pull/1),
  [#2](https://github.com/romanoff5/ScoutSuite/pull/2) and
  [#3](https://github.com/romanoff5/ScoutSuite/pull/3) **merged**.
- Task 00 checks: Windows CPython 3.11.9, 146 passed, 161 warnings, 22 subtests.

### M03 integration receipt

- M03 implementation commit: `942202db0afa04358cec2a82ff130aad96f86e76`.
- Pushed to `origin/master`, verified by `git ls-remote`.
- M02-B commit `81ef88e3` is ancestor of M03 commit.

Rollback: retain original default `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`
and the original implementation commits. Revert specific increments on the fork;
do not force-reset published history or change the stable scanner environment.

## M04 — runtime isolation and assessment integrity (2026-11-01)

The following increments are chained on `15bcb1bc`, with no Azure/GCP
SDK modernization. They remain in validated development branches until the
final CI gate passes, and are **not yet merged to master** as of this
documentation change.

| Increment | Commit | Scope | Validation |
| --- | --- | --- | --- |
| M04-A | `be2db62` | Per-run, per-session AWS clients; close on cleanup | Windows/Ubuntu Offline CI passed |
| M04-B | `74b96c1` | Additive incomplete statuses and per-run errors | Windows/Ubuntu Offline CI passed |
| M04-C | `63ed73a` | Bounded tasks; capped opt-in throttling retries | Windows/Ubuntu Offline CI passed |
| M04-D | `87ba3f9` | Strict completeness exit 201; finite AWS SDK timeouts | Windows/Ubuntu Offline CI passed |
| Acceptance | `d5c6759` | Real CLI exit and JSON round-trip; timeout/unsupported | CI pending when documented |

See [M04-A](docs/modernization/M04_A_CLIENT_ISOLATION.md),
[M04-B](docs/modernization/M04_B_COMPLETENESS.md),
[M04-C](docs/modernization/M04_C_BOUNDS.md),
[M04-D](docs/modernization/M04_D_STRICT.md) and
[acceptance tests](docs/modernization/M04_ACCEPTANCE.md).

Remaining work is explicitly tracked: HTML viewer presentation (M09),
full AWS direct-client timeout/pagination inventory (M05/M06),
Python 3.14 after M04, cross-account live AWS execution, and full
long-running/scale evidence. Those checks are not claimed complete.


## M08 continuation — 2026-11-01

Branch: `modernization/m08-imds-lambda-clb-iam-standards-20261101`, based on `3ed56dd5`.
Implemented: evidence-aware EC2 IMDSv2 requirement based on existing MetadataOptions;
Lambda ZIP runtime lifecycle with a static UTC-date reference catalog and explicit Image NA;
Classic ELB TLS protocol floor using policy details and a separate catalog (no ALB policy reuse).
Existing Classic ELB finding identifier retained. Added dedicated synthetic four-state tests.

IAM and standards: performed a limitation/mapping review without claiming effective permissions or inventing a new CIS edition mapping; see `docs/modernization/M08_IAM_STANDARDS_REVIEW.md`.

**Validation status:** GitHub Actions for this feature branch must pass before merge to master. Local repository checkout is not present in this execution environment, and no local offline suite or diff-check has been executed. This branch is therefore **not accepted/integrated** until verifiable CI. Do not claim live AWS testing. No Azure/GCP changes.


## M08 completion — 2026-11-01

- Branch `modernization/m08-imds-lambda-clb-iam-standards-20261101`, source code commits from `b4e597c6` through `fb2354e1`.
- Implemented EC2 IMDSv2, ZIP Lambda runtime lifecycle, Classic ELB TLS evidence classification, dated static catalogs, synthetic four-state tests; IAM catalog and newer standards are documented as partial work, not falsely certified.
- CI failure corrections: `tests/test_m08_remaining.py` nested literal syntax, `tests/data/rule-fixtures.json` manifest inventory, and `tests/data/provider-catalogs.json` expected catalog. Existing fixtures preserved.
- Verified offline Windows Python 3.11.9 and Ubuntu Python 3.11.18 success in [run 41347955928](https://github.com/romanoff5/ScoutSuite/actions/runs/41347955928).
- Integrated `origin/master` by guarded fast-forward to `fb2354e1915648d0e153b35f0cc2d7cfd3f63aa5`, verified remote ref. All older branches were ancestors or identical; no duplicated merges or upstream PRs.

## Task 11 / M09-A and CIS Foundations 7.1.0 — 2026-11-01

- Branch `modernization/m09a-versioned-report-cis-7-1-0`, implemented from validated M08 baseline `fb2354e1`.
- Changes: non-mutating, deterministic report serialization; explicit RESULTS schema v1 in JS and SQLite; compatible unversioned v0 reader; clear rejection of future/malformed schema versions; sorted report HTML template ordering. Existing finding IDs, user exceptions, filter paths and data keys are retained.
- New user-requested CIS Foundations **v7.1.0** opt-in, **partial candidate** crosswalk (`cis-foundations-7.1.0-partial.json`): 11 control IDs linked to existing evidence rules, explicitly `compliance_verified=false`. Unassessed/manual controls are not passed. Historical `cis-1.2.0.json` remains unchanged.
- Sources include user-provided benchmark PDFs used locally for mapping. PDFs and protected control text were **not** uploaded to the public repository. Additional supplied Compute/Database/Storage/End User Compute benchmarks are tracked as references without false coverage claims.
- Synthetic golden v0 fixture and v1 JS/SQLite round-trip tests; offline preservation/packaging smoke run. **Windows Python 3.11.9: 305 passed, 34 subtests passed, 161 warnings; Ubuntu Python 3.11.18: 305 passed, 34 subtests passed, 161 warnings**. Lint, build, dependency, test, packaging and workflow checks all passed: [run 41348332005](https://github.com/romanoff5/ScoutSuite/actions/runs/41348332005).
- Verified remote integration of 10 M09 commits, fast-forwarding `master` from `fb2354e1` to `6de02364d34778da1c2d0cbea8c781c766e43090`, without rewriting history.
- Limitations: no live AWS/customer scan, no Python 3.14 validation for M09, no full CIS v7.1.0 scoring or certification, no M09-B browser/SQLite server security overhaul. Rollback via explicit commit reverts (never force-reset shared history), or use the historical v0 loader for unversioned reports.

## Task 13 / M10-A — IAM Access Analyzer (2026-11-02)

First opt-in vertical slice on `modernization/m10-access-analyzer-vertical-slice`. Implemented read-only bounded
`ListAnalyzers`, explicit incomplete/denied evidence, account-visible scope,
normalized stable IDs, an inactive-analyzer finding, escaped report partial,
and strict synthetic integration tests. This **does not complete M10**.

Scope, API permissions, exclusions, test contract and rollback:
[docs/modernization/M10_ACCESS_ANALYZER.md](docs/modernization/M10_ACCESS_ANALYZER.md).
Acceptance remains conditional on Windows/Ubuntu CI and installed package tests.

## Task 13 / M10-B — GuardDuty public detector inventory (2026-11-02)

Opt-in regional GuardDuty read-only vertical slice on `modernization/m10b-guardduty-vertical-slice`.
Public collector provides bounded ListDetectors/GetDetector, incomplete
status, normalized detector IDs, a DISABLED-only finding, and an escaped
report partial. AWS/region and organization-wide coverage are not implied.
See [M10-B scope](docs/modernization/M10_GUARDDUTY.md).
M10 overall remains incomplete; no other service is advertised without an
independent complete vertical slice.

## Task 13 / M10-C — AWS Organizations vertical slice (2026-11-02)

Branch: `modernization/m10c-organizations-vertical-slice`. Opt-in global partition-aware Organizations read-only inventory
(DescribeOrganization, ListRoots, ListAccounts); evidence-aware ALL features/SCP root
findings; bounded pagination; explicit access/partial states; account emails excluded.
See [M10-C scope and rollback](docs/modernization/M10_ORGANIZATIONS.md).
M10 remains partially delivered (Organizations does not include policy contents,
OU hierarchy, effective SCP evaluation, or organization-wide proof).


## M10-D — Amazon Inspector2 (2026-11-02)

- Opt-in AWS `inspector2` collector added to `AWSServicesConfig`, `AWSFacade` and metadata; does not modify default service scan, Azure or GCP collectors.
- Read-only `BatchGetAccountStatus` (current account) and account-filtered `ListCoverage` (up to 5 pages/500 entries per Region), run-scoped concurrency and explicit partial/denied/unsupported/error handling. No vulnerability findings, delegated organization queries, customer data or AWS writes.
- Status and coverage stored at `services.inspector2.regions.<region>.accounts/coverage.<id>` with existing report schema; escaped Handlebars partials and two evidence-aware rules. Unknown/transitional and incomplete collections do not become verified PASS. No benchmark certification implied.
- Synthetic botocore Stubber/API-model tests validate account status, resource IDs, pagination, errors, cross-account filtering, normalized data, rule evaluation and opt-in; invalid initial stubs fixed to match AWS required fields.
- Source branch `modernization/m10d-inspector2-vertical-slice-20261102` at `d07eac6c6e7d453b8023be8e4237fb5b1099999c`, CI [#41370417910](https://github.com/romanoff5/ScoutSuite/actions/runs/41370417910) passed.
- Reconciled parallel Security Hub and Organizations changes using a genuine two-parent merge in `integration/m10-inspector2-all-20261102`. CI [#41370950308](https://github.com/romanoff5/ScoutSuite/actions/runs/41370950308): Windows Python 3.11.9 and Ubuntu Python 3.11.18 — **394 passed, 34 subtests passed**, 206 warnings each, lint/packaging passed.
- Fast-forward integrated `master` to `050926522c3b520794e8b9020ce6cd0d91c54e0f`, remote ref verified. No live AWS calls or customer scans. Next work: scoped coverage quality/organization-level assessment and robust region-specific behavior; avoid treating empty verified coverage as complete service enrollment.
- Rollback: revert the merge through normal history-preserving commits; no AWS state or report migration involved.

## M10 report evidence completeness correction (2026-11-02)

Branch: `fix/m10-report-evidence-completeness-20261102`. Owner requirement: security reports must retain actionable
diagnostic evidence, including account/contact emails, full ARNs, resource
names, status/reason, timestamps, tags, policy type status and OU paths.
Do not blanket-anonymize local reports. Secrets remain prohibited.
Rules codified in `AGENTS.md`.

Organizations now persists management/account emails, management ARN,
joined timestamps, OU paths, root policy types and deprecated status only
as secondary context. Access Analyzer keeps tags, timestamps, last-analyzed
resource and configuration when returned by ListAnalyzers. GuardDuty keeps
feature/data-source configuration, service-role and lifecycle metadata;
Security Hub keeps status reasons, providers and controls-updatable state.
Fixed low M10 pagination caps are raised, with explicit partial state on
exhaustion. New synthetic scale and SQLite-preservation regression tests.
Windows/Ubuntu offline CI required before integration. No live credentials.


## M10-D Inspector2 dual-branch consolidation — 2026-11-02

- Confirmed that `modernization/m10d-inspector2-vertical-slice-20261102` was already part of `master`. The separate `modernization/m10d-inspector2-account-state-20261102` had additional account **scan-type** status logic but duplicated the account-level facade, resource and finding rule.
- Resolved by preserving the already deployed **single** `Inspector2Facade`, `InspectorAccounts`, `InspectorCoverage`, all old resource paths, `resource_states`, account and coverage finding IDs. Added nested `scan_types` with five potential AWS categories (EC2, ECR, Lambda, Lambda Code, Code Repository) and the single new `inspector2-scan-type-inactive` rule. Reused the account-state classifier; no second collector or duplicated account rule.
- The API model requires EC2/ECR resource states; missing/malformed required statuses record partial collection. Absent optional scan types remain `UNKNOWN`, not disabled/secure. A nonempty `failedAccounts` rejects account status as incomplete, even when a success object was also returned. Report fields render with HTML-escaped Handlebars; original IDs and actionability are retained. Existing read-only bounded `BatchGetAccountStatus` and `ListCoverage` stay opt-in.
- Added AWS Stubber and negative tests for all five scan states, optional absence, malformed/failed response, no duplication, evidence counters, existing coverage rule, report serialization and escaped HTML.
- Two-parent merge `1fd577be90d34a21507668fa71370128a6921381` has the distinct account-state branch as an ancestor; branch history was merged with a manually reconciled final tree, not copied wholesale.
- Reconciled concurrent AWS M10 changes on the then-current master `6a8ca071a0e217e79fcb3c419b1421177891d2f2` in merge `19313c771553587accc72d24035bd96e337c23b0`. No unrelated AWS service changes were dropped. Fast-forward updated origin/master, remote ref verified.
- [Offline Windows/Ubuntu CI #41372856680](https://github.com/romanoff5/ScoutSuite/actions/runs/41372856680): each OS **406 passed, 34 subtests passed, 206 warnings**, enforced lint, packaging and browser/XSS checks passed.
- No live AWS/customer scan was performed; no CIS certification is implied. Remaining limitations: small explicit `ListCoverage` result cap (500/Region, surfaced as incomplete on overflow), absent region/resource completeness comparison, no organization/delegated administrator coverage inference.
- Rollback using history-preserving commit reverts; remove `inspector2` from opt-in service selection to avoid the new Inspector2 calls. Do not force-reset shared history or rewrite existing reports.

## Task 13 / M10-E — ECR private repository inventory (2026-11-02)

Public opt-in ECR, `DescribeRepositories` only for the authenticated account and
selected Regions, max 100 pages × 100 repositories. Full ARN/URI/name,
encryption, scan-on-push metadata, creation date, and tag mutability exclusions
are retained for remediation. Mutable tags trigger a scoped warning; enhanced
registry-level vulnerability scanning is **not** inferred from scanOnPush.
Unsupported/denied, malformed/looped pagination and overflow produce explicit
incomplete statuses. See `docs/modernization/M10_ECR.md`. ECS and EKS are
separate unimplemented next slices. No Azure/GCP collector changes.

## Task 13 / M10-F — ECS cluster inventory (2026-11-02)

Public opt-in ECS `ListClusters`/`DescribeClusters` by selected region.
Max 50 pages × 100 ARNs and batched details; collect full ARN/name, tags,
metrics, ECS Exec logging/KMS config, capacity strategy and Container Insights
state. Only explicitly disabled Container Insights triggers a scoped warning;
unknown/missing settings stay incomplete. Invalid/foreign/duplicate ARNs,
malformed/denied responses and pagination limits create collection issues.
See `docs/modernization/M10_ECS.md`. No resource mutation or live AWS test.

## Task 13 / M10-G — EKS cluster inventory (2026-11-02)

Public opt-in EKS `ListClusters`/`DescribeCluster`; up to 20 pages ×
100 names and 1,000 described clusters per Region. Full ARN, version,
endpoint/CIDR details, VPC, tags, logging, encryption, access and upgrade
settings preserved. Only explicitly public endpoint allowing `0.0.0.0/0`
or `::/0` is flagged. Missing access/CIDR evidence stays UNKNOWN;
partial/denied/duplicate/capped responses create collection issues.
See `docs/modernization/M10_EKS.md`. No Kubernetes API, credentials,
cloud writes or live AWS assessments. Azure/GCP unchanged.


## M10-E — Inspector2 scalable coverage and delegated administration (2026-11-02)

- Implemented `inspector2:ListCoverage` with AWS's 200-result page size, continuing to pagination completion and retaining the original resource IDs/ARNs, scan codes/reasons, last scan timestamp and available provider identifiers. A high, explicit circuit breaker (2,500 pages / 500,000 records per account/Region) remains: exceeding it, bad tokens, duplicate entries, or API failures is **partial**, never compliant. Earlier 5-page/500-record truncation removed.
- Added independent account-filtered `inspector2:ListCoverageStatistics` (`SCAN_STATUS_CODE`) with reported totals, group counts, pagination and count mismatch checks. Per-region `coverage_summary` distinguishes complete Inspector enumeration and statistical reconciliation from actual AWS resource coverage. It never asserts overall AWS security coverage or CIS compliance.
- Added `inspector2:GetDelegatedAdminAccount`, `ListMembers(onlyAssociated=false)`, `DescribeOrganizationConfiguration`, and read-only member `BatchGetAccountStatus` (max 100 IDs/request). Organization data is collected only when the current account is Inspector's active delegated admin in the specific Region; otherwise no unauthorized member enumeration is attempted. Member list is bounded at 50,000 accounts with explicit partial flag. Member IDs, relationship status, scan types and configuration are preserved, while AWS error messages and vulnerability data are excluded. New finding `inspector2-member-account-disabled` flags confirmed inactive member scanning.
- Optional, **zero-new-API-call** reconciliation with concurrently selected EC2, ECR, Lambda and AWS Organizations inventories compares observed IDs/ARNs and active organization roster to Inspector's reports. Missing resources and accounts retain full identifiers in report evidence, but are **unverified gaps**, not invented vulnerabilities. `organization_roster_verified` and `resource_applicability_verified` remain false unless supported by available independent evidence; no Inspector-only list can prove the whole AWS estate was scanned.
- Preserved old Inspector2 account/scan-type/coverage finding IDs, region report paths, JSON/SQLite schema and opt-in behavior (`--services inspector2`), along with existing Azure/GCP and new AWS ECR/ECS/EKS collectors. No AWS credentials, live cloud calls, customer data, secret values or remediation operations were used.
- Source branch `modernization/m10e-inspector2-coverage-org-20261102` CI [#41375445434](https://github.com/romanoff5/ScoutSuite/actions/runs/41375445434): Windows/Ubuntu **420 passed**, 34 subtests each, lint/packaging successful. Corrected opt-in test regression and retained exact rule catalog guards.
- Consolidated parallel ECR/ECS/EKS master changes with a two-parent, history-preserving integration merge `4689268733f86ce52f1c499c5be8c52bebf58d62`. [Integrated CI #41375625757](https://github.com/romanoff5/ScoutSuite/actions/runs/41375625757): Windows Python 3.11.9 and Ubuntu Python 3.11.18 — **441 passed, 34 subtests passed**, 206 warnings each; lint, packaging, offline and browser security gates passed. Fast-forward merged and verified remote master.
- Limitations: no live AWS/organization validation. AWS service-level eligibility, undiscovered resources, nonassociated organization accounts, partition/Region drift, exceptionally large inventories and racing API snapshots still require independent confirmation. Rollback via ordinary revert commits; selecting no `inspector2` avoids new Inspector2 API actions.

## M10-H — default ECR/ECS/EKS and deeper controls (2026-11-02)

ECR, ECS and EKS are part of the ordinary AWS service selection. Other
experimental M10 services remain opt-in. ECR now collects registry scanning
configuration; ECS enumerates up to 1,000 ACTIVE task definition revisions
with a strictly sanitized report (no environment values or logging tokens);
EKS evaluates `audit` control-plane logging from DescribeCluster.
Collection failures stay explicit, and no resource modification is used.
See M10_ECR.md, M10_ECS.md and M10_EKS.md for scope and limits.


## CI warning root-cause remediation — 2026-11-02

- Baseline on [Offline CI #41376017062](https://github.com/romanoff5/ScoutSuite/actions/runs/41376017062): both Windows 2022 / Python 3.11.9 and Ubuntu 24.04 / Python 3.11.18 had **441 passed, 34 subtests passed, 206 warnings**.
- Warning source classification by structured `conftest.py` evidence: **50** first-party invalid regex string escapes in `ScoutSuite/providers/utils.py`; **127** in pinned legacy GCP KMS SDK, **17** in legacy GCP Monitoring, **10** in `pkg_resources` namespaces, **2** in legacy Azure SQL SDK.
- Converted **87** secret-detector regex source literals to raw strings without altering regular-expression expressions. Added warning-as-error Python compile test, synthetic detector regressions, and explicit CI `verify_warning_debt()` with **14** precisely identified third-party warning path/category maximums. Any new first-party or unrecognized warning now **fails CI**, while known third-party warnings remain visible and are not filtered. Azure/GCP SDKs remain pinned and unmodified.
- Detailed breakdown and phased follow-up for the 156 third-party warnings: `docs/modernization/CI_WARNING_AUDIT_2026-11-02.md`; eliminating them requires separate, tested SDK/provider compatibility migration, not silencing deprecations or weakening tests.
- Source branch `maintenance/m10-ci-deprecation-warning-cleanup-20261102` passed both systems; reconciled parallel M10-H AWS changes in two-parent merge `21cd77c479248059675d70f81bbdbf7f2dd16656`, preserving both histories. [Integrated Offline CI #41413294264](https://github.com/romanoff5/ScoutSuite/actions/runs/41413294264): **461 passed, 156 warnings, 34 subtests passed** per OS, lint, XSS/browser and packaging gates passed. **Zero first-party warnings**, explicit 156-vendor ceiling enforced. Fast-forward merged and remotely verified `master`.
- No production/cloud credentials, live scans, external assessment artifacts, Azure/GCP modernization, vendor SDK monkeypatching, warning suppression or disabled tests.

## M10-I — All integrated M10 services enabled by default (2026-11-02)

Ordinary `scout aws` scans now include **all eight** integrated M10 services:
`accessanalyzer`, `guardduty`, `securityhub`, `organizations`,
`inspector2`, `ecr`, `ecs`, and `eks`. Removed the provider-level
post-selection filter which previously disabled five of them.

Normal service selection is still handled by `BaseProvider`:
`--services` can restrict a scan to requested services; `--skip-services`
can exclude any subset without affecting the others. Local/offline replay
does not construct live provider facades or perform AWS SDK calls.

**Operational note:** default AWS scans will issue the read-only API requests
required by each selected M10 collector. IAM permissions/SCPs and AWS service
availability may make a collection denied, unsupported, partial or
not-applicable; missing evidence is never considered a successful security
check. Organization and Inspector delegated-admin enumeration remain subject
to their existing permission, scope and completeness gates. New default
selection does not assert live-tested estate-wide coverage.

No Azure/GCP collector modernization, new AWS write operations, vulnerability
finding payload requests, or changes to configured collection caps.

## M10-J — AWS WAFv2 regional and CloudFront Web ACL inventories (2026-11-02)

Adds the public `wafv2` service to the default AWS scan, with bounded read-only `ListWebACLs`, `GetWebACL` and `GetLoggingConfiguration`. Regional Web ACLs are collected for selected Regions and CLOUDFRONT scope only in `us-east-1`. Preserves full ARN/ID/name, priority-ordered rule names and type summaries, logging destinations, scope and default action without retaining raw rule statements/request bodies. Empty ALLOW ACLs not managed by Firewall Manager are flagged; missing/ambiguous management, details, logging and API responses remain partial/unknown. CloudFront scope is not claimed if `us-east-1` is not scanned. See `docs/modernization/M10_WAFV2.md`. No AWS writes or Azure/GCP modernization.

## Task 13 / M10-K — AWS Backup vault and backup plan inventory (2026-11-02)

- New default AWS Backup public API vertical slice (no special opt-in): regional
  `ListBackupVaults` + `DescribeBackupVault`, and `ListBackupPlans` +
  `GetBackupPlan`. `--skip-services backup` remains available.
- Resource paths: `services.backup.regions.<region>.vaults.<id>` and
  `services.backup.regions.<region>.plans.<id>`. Preserve full vault/plan ARN,
  backup plan schedules and copy/retention rules, KMS key, lock state, vault
  retention bounds, timestamps and recovery-point count. The HTML viewer
  escapes untrusted values; no backup contents, secret values, selections
  or recovery point payloads are collected.
- `backup-vault-lock-disabled` warns only on `Locked=false`. Unknown/absent
  state does not become a verified pass. Pagination, malformed data, token
  cycles, deduplication, permissions and failed details record collection
  issues rather than implying completeness.
- Branch: `modernization/m10k-aws-backup-vaults-plans-20261102`.
  Implementation commit, branch head and fast-forwarded `origin/master`:
  `297a7cd461f386cef2bcf2ebc47339e4736b39df`.
- Offline CI [run #41417744603](https://github.com/romanoff5/ScoutSuite/actions/runs/41417744603)
  passed on Ubuntu 24.04 / Python 3.11.18 and Windows 2022 /
  Python 3.11.9, including build, lint, guarded tests, XSS/browser and
  packaging tests, plus Linux SQLite HTTP integration. Synthetic AWS
  response structures independently validated with botocore Stubber.
- No live AWS account or customer environment assessed. No CIS compliance
  certification inferred. Scope exclusions and rollback are documented in
  `docs/modernization/M10_BACKUP.md`.
- Follow-ups: backup selections/assignment coverage, vault access policies,
  vault tags, recovery-point resilience, backup audit evidence and restore
  test coverage. These were not evaluated by M10-K.

## M10-J2 — WAFv2 associations (2026-11-02)

Extended default-scan WAFv2 to discover actual Regional Web ACL associations
via `ListResourcesForWebACL` (ALB, API Gateway REST stages, AppSync, Cognito,
App Runner, Verified Access, Amplify) and CloudFront distributions via
`ListDistributionsByWebACLId` (full WAF ARN, up to 100 pages × 100).
Explicit `associated`/`unused_candidate`/`unknown` with per-type
completeness; access denied, malformed/foreign, duplicate, capped and looping
responses cannot be classified as unused. Full associated ARN and CF
ID/domain/status retained for remediation. Added scoped unused-candidate
finding and synthetic SDK/security/regression tests; no writes or live cloud
calls. See `docs/modernization/M10_WAFV2.md`.

## M10-L — IAM Identity Center assignments and principal evidence (2026-11-02)

- Implemented default read-only regional `identitycenter` service (can be
  selected with `--services identitycenter` and disabled with
  `--skip-services identitycenter`). Queries visible SSO instances,
  permission sets, attached AWS/customer-managed policy references,
  inline-policy presence, permissions boundaries, provisioned accounts,
  account assignments, principal identities and direct group memberships.
- Preserves full instance/permission-set ARNs, AWS account IDs, identity-store
  IDs, user/group IDs and ARNs, revisions, membership IDs/ARNs, user names,
  all email addresses and attached policy references. No raw inline policy
  contents, credentials or unrelated identity attributes are stored.
- `identitycenter-aws-admin-policy-assignment` flags a positively observed
  AWS-managed AdministratorAccess policy on an account assignment. Other
  policies, SCPs and boundaries can affect effective rights: non-matching
  assignments do **not** prove least-privilege. Denied/missing identities,
  failed pages, permission metadata and group resolution produce
  explicit incomplete/unknown evidence rather than false PASS.
- Independent M10-L branch `modernization/m10l-identity-center-20261102`
  validated with Ubuntu 24.04 / Python 3.11.18 and Windows 2022 /
  Python 3.11.9 [Offline CI #41421966510](https://github.com/romanoff5/ScoutSuite/actions/runs/41421966510),
  after AWS botocore model corrections (Identity Store UserArn/GroupArn,
  Revision and MembershipArn). M10-J2 WAFv2 test identifiers also corrected.
- Reconciled 26 parallel master commits (AWS Backup depth and M11 SDK
  migrations) through a two-parent merge on
  `integration/m10l-identity-center-all-20261102`. The combined CI
  [#41422635182](https://github.com/romanoff5/ScoutSuite/actions/runs/41422635182)
  passed on Ubuntu and Windows, including lint, guarded offline tests,
  XSS/browser, packaging and Linux SQLite HTTP integration.
- Remote `master` verified at integration commit
  `f11f1d8777ec55e71f782a0c022489875d9852aa`. No upstream PR, live
  AWS assessment, cloud writes or customer data processing. Next: optionally
  analyze inline/customer-managed permissions and cross-account SCP context
  in a separately tested slice; this initial rule is not an effective
  permission evaluator.

## RC5 RDS snapshot cache correction (2026-11-02)

- The published RC5 `get_snapshots` path raised `KeyError` for a previously
  uncached Region: `_cache_snapshots` passed `_snapshots_cache[region]` to
  enrichment before publishing that cache entry. Commit
  `849a73a096da9da72e95bbf9a8bebaa9c57c51e2` passes the freshly fetched
  local snapshot list and adds a synthetic two-snapshot cache/reuse regression
  test. AWS RDS read permissions, report schema, rule IDs, and other providers
  are unchanged. Rollback is the parent commit; the tagged RC5 release remains
  immutable and is not represented as fixed.
- Guarded focused tests: 10 passed. Full guarded local suite using RC5 runtime
  dependencies and the isolated pytest runner: 703 passed, one Windows
  symlink-privilege failure (`WinError 1314`); no changed-feature failure.
  Focused flake8 and `git diff --check` passed. The earlier stale test
  environment additionally failed three Azure/GCP SDK contract tests, which
  disappeared with RC5 dependencies. CI status and pushed/default-branch SHA
  are recorded in the follow-up integration note.
- The Ridgepay assessment's separately authorized live scan and customer
  evidence are stored outside this repository under the customer's private
  `results/codex-review` and `reports/scout-fork` directories. No customer
  data or credentials were used for development fixtures or committed here.
- The fix branch was reconciled with the independent Macie change using merge
  commit `f0a80ac4829968ad6b99f061e8d2302e5597e953`; its combined
  [Offline CI run](https://github.com/romanoff5/ScoutSuite/actions/runs/41501772190)
  passed all four Windows/Ubuntu Python 3.11/3.14 jobs. The earlier
  [fix-only CI run](https://github.com/romanoff5/ScoutSuite/actions/runs/41500978332)
  also passed all four jobs. Branch `fix/rc5-rds-snapshot-cache` was pushed at
  `f0a80ac4829968ad6b99f061e8d2302e5597e953`; remote default branch
  `master` was fast-forwarded and verified at the same SHA. No PR or upstream
  push was made. The published RC5 tag/wheel still contains the defect; a
  future release requires fresh packaging and live acceptance.
