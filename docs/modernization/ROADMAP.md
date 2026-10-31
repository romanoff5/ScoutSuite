# Prioritized modernization roadmap

Status: **proposal, no modernization implementation authorized or applied**. Date: 2026-10-30. Based on revision `7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d`; see [baseline](BASELINE.md) and [offline evidence](OFFLINE_VALIDATION.md). Scope is Python 3.11+ and current AWS behavior while preserving Azure and GCP.

## Strategy and target architecture

Retain the existing facade/resource/rules/report seams. Introduce explicit contracts around them through small changes. A wholesale rewrite or a single dependency refresh would obscure collection, interpretation and presentation regressions.

Target flow: a CLI or async entry point supplies explicit run context (provider credentials, service/region selection, concurrency/rate policy, errors and cancellation). Provider adapters collect typed or validated raw responses; resource normalizers produce a versioned, provider-specific result contract. Rules operate on normalized offline data and report evaluated/not-applicable/incomplete states. Encoders and the viewer consume immutable versioned results. Add contracts incrementally; do not require a new ORM, framework or common cross-cloud resource schema.

Priorities: **P0** makes subsequent work safe and measurable; **P1** prevents incorrect or incomplete assessment and protects compatibility; **P2** expands coverage or improves maintainability after those gates. Relative size is S (one focused PR), M (several bounded PRs), or L (a migration lane requiring subdivision), not a delivery estimate. Owners are required roles, not assigned people.

## Ordered backlog

| ID | Priority / size | Deliverable | Dependencies | Required review roles |
| --- | --- | --- | --- | --- |
| M01 | P0 / M | Enforced offline harness, honest test execution, portable fixture loading and baseline manifests | None | Test maintainer, multi-cloud maintainer |
| M02 | P0 / M | Valid dependency metadata, reproducible environments, supported CI and installed-wheel checks | M01 safety guard | Packaging/CI maintainer, Azure/GCP maintainers |
| M03 | P1 / M | Python lifecycle and synchronous/async API contracts, real offline local replay | M01, M02 bootstrap | Shared runtime maintainer, all three provider reviewers |
| M04 | P1 / L | Assessment completeness states, bounded collection, per-run caches, retries and cancellation | M01; runtime lifecycle from M03 | Runtime and provider maintainers |
| M05 | P1 / M | AWS API/pagination/response corrections for existing services | M01, tested AWS SDK constraints from M02; M04 error contract | AWS maintainer |
| M06 | P1 / M | Legacy/deprecated AWS surface adapters and dated metadata | M05 | AWS maintainer, report compatibility reviewer |
| M07 | P1 / L | Azure/GCP SDK migration and optional provider dependencies | M01 characterization, M02 packaging, shared M03/M04 contracts | Azure and GCP maintainers, packaging maintainer |
| M08 | P1 / L | Current rule semantics and versioned policy profiles | M04, relevant M05/M06 data contracts | AWS security-rule reviewer, standards owner |
| M09 | P1 / L | Versioned reports, safe deterministic serialization, reproducible local viewer assets | M01 report fixtures, M02 build inputs; M04 completeness contract | Report/UI maintainer, security reviewer, all three providers |
| M10 | P2 / L | Public current-service AWS coverage in small vertical slices | M04, M05, relevant M08/M09 interfaces | AWS maintainer, permissions/security reviewer |
| M11 | P1 / M | Release gates, compatibility/scale evidence and staged rollout | M03-M09; only completed M10 services included | Release owner, provider/report maintainers |

M07 and M09 preparation can proceed alongside bounded AWS work once their prerequisites pass. Do not change the same shared dependency or schema independently in competing migrations. A release may ship a completed subset of M10; it must not advertise planned services as supported.

## Phase 0 — baseline and development boundaries (this deliverable)

Deliverables: repository `AGENTS.md`, architecture/debt baseline, AWS operation inventory, observed offline results and this prioritized roadmap.

Acceptance criteria:

- Baseline names a source revision, assessment date, source evidence and unknowns.
- Changes are documentation only; scanner code, requirements, rules, fixtures, CI, generated report assets and package version remain unchanged.
- No production credentials, customer data, live assessments, external report uploads or cloud writes are used.
- Reproduced failures and misleading passes are retained as evidence; no green baseline is claimed.

## Phase 1 — make validation reliable (M01, bootstrap M02)

Implement in this order:

1. Add a default test harness that blocks external HTTP/gRPC/sockets and cloud credential discovery before provider imports. Allow only explicit local IPC required by the test platform. Isolate home/config paths, disable metadata access, and use synthetic identities. Child-process tests must inherit isolation. Keep any future live tests outside default collection.
2. Make fixture loading portable: resolve the current Git symlink aliases deliberately or replace them with explicit fixture references. Fix path comparisons with path-aware expectations, temporary-file cleanup, fixed filesystem output paths and shell-based CLI smoke invocation.
3. Convert the six async CLI tests to actually execute. Align them with the current synchronous `run_from_cli()` / async `_run()` boundary, arguments and return codes. Do not simply add an async marker to synchronous functions. Remove broken mocks, vacuous assertions and broad xfails only when replaced with behavioral tests.
4. Build a rule-fixture manifest. Separate presence, parseability, positive/negative cases and verified expectations. Missing fixtures must fail the declared covered set. Keep a visible backlog for uncovered rules; do not label all rules tested because a single loop completed.
5. Add synthetic characterization fixtures for at least one meaningful collection-to-rule-to-report path for each of AWS, Azure and GCP. Include existing exceptions and stable IDs. Record all configured service/rule keys and templates structurally for the remaining catalog.

Acceptance criteria:

- An intentionally unmocked external request, default SDK credential lookup, and subprocess escape each fail a harness self-check. No real credential stores are accessed.
- All six CLI test bodies demonstrably execute; an assertion deliberately broken during validation causes failure. Runtime/unawaited-task warnings from application tests fail the gate.
- Both recorded Windows failures are resolved with reviewed tests; test outputs stay under temporary directories and leave Git clean.
- Existing 19 paired AWS fixture names are accounted for; coverage reports separately identify untested rules, parse failures and intentional aliases. Every changed rule has passing secure/unsafe cases.
- AWS/Azure/GCP characterization tests and provider imports run on Python 3.11 in a documented isolated environment. Missing SDK compatibility is reported as a blocking item for the affected migration, not replaced by a permissive mock of the entire provider.
- New test policy prevents credential/cloudwatch/profiles tests from running accidentally. An xfail/skip is never used as the safety boundary.

Regression/rollback: record exact commands, dependency snapshot, test counts and warnings. Retain baseline expected behavior, including documented deficiencies, until the corresponding behavior change is separately reviewed. Harness changes can be reverted without altering production scanner behavior.

## Phase 2 — reproducible packaging and CI (M02)

First fix invalid requirement syntax. Add explicit build-system/interpreter metadata without changing CLI entry points. Establish tested constraints for core, AWS, Azure and GCP and a combined installation; record hashes/provenance for release artifacts. Retain the combined installation as a compatibility path while dependency boundaries are audited. Keep development tools separate from runtime dependencies.

Replace retired runner/cache references with currently maintained, runner-compatible actions pinned to reviewed commit SHAs. Use explicit read-only permissions, timeouts and cancellation; cache keys must include OS, interpreter and all relevant dependency inputs. Separate dependency acquisition from offline test execution. PR tests receive no cloud secrets; coverage uploads contain sanitized coverage only. Replace the dummy frontend job when the asset build exists.

Build the fork's wheel/sdist and verify resource/rules/template inclusion for all registered providers, including DigitalOcean. Docker must install the fork artifact, install its prerequisites, report its revision, and pass offline smoke tests; it must not silently install the upstream PyPI package instead.

Acceptance criteria:

- All requirement entries parse with supported packaging tools; fresh Python 3.11 core/AWS, Azure, GCP and combined installs resolve or have an explicit migration blocker with a tracking item. `pip check` passes for each declared supported environment.
- Wheel/sdist installs outside the source tree preserve `scout` entry points, provider metadata, default rules, report templates and assets. Core-only behavior is accurately defined before publishing extras.
- Required CI runs on a supported Ubuntu runner and Windows. Actions and toolchain versions are recorded; no PR job has cloud permissions or production/customer artifacts.
- Baseline checks and offline suites pass from acquired dependencies with test-time external egress denied. The log names the resolved versions, interpreter and OS.
- Build inputs produce a reproducible asset/package manifest; SBOM and dependency/advisory review use the resolved graph. Vulnerability exceptions are narrow, reviewed and time-bound.

Regression/rollback: upgrade one dependency family at a time with before/after results. Keep the last passing constraints/artifacts. Do not regenerate all lock inputs with unrelated behavior changes.

## Phase 3 — shared runtime and assessment integrity (M03, M04)

Use a deliberate synchronous CLI wrapper and an explicit awaitable programmatic path. Manage loop, executor, throttler, cancellation and client lifetime per run; avoid closing a caller's loop or attaching arbitrary shared state to it. Make local replay operate from synthetic saved data without authentication/provider network initialization. Remove compatibility monkeypatches only after affected behavior is covered.

Introduce additive collection/evaluation status metadata: success (including a genuinely empty result), denied, unsupported, failed, partial and not applicable, with useful sanitized diagnostics. Rules must not convert unavailable evidence to a passing result. Keep existing finding fields readable while the viewer learns the added states. Decide exit-code behavior explicitly; preserve existing codes by default and introduce an opt-in strict completeness mode before making it a default.

Bound queued work and API concurrency; define finite SDK timeouts/retry limits with jitter and service-aware throttling. Avoid duplicate retry layers. Cache clients by run/session/account/partition/service/region as appropriate, and close them. Define intentional partial-results behavior for interrupted runs.

Acceptance criteria:

- Tests cover two consecutive sync runs, a call from an existing event loop via the async API, cancellation/KeyboardInterrupt, empty resources, unexpected child exceptions, cleanup and no leaked tasks/executors.
- A fresh Python 3.14 process can enter the CLI without depending on an implicitly created loop. Python 3.11 behavior remains covered.
- Two mocked accounts using the same region cannot reuse each other's clients/results/errors. A cache hit does not instantiate an unused client.
- Denied/timeout/unsupported/malformed-page fixtures remain visible as incomplete assessment in rules and reports. Empty successful collection remains distinct. Zero checked items is not presented as evidence of compliance.
- Fake-clock tests verify maximum attempts/backoff and cancellation during throttling. Measured in-flight and queued work stay within configured bounds.
- AWS/Azure/GCP characterization contracts pass; `--local` from synthetic fixtures triggers zero auth or SDK calls, including provider constructors.

Regression/rollback: additive status fields and an explicit result-format version retain old readers or fail with a clear version message. Runtime and status changes ship in separate PRs. Revert behavior independently without deleting saved evidence.

## Phase 4 — correct existing AWS collection (M05, M06)

Start with S3 bucket pagination, CloudFront/SQS pagination, EFS tag replacement and CloudTrail basic/advanced selectors. Update request/permission inventories together with adapters. Audit direct list calls, default filters (including ACM certificate key types), per-resource lists, paginator response keys and pagination tokens against the selected botocore models. Model checks run without creating authenticated sessions.

Then address regions/partitions, missing optional fields, S3 ownership/public-access context, Config recorder variants, KMS key eligibility/rotation fields, RDS/Aurora cluster differences and legacy Classic collections. Preserve legacy saved-report structures through adapters. Put public metadata such as CA/runtime/TLS catalogs and IP ranges under a versioned provenance/update policy, not automatic test-time downloads.

Acceptance criteria:

- Every changed AWS operation has strict request-parameter tests, empty/single/multipage responses, absent optional fields, denied/throttled/deleted/unsupported cases and normalized output expectations.
- Synthetic S3 quota/continuation cases return all pages; directory-bucket coverage is explicitly implemented or marked outside the general-purpose collector's scope. CloudFront/SQS second-page resources cannot disappear.
- EFS uses `ListTagsForResource`, preserves `Tags`, follows continuation tokens, and documents the exact IAM permission delta. Do not infer permissions just by changing the API name.
- Basic and advanced CloudTrail selectors, multiple selectors, organization trails, missing permissions and non-home regions produce reviewed results. Timestamp arithmetic is portable with exact freshness boundaries.
- Commercial/GovCloud/China and opt-in/disabled region fixtures preserve partition-aware identifiers and skip reasons; global resources are deduplicated correctly.
- Legacy API responses and saved Classic resources remain readable. Unsupported legacy collection is observable, without silently treating it as missing security configuration.
- SDK operation/paginator validation and Azure/GCP shared smoke suites pass with no broad dependency bump.

Regression/rollback: each service correction is a separate change with old/new normalized snapshots and a permissions diff. Keep stable rule/resource IDs. Avoid simultaneously changing collection and severity so differences are attributable.

## Phase 5 — migrate Azure/GCP safely (M07)

Characterize each SDK family before upgrading it. Keep SDK-specific request/model differences in adapters so rule paths and templates remain stable. Stage Azure Identity/Graph, then management SDKs in groups (resource/RBAC, network/compute, storage/Key Vault, database/security). Handle deprecated password authentication with a documented replacement using supported interactive/workload flows; preserve CLI, service-principal and managed-identity selection semantics.

For GCP, migrate Monitoring and KMS request/path shapes, then other client libraries. Audit obsolete `oauth2client` usage and transport/discovery coupling. Replace the global httplib2 shim only with a tested per-thread/per-request transport strategy. Explicitly test whether discovered clients use the authenticated identity and whether cached discovery requires network.

Acceptance criteria:

- Azure fixtures cover tenant/subscription selection, every existing auth mode's selection/error path, Graph `@odata.nextLink`, 404/403/429, beta-field absence, sovereign endpoints where supported, pageable SDK models and serialized resource properties. No real login occurs.
- GCP fixtures cover mocked ADC/service-account selection, project/folder/organization traversal, IAM policies, discovery HTTP and gRPC pagination/errors, KMS and Monitoring migrated calls, and Functions v1/v2. No real discovery download or token refresh occurs.
- Every migrated service preserves stable normalized IDs/paths and finding outcomes on unchanged fixtures; intentional differences have explicit golden diffs and rule-version notes.
- AWS suites stay green while Azure/GCP constraints change; combined and provider-specific installs pass `pip check` and installed-wheel smoke tests on the claimed runtime matrix.
- Optional extras do not break existing combined installs, silently remove services, or make AWS CLI help import unrelated SDKs. Missing-extra errors identify the required extra before credential discovery.

Regression/rollback: one SDK family per increment, with a compatibility adapter or previous constraints available. No forced simultaneous migration of all providers. Do not preserve a deprecated auth flow by bypassing MFA or TLS checks.

## Phase 6 — current security checks and report contracts (M08, M09)

Rule order: (1) false-clean/incomplete-state handling, (2) RDS CA lifecycle, TLS policy capability checks, S3 encryption/exposure, CloudTrail selector aggregation, KMS eligibility/rotation periods, (3) IMDSv2/Lambda runtime lifecycle, (4) IAM policy-data freshness and versioned standards/profile review. Maintain old rule IDs or supply a migration map for renamed/replaced controls and exceptions. Review CIS/other benchmark editions and licensing before shipping new mappings; do not invent equivalence between editions.

For reports, first introduce deterministic, non-mutating serialization and explicit schema versions. Preserve JavaScript payloads and SQLite behavior through a reader adapter or an intentional migration. Rebuild bundled assets from a reviewed manifest with licenses/hashes; update libraries in small steps, serving all assets locally. Remove unnecessary dynamic execution/unsafe DOM paths with escaping tests. Improve SQLite pagination/API bounds and configurable endpoint handling independently from frontend restyling.

Acceptance criteria:

- Every changed/new rule has secure, unsafe, missing-data and denied/not-applicable cases where relevant; exact finding IDs, affected resources, severity, checked/flagged counts and exceptions are reviewed. Unknown policy/runtime/CA values remain visible.
- Versioned TLS/CA/runtime/IP catalogs have source URLs, retrieval/version dates, an owner and an offline update test. Old secure and new secure values are not conflated with arbitrary unknown names.
- AWS/Azure/GCP synthetic golden reports preserve navigation, counts, filters/search, exceptions and resource links. JSON/SQLite round trips preserve the declared schema. Old supported reports either load compatibly or return a precise supported-version error.
- Encoding does not delete credentials/profile/metadata from the in-memory provider object. Sensitive fields do not appear in normal logs or test snapshots.
- Browser tests verify hostile tags/names/policy strings are rendered as text, no unexpected script executes, no console errors occur, and no external network request is made. Asset licenses and reproducible bundle hashes are checked.
- SQLite API tests cover bounds, missing keys, allowed origins, loopback defaults and non-default port configuration. Untrusted deserialization remains blocked unless a reviewed safe format is adopted.
- Scale fixtures benchmark collection, rule engine, serialization and browser memory separately. Before performance changes, record a synthetic reference (for example 10,000 and 100,000 resources); agree budgets, then enforce no more than 20% unexplained time/memory regression on the same runner. Do not claim the present code meets those targets.

Regression/rollback: retain old fixtures and versioned readers; never silently regenerate report goldens. Roll back rule profiles/catalogs independently of collector releases. A frontend rollback must not require a new cloud scan.

## Phase 7 — expand current AWS coverage (M10)

Each service is a vertical slice: advertised capability -> permissions -> pagination/error handling -> normalization -> security rules -> report templates -> offline tests -> support documentation. Optional private imports are not a substitute for public tested collectors, and their implementation must not be copied without provenance/license review.

| Order | Candidate slice | Security outcomes and scope boundary |
| --- | --- | --- |
| 1 | Identity Center/Organizations inventory, IAM Access Analyzer, organization logging | Expose identity and organization context, trust/public/cross-account access and logging gaps; never claim complete IAM policy evaluation without all applicable policy layers. |
| 2 | GuardDuty and Security Hub configuration, Inspector, Macie where relevant | Report enablement/coverage and organization/member/region context. Importing vendor findings is distinct from verifying controls or exporting assessments. |
| 3 | ECR/ECS/EKS | Repository exposure/scanning, task execution vs task roles, public endpoints, control-plane logging and supported authentication settings. No container execution or cluster modification. |
| 4 | SSM, AWS Backup, WAFv2, additional S3 access surfaces | Configuration posture, protection and exposure; no SSM command execution, backup restores or policy changes. |
| 5 | Selected newer services such as Bedrock | Start only with a defined user need, configuration APIs, least-privilege permissions and a testable control model. No prompt/content/customer-data collection by default. |

Acceptance criteria per slice: explicit supported accounts/regions/partitions and unsupported cases; strict mocked API/permission contracts; positive/negative/denied/empty/multipage tests; deterministic reports and exceptions; bounded work/cost model; no secret-content retrieval or resource writes; passing shared AWS/Azure/GCP gates. New services default to opt-in until these criteria pass. Priorities may be reordered based on a documented target environment, not unverified popularity.

## Phase 8 — release and ongoing maintenance (M11)

Support matrix proposal:

| Runtime/platform | Required target |
| --- | --- |
| Python 3.11 | Minimum supported; full offline AWS/Azure/GCP and report suite on Linux; Windows suite and package smoke |
| Python 3.12, 3.13, 3.14 | Promote each to required full provider/packaging gates as its dependency lane passes; do not infer support from syntax compilation |
| Python 3.15 | Start with an informational compatibility lane; publish blockers; promote to required only after SDK/wheel and provider/report gates pass |
| macOS / alternate architectures | Installed-wheel and offline core/provider smoke where SDK wheels exist; explicitly state coverage before claiming support |
| Python 3.9/3.10 | Drop from the modernization support claim with a release note; retain the old release for historical reproducibility |

Acceptance criteria:

- The release documents exactly which Python/OS/provider combinations passed, the supported saved-report window and the catalog/standard versions. No unsupported lane is silently reported as success.
- Required offline tests, package contents, `pip check`, lint, selected type checks, dependency/advisory review, browser/serialization contracts and synthetic performance budgets pass on the exact release artifact.
- Build provenance, hashes and SBOM accompany the fork's versioned artifacts. A rollback package plus constraints, rule/catalog version and report reader compatibility are recorded.
- An optional later disposable-cloud integration smoke is separately authorized under `AGENTS.md`; it is not required to complete this initial offline roadmap, never uses production/customer data, and cannot substitute for the offline suite.
- A release candidate is evaluated using synthetic fixtures first. Review outcome differences by collector/rule/schema version before changing defaults. Preserve the last known-good artifact and document revert steps.

After release, schedule dependency/SDK/model and metadata freshness review, test new supported Python releases, and triage provider retirement notices. Suggested cadence: monthly compatibility/advisory review and quarterly rule/profile review, adjusted to maintainer capacity. These are proposed processes, not automations created by this assessment.

## Dated implementation evidence

2026-10-31: [M02-A packaging evidence and rollback](M02_A_PACKAGING.md) records verified Windows/Linux Python 3.11 dependency and installed-artifact gates. Docker execution remains blocked under tracking item M02A-D01; M02-A is not fully accepted until that gate passes. M02-B and subsequent phases are not included.

2026-10-31: [M02-B CI contract, evidence and rollback](M02_B_CI.md) describes pinned Windows/Ubuntu workflows, separate acquisition and offline execution, OS and M01 isolation, fixture/body verification and current PR log links. Local source tests increase to 146 plus 22 subtests; historical warning debt stays visible. Hosted acceptance is determined by PR #3's current-head checks. M02A-D01 remains a separate Docker blocker; no later modernization phase is included.

## Definition of done for each change

A PR is ready only when it names its backlog item, documents the behavior and permission delta, includes the relevant regression evidence, preserves unaffected-provider contracts, identifies compatibility/rollback consequences, and has the required reviewers. Unresolved failures, missing fixtures, deferred services and advisory exceptions remain visible in a dated progress record. Keep this roadmap and the historical baseline distinct.
