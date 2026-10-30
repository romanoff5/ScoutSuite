# Repository development rules

## Scope and current stage

This repository is a multi-cloud security assessment tool. The initial modernization deliverable is documentation only: see [baseline](docs/modernization/BASELINE.md), [roadmap](docs/modernization/ROADMAP.md), and [offline validation](docs/modernization/OFFLINE_VALIDATION.md). These documents describe proposed work, not permission to implement every phase. Do not begin modernization implementation until the user requests it. Follow explicit user instructions when they narrow or change this scope.

## Security and data boundaries

- Never use production cloud credentials or customer assessment data for development, examples, fixtures, benchmarks, or CI.
- Initial and default validation must be offline, using synthetic fixtures and mocked API responses. Dependency downloads and public documentation research are separate setup activities; they do not authorize cloud API calls.
- Do not inspect developer credential stores, reuse ambient profiles, invoke cloud CLIs, authenticate through ADC/SSO/managed identity, or probe instance/container metadata. Isolate credential discovery and deny external network access during tests. Mock authentication as well as resource APIs.
- `--local`, `--no-browser`, test markers, skips, and xfails are not network isolation. At the baseline revision, `--local` still authenticates and constructs providers before loading saved data.
- Never execute the default scanner run, a credential-marked test, or `tools/aws_security_hub_export.py` during offline validation. The export tool writes to AWS. An xfail can still execute its body.
- Any later live integration test requires explicit authorization for a named disposable non-production account/project/subscription, allowed operations, regions, cost limits, and cleanup. It must be opt-in, separate from normal tests, and use short-lived least-privilege credentials. No production credentials or customer data are permitted.
- Preserve assessment behavior as read-oriented. Do not add remediation, resource creation, policy changes, secret-value retrieval, or broader permissions implicitly. Review metadata operations such as IAM credential-report generation individually; their names alone do not establish safety.
- Treat resource names, tags, policies, user data, local reports, exceptions, and SDK error messages as untrusted and potentially sensitive. Do not publish generated reports or upload them to telemetry, coverage, issue trackers, or external services. Logs and snapshots must not contain tokens, private keys, secrets, or real identifiers.
- Keep report serving on loopback by default. Do not widen CORS, bind interfaces, disable TLS validation, or suppress authentication checks to make tests pass. Treat SQLite reports as trusted serialized input until their loading behavior has been reviewed.

## Architecture and compatibility

- Preserve the authentication -> provider/facade -> resources -> preprocessing -> rules -> postprocessing -> report boundaries. Keep provider SDK calls inside provider adapters/facades; keep rule evaluation and report rendering usable without cloud access.
- Shared code changes must preserve AWS, Azure, and GCP behavior. Keep the other registered providers importable and avoid accidental support removal. Missing optional/private AWS modules must remain an explicit capability condition rather than silently advertised coverage.
- Preserve CLI flags, exit codes, service selection, report paths/keys, rule identifiers, exception identifiers, stable resource IDs, and programmatic entry points unless a separately documented migration changes them.
- Add schema fields compatibly. Version intentional schema or rule-behavior changes, document old-report handling, and provide explicit migration/rollback behavior. Preserve old reports as immutable fixtures.
- Never turn access denied, unsupported region/service, throttling, malformed data, or a failed collector into a passing security result. Preserve the distinction between empty inventory and incomplete assessment.
- Target Python 3.11 as the minimum modernization runtime. Declare additional supported versions only after their provider and report gates pass; a classifier or Docker base image is not proof of support. See the roadmap for the staged matrix.
- Prefer standard, explicit async lifecycle management and bounded work. Do not introduce event-loop monkeypatches, shared credential-insensitive client caches, implicit global state, or unbounded retry/task creation.

## Development practice

- Read relevant code, tests, and the baseline before changing a subsystem. Use small, reviewable changes tied to a roadmap item and a concrete behavior contract.
- Keep collection, normalization, rule semantics, dependency upgrades, and frontend changes in separate increments where practical. Do not combine a large formatting sweep with behavior changes.
- Use an isolated environment; never modify global packages to accommodate the repository. Preserve the existing style and 127-character line convention for touched Python code. Add focused typing where it clarifies an interface; do not require a repository-wide typing rewrite.
- Select maintained dependency versions using current upstream documentation, compatibility checks, and advisory review. Do not blindly unpin Azure/GCP packages, replace the flat requirements with untested extras, or upgrade every SDK at once.
- Do not hand-edit bundled minified libraries or overwrite `includes.zip` without a reproducible asset manifest/build process, license review, and report regression evidence.
- Preserve unrelated workspace changes. Never include credentials, generated assessments, local virtual environments, temporary test outputs, or package caches in commits.

## Testing requirements

- For documentation-only work, validate links, evidence, Markdown, and the diff; do not add implementation-shaped tests. Record any baseline checks actually run and their limitations.
- Before implementation, establish the Phase 1 offline harness. Until then, use only an audited allowlist with an explicit network/credential guard, such as the procedure in [OFFLINE_VALIDATION.md](docs/modernization/OFFLINE_VALIDATION.md). Do not assume bare `pytest` is safe.
- Test behavior changes with meaningful synthetic cases at the changed boundary. AWS adapters should use botocore `Stubber` or strict mocks; Azure SDK operations and Graph HTTP transports must be mocked; GCP ADC, discovery, HTTP, and gRPC transports must be mocked. Do not stub away the normalization/rule logic under test.
- Every changed security rule needs vulnerable, secure, absent/unsupported, and collection-error cases as applicable, with expected resource IDs and finding severity/counts. Missing fixtures must fail a declared coverage gate rather than silently count as coverage.
- Async tests must execute and await their bodies. Use an async-aware test runner or `IsolatedAsyncioTestCase`; test repeated invocation, cancellation, empty inputs, concurrency bounds, and cleanup where lifecycle code changes.
- Shared runtime, schema, dependencies, rule engine, or report changes require AWS, Azure, and GCP offline contract tests. Provider-only changes still require shared smoke tests and unaffected-provider imports. Add packaging and installed-wheel checks for package changes.
- Report changes require JSON/SQLite round trips, sanitized deterministic fixtures, exceptions, escaping of hostile strings, offline browser smoke tests, and all three provider templates. Browser tests must deny external requests, including CDN resources.
- Run the smallest relevant checks first, then the required cross-provider gates. Record exact commands, interpreter and resolved dependency versions, failures, skips, and known warnings. A missing environment is a limitation, not a passing result.
- Do not weaken assertions, blanket-ignore warnings, silently regenerate golden files, broaden xfails, or reduce supported-provider coverage to obtain green CI. Any temporary exception needs a narrow scope, reason, owner, tracking item, and expiry condition.

## Incremental change management

- Each implementation PR must name its roadmap item, describe the before/after behavior, list affected providers and permissions, include tests and evidence, and state compatibility and rollback implications.
- Follow dependency order and phase acceptance criteria in [ROADMAP.md](docs/modernization/ROADMAP.md). A phase is complete only when its observable exit criteria pass; partial coverage must be reported explicitly.
- Prefer reversible adapters and additive schemas over parallel rewrites. Use opt-in capability flags for new services or changed semantics until their offline gates pass. Delete legacy paths only after their replacements and old-report compatibility are verified.
- Keep the baseline revision and historical results intact. Add dated progress notes/evidence rather than rewriting the historical baseline as though the old behavior never existed.
- Preserve the two-reviewer policy in `CONTRIBUTING.md`; include Azure/GCP expertise when shared/provider compatibility is affected. Do not push, publish, land, or perform live assessments merely because the roadmap proposes them.
