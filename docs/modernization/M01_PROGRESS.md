# M01 progress and validation

Date: 2026-10-31. Scope: enforced offline testing only. The [historical baseline](OFFLINE_VALIDATION.md) is unchanged. Production source, security rules, runtime requirements, packaging and CI workflows remain outside this increment.

**Status: M01 implementation and local acceptance checks complete on Windows and Linux.** PR review and hosted CI readiness are separate gates; M02 and later phases have not been started. See [test instructions](../../tests/README.md), [machine-readable results](evidence/M01_RESULTS.json), and [resolved environments](evidence/M01_ENVIRONMENTS.json).

## Increment 1 — isolation and honest legacy tests

- Root `conftest.py` installs credential/environment isolation, a Python audit hook, SDK credential/transport guards and process-creation guards before application test imports. External and arbitrary loopback connections are rejected; only the internal `socketpair()` implementation receives a narrowly scoped IPC exception.
- Rejected calls are recorded and fail the test even if application code catches their exception. Negative tests explicitly acknowledge exactly one expected denial. Raw Python socket and native process entry points are covered; native gRPC channel factories are blocked separately.
- Default pytest collection rejects credential/cloudwatch/profiles tests and skip/xfail markers; runtime skips fail. Runtime, unawaited-coroutine, thread/unraisable and returned-test-value warnings fail. Third-party plugin autoload is disabled; requested plugins must be loaded explicitly.
- All six CLI tests are synchronous because `run_from_cli()` is synchronous. They await mocked collectors through the real scanner lifecycle, and six negative mutation checks demonstrate that incorrect CLI results fail their assertions. The expected authentication failure code is the current `101`, not the obsolete `42`.
- Windows path comparisons use `Path`. A fixture loader supports native symlinks and Git text aliases with cycle/root traversal checks. The manifest declares the 19 historical paired AWS cases; each is an individual asserting test. Untested rule keys remain explicit rather than becoming skipped tests.
- Filesystem tests use temporary outputs and assert results. Previously unused IP-range cases now execute. One missing synthetic filter input was added; the old expected AWS public-prefix output received the two `network_border_group` fields already present in the bundled 2022 metadata. Existing rule expected-result files were not regenerated.
- The skipped secret-recognition test now uses exact constructed lengths and tests valid/invalid boundaries. Vacuous type/lookup/age assertions were replaced with actual assertions. Test-owned event loops and temporary ruleset files are closed/removed.

Validation on Windows, CPython 3.11.9:

```text
python -B -m pytest -q -p no:cacheprovider --tb=short --show-capture=no
111 passed, 50 warnings, 22 subtests passed
```

The environment was isolated outside the checkout and installed the unchanged full `requirements.txt` plus pytest 9.2.0, pytest-cov 7.1.0 and flake8 7.5.0. `pip check` and the repository's configured `flake8 .` pass. Full Linux and cross-provider characterization evidence follows in the next increment.

## Newly characterized defect deferred to M09

`ScoutSuite.core.fs.save_blob_as_json` opens/truncates a file but sends JSON to the logger instead of the file. Its old test had no assertions. M01 asserts the current empty-file and logged-payload behavior explicitly, without fixing production logic or presenting it as intended functionality. Changing this helper is separate work; no xfail hides the behavior.

## Current limitations

- The 50 remaining warnings are existing invalid string-escape deprecations in application code. They are visible and unsuppressed; changing production code is outside M01. They are distinct from the removed unawaited-test/unittest warnings.
- Fixture presence is not runtime verification. The generated manifest report records validity, actual verified cases, not-run cases and the explicit untested backlog.
- This is a guard for trusted Python test code, not an OS sandbox against malicious extensions or a privileged process deliberately undoing monkeypatches. No live assessment is authorized.
- Production dependency metadata and retired hosted CI remain M02 work. No package/SDK migration is included merely to make tests pass.

## Increment 2 — cross-provider characterization and final validation

Twelve safe/unsafe/report-format cases exercise actual AWS EC2 EBS regional-settings, Azure Storage account and GCP Cloud Storage collectors and resource parsers. AWS uses strict botocore `Stubber` request/response contracts; Azure SDK operations and GCP storage client methods use bounded mocks. Authentication is isolated/mocked. The resource normalization, rule evaluation, exception application, JavaScript payloads, HTML assembly and SQLite serialization are real code. Expected normalized resources, finding IDs, counts and levels are committed synthetic fixtures, not snapshots generated from customer reports.

The resulting inventory is **31 verified cases across 21 default rule keys**: AWS 19 rules/23 cases (19 historical plus four characterization cases), Azure one rule/four cases and GCP one rule/four cases. Untested keys remain AWS 128, Azure 80, GCP 118. This is initial characterization, not a claim that all provider controls or collection-error semantics are covered.

Structural contracts cover all 347 AWS/Azure/GCP default rule keys and their definitions, 144 provider template files, metadata service keys and service declarations. AWS has 27 core plus seven optional declarations; Azure has 12 core plus three optional declarations; GCP has 12 core declarations. This corrects the baseline's interpretation of Azure's 15 attempted declarations: three are private optional imports absent from the checkout, not verified public services.

| Run | Passed | Failed | Skipped / xfailed | Warnings | Passed unittest subtests |
| --- | --- | --- | --- | --- | --- |
| Historical Windows subset (3.11.9) | 46 | 2 | 1 / 0 | 63 | Not recorded |
| Final Windows full suite (3.11.9) | 132 | 0 | 0 / 0 | 150 | 22 |
| Final Ubuntu 24.04 / WSL2 full suite (3.11.18) | 132 | 0 | 0 / 0 | 161 | 22 |

Final full-suite runs use `python -B -m pytest -q -p no:cacheprovider --tb=short --show-capture=no`. The earlier 130-test coverage runs use the coverage invocation in `tests/README.md`; the last two tests specifically verify runtime skip/xfail conversion through the real pytest report hooks. `pip check`, repository-configured `flake8 .`, and `git diff --check` pass. Both platforms verify all 31 declared cases; no missing or invalid fixture is counted as coverage. Linux exercises native symlinks as well as the Git text aliases used by the Windows checkout. Test output directories are temporary; evidence contains counts/package versions rather than generated assessments.

The historical pass count is not a correctness denominator. Six old methods never executed their coroutine bodies, several assertions were vacuous, three unsafe/fixed-path tests were outside the historical selection, and the old rule loop silently omitted most rules. All applicable tests now execute under the guard; the six deliberately wrong CLI outcomes produce six assertion failures inside the negative self-checks.

Warnings are retained rather than suppressed. Windows records 50 application regex/string escape deprecations plus 100 from the pinned GCP KMS generated protobuf module. Linux adds one KMS-client `pkg_resources` warning and ten legacy namespace declaration warnings. The 12 unawaited/unittest return-value warnings and deprecated unittest assertion warning from the old subset are gone. Coverage source analysis can also echo existing escape deprecations outside pytest's warning summary. These are deferred M03/M07 dependencies/source work, not exceptions allowing unawaited tests to pass.

The root historical `.coveragerc` reports only 108 modules in this run. A test-only coverage configuration includes all **504** application modules and branch accounting. Windows measures **4,322/13,929 executable lines (31.03%)** and **566/3,398 branches (16.66%)** in application code. Test code is measured separately. Those deliberately modest figures expose remaining collector/rule coverage gaps; the higher percentage from the narrower legacy report must not be described as complete coverage. Exact Linux counts and the resolved environments are recorded in the JSON evidence.

## Acceptance criteria

| M01 criterion | Status / evidence |
| --- | --- |
| Enforced default offline environment before application imports | Pass: root conftest, isolated home/config, SDK/audit/native process guards; 33 negative/boundary tests |
| Unmocked network, default credentials and subprocess escape fail | Pass on both OSes: HTTP/DNS/TCP/UDP/raw sockets, arbitrary loopback/listen, native gRPC, ADC/Azure/AWS/metadata and Python/native launch entry points |
| Blocked exceptions cannot become successful collection | Pass: violation-ledger self-check catches swallowed exceptions; collector/rule characterization also asserts no evaluation errors |
| Six CLI bodies and assertions execute | Pass: real synchronous entry point, awaited `AsyncMock` collection, exact current codes, six wrong-result self-checks |
| Windows paths and portable fixture aliases | Pass: path/header assertions, 19 historical rule cases, text/native aliases, cycle/traversal rejection |
| Tested/untested/missing/invalid fixture accounting | Pass: explicit catalog manifest, missing/invalid/duplicate/omitted-provider/catalog-drift checks and runtime verification report |
| AWS/Azure/GCP characterization, exceptions and stable IDs | Pass: actual collection/normalization/rules/report paths, JSON/SQLite formats, imports and structural catalogs |
| No broadened skip/xfail or hidden unawaited tests | Pass: collection rejects these markers; runtime skips and relevant warnings fail |
| Scanner behavior and production boundaries preserved | Pass: no diff under `ScoutSuite/`, runtime requirements, `setup.py`, Docker or `.github`; no cloud credentials/accounts/customer data used |
| Reproducible setup and reviewable commits | Pass: private environment instructions, test tooling pins, full resolved snapshots and incremental commits; no generated assessments included |

## Remaining risks and blockers beyond M01

- GCP imports depend on the existing CLI bootstrap's `collections.Callable` workaround. The tests call the real bootstrap; they do not add a new compatibility monkeypatch or substitute fake provider modules. Standalone import/runtime cleanup remains M03/M07.
- Dependency resolution passes `pip check` on both environments, but the graph still contains old SDK pins and generated-code deprecations. No advisory/reachability audit or runtime dependency modernization was performed. Test-only snapshots are historical reproduction inputs, not release locks.
- Existing hosted workflows use retired runners/cache actions and invalid development dependency syntax. They cannot yet provide a trustworthy required GitHub check. Fixing them is M02 and is intentionally not included. `pytest_cov` is explicitly allowlisted so this harness does not introduce a new incompatibility with the workflow's `--cov` arguments.
- Only three service paths have end-to-end characterization. Comprehensive auth modes, pagination/denied/partial response behavior, browser interaction/remote assets, installed distributions, scale, alpha-provider runtime behavior and live-cloud validation are not certified by these results. Collector completeness/error reporting remains M04.
- The save-helper empty-file defect is intentionally preserved and tracked above for M09. No assertion or xfail conceals it.
- The guard assumes trusted test code. It cannot prove isolation against malicious native extensions deliberately bypassing Python guards. No live-test bypass is provided.
- Two human reviewers are still required by `CONTRIBUTING.md`; this work does not authorize merging. An unrelated local `ScoutSuite_AWS_Codex_Tasks.md` file appeared during execution and is preserved outside the commits/PR.

No M02 or later implementation is included. The historical baseline files retain their contents/results; two trailing blank lines were removed solely so the complete PR passes whitespace validation.

## Rollback

Revert the final characterization/evidence commit and `222de9ec` to undo M01 implementation while retaining baseline documentation (`659b8394`). No scanner, report-schema, cloud-permission or assessment-data migration is needed. Reverting the guard restores the old unsafe test defaults: use only the historical guarded allowlist from `OFFLINE_VALIDATION.md` until isolation is reinstated. Do not run bare legacy tests or a live scanner as rollback validation. No merge is performed by this task.
