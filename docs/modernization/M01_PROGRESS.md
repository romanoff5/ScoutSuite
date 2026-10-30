# M01 progress and validation

Date: 2026-10-31. Scope: enforced offline testing only. The [historical baseline](OFFLINE_VALIDATION.md) is unchanged. Production source, security rules, runtime requirements, packaging and CI workflows remain outside this increment.

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
