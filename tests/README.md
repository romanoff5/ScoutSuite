# Offline test instructions (M01)

Use Python **3.11**. The measured environments are Windows 3.11.9 and Ubuntu 24.04 under WSL2, Python 3.11.18. Production SDK requirements and CI remain unchanged. `dev-requirements.txt` still has invalid `pytest>=5.*` syntax, which is an M02 blocker; the separate test requirements below do not change it.

## Install in a private environment

Run from the repository root. Package acquisition is setup, separate from offline test execution. Do not authenticate a cloud CLI or supply credentials.

Windows PowerShell:

```powershell
$testEnv = Join-Path $env:TEMP ('scoutsuite-tests-' + [guid]::NewGuid().ToString('N'))
py -3.11 -m venv $testEnv
& "$testEnv\Scripts\python.exe" -m pip --isolated install -r tests/requirements-offline.txt
& "$testEnv\Scripts\python.exe" -m pip check
& "$testEnv\Scripts\python.exe" -B -m pytest -q -p no:cacheprovider
```

Linux:

```sh
test_env="$(mktemp -d -t scoutsuite-tests-XXXXXXXX)/venv"
python3.11 -m venv "$test_env"
"$test_env/bin/python" -m pip --isolated install -r tests/requirements-offline.txt
"$test_env/bin/python" -m pip check
"$test_env/bin/python" -B -m pytest -q -p no:cacheprovider
```

For repeated WSL sessions, put the private environment on a persistent Linux filesystem: `/tmp` can disappear when the distribution stops. The test guard creates a fresh isolated home and temporary-output root for each run. It requires no symlink privilege on Windows. Linux additionally exercises native fixture symlinks.

For historical reproduction, the resolved package versions are recorded in [M01_ENVIRONMENTS.json](../docs/modernization/evidence/M01_ENVIRONMENTS.json). Convert the chosen platform's `requirements` list into a constraints file, then add `-c <constraints-file>` to the setup install command. Use constraints, rather than installing every recorded package: the Windows environment also contains the `uv` setup helper. These are evidence snapshots, not a release lockfile or security recommendation. For fully disconnected setup, acquire wheels/build inputs separately and use `--no-index --find-links <wheelhouse>` during installation. No dependency download belongs inside a test.

## Manifest, coverage and lint

Add `--offline-manifest-report=<absolute-output-path.json>` to emit fixture validity and actual verification results. The parent directory must exist. The report includes each declared case's `valid/missing/invalid` fixture status, `verified/failed/not_run` execution status, warning counts by module, and explicit untested rule keys. A focused test selection correctly leaves unrelated cases `not_run`.

The default full suite runs every applicable test; no credential-based exclusions, skip markers or xfails are used to obtain success. The manifest gate runs even during focused selections. New rule keys, missing declared fixture files, invalid data, duplicate cases, provider omissions and catalog drift require review.

Plugin autoload is disabled. `pytest.ini` explicitly allowlists `pytest_cov`, preserving the existing CI command's `--cov` arguments. The following invocation also names the plugin explicitly:

```sh
python -B -m pytest -q -p no:cacheprovider -p pytest_cov --cov \
  --cov-config=tests/offline.coveragerc --cov-report=term \
  --cov-report=json:/absolute/output/coverage.json \
  --offline-manifest-report=/absolute/output/fixtures.json
python -m flake8 .
```

Use the private environment's Python above; on PowerShell put the coverage command on one line. Set `COVERAGE_FILE` to an external output path if the raw coverage database should also stay outside the checkout. The historical root `.coveragerc` limits its report to 108 top-level modules in this run and omits nested resources/tests. `tests/offline.coveragerc` measures all 504 application modules plus tests, including namespace directories, and records branches. Do not compare the two percentages as though their denominators were equal.

The suite prints existing application/SDK deprecations. It fails runtime, unawaited-coroutine, unraisable/thread and returned-test-value warnings. Do not add broad warning filters to hide SDK debt. See [progress and acceptance evidence](../docs/modernization/M01_PROGRESS.md) for observed counts and known defects.

## Isolation contract

Root `conftest.py` installs the guard before importing application test modules. Home/config paths point at a fresh temporary directory; ambient AWS/Azure/GCP/OCI and Kubernetes credential settings are cleared. Default credential discovery and AWS instance/container metadata helpers are rejected. AWS `Stubber` and explicit synthetic credentials remain usable, while an unstubbed endpoint request fails before transport. Azure credential constructors/token calls, Google ADC/file loaders and native gRPC channel factories are blocked.

Audit hooks reject external connections, DNS, datagrams, credential-store file access outside the isolated home, and process creation. Arbitrary loopback access and implicit server listening are also rejected. Only the implementation of `socket.socketpair()` gets a scoped local IPC exception for asyncio. Platform identification and urllib3's local IPv6 capability probe are warmed during setup; no cloud provider imports occur in that warmup.

Subprocesses, shells and native process launch functions are blocked; CLI smoke tests call the existing entry point in process. No live-test escape flag is provided. Credential/cloudwatch/profiles and skip/xfail markers fail collection; runtime skips fail the test. Any future live suite needs a separately authorized design under `AGENTS.md`.

Negative boundary tests use `offline.expect_violation(category)` to acknowledge exactly one expected rejection. An exception caught by application code remains in the guard's violation ledger and fails teardown/collection. Missing SDKs fail imports; entire providers are never replaced with permissive fake modules.

This is a default test boundary for trusted test code, not an OS sandbox against a hostile native extension or a privileged process deliberately undoing the guard. Run untrusted code in a separately isolated system. `--local`, `--no-browser`, an xfail or a selected marker is not isolation.

## Coverage boundaries

M02-B's [CI instructions and evidence](../docs/modernization/M02_B_CI.md) add
pinned wheelhouse acquisition, clean installed-artifact gates and OS network
isolation on hosted Windows/Ubuntu. Local default pytest continues to use M01;
the CI driver does not alter a developer's firewall.

- Nineteen historical AWS rule cases retain their original expected rule results. Text and native aliases resolve through the same bounded fixture loader.
- New safe/unsafe cases exercise real AWS EC2, Azure Storage and GCP Cloud Storage facade/resource logic, unchanged rules, stable IDs, exceptions and JSON/SQLite report round trips. Raw SDK responses are synthetic; authentication and SDK calls are stubbed or strictly mocked.
- Structural snapshots cover core/optional service declarations, metadata service keys, all AWS/Azure/GCP default rule keys and provider templates. Optional/private declarations are not advertised as implemented services.
- Initial characterization is not complete provider coverage. Many rule keys remain explicitly untested, and browser interaction, live SDK behavior, full authentication-mode coverage, scale and installed-package behavior remain later work.
- GCP provider tests use the actual CLI bootstrap, which already installs a `collections.Callable` workaround. Standalone provider imports can still fail without that bootstrap; M01 does not add a new production monkeypatch to mask the issue.
