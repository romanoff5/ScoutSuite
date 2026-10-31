# M02-A — packaging and reproducible AWS/core dependencies

Date: 2026-10-31. Parent: M01 commit `14344de3` / PR #1. Scope: packaging and dependency inputs, not collector/rule or CI modernization.

## Behavior and compatibility

`pyproject.toml` is now the canonical PEP 517/621 metadata. `setup.py` remains a compatibility shim. The distribution is still named `ScoutSuite`, its version still comes from `ScoutSuite.__version__`, and `scout = ScoutSuite.__main__:run_from_cli` is unchanged. Minimum installation Python is 3.11; only CPython 3.11 on Windows/Linux is verified in this increment. This does not certify Python 3.12-3.15 scanner runtime behavior.

The default combined installation retains all **49 existing runtime requirements**, including unchanged Azure/GCP SDK specifications. No optional-extra conversion, provider removal, security-rule change or SDK migration is included. Namespace discovery includes DigitalOcean's modules/data, and explicit package-data patterns preserve JSON rules, report templates, JS/CSS, icons, archives and empty-directory markers.

Installed-sdist verification exposed missing empty Azure/GCP report directories when `.keep` files were omitted. Packaging now preserves the original `.keep`/`.gitkeep` assets; no report/provider source code changed. All **1,379** source code/data assets are hash-compared with the installed artifact. Wheel metadata is checked against the unchanged runtime requirement set.

`pytest>=5.*` in development requirements is corrected to valid `pytest>=5`. Actual M01 test-tool pins remain in `tests/requirements-offline.txt`.

## Dependency inputs and their limits

- `requirements-core.txt`: shared dependencies, including `policyuniverse`, which the shared condition engine imports.
- `requirements-aws.txt`: shared core plus boto3/botocore.
- `constraints/aws-core-py311.txt`: complete 38-package union of the verified Windows/Linux AWS/core dependency closures, with OS markers. These select the already tested M01 versions; this is not a bulk dependency upgrade.
- `constraints/aws-core-py311.lock`: exact versions and SHA256 hashes of PyPI release files. Install with `--require-hashes -r`, not `-c`. Hashes were retrieved from public PyPI version metadata during acquisition, never during a test.
- `constraints/build-py311.txt`: exact build frontend/backend/tool versions. PEP 517 backend requirements independently pin setuptools 80.9.0 and wheel 0.45.1.
- `constraints/combined-py311.txt`: compatibility snapshot retaining M01 provider SDK versions for testing the default combined distribution. It is not an Azure/GCP modernization proposal and does not provide the hash-lock guarantee of the AWS/core lock.

Minimal core/AWS environments validate **dependency sets**, not a new minimal ScoutSuite distribution. They intentionally contain no installed ScoutSuite metadata and no Azure/GCP SDKs; the core profile also contains no boto3/botocore. The existing distribution still requires all providers. Installing that distribution with `--no-deps` into a minimal profile would violate its metadata and fail `pip check`; that is not a supported install mode. This preserves the default installation contract rather than silently changing provider availability.

Version pins and hashes support repeatable dependency acquisition, not an assertion that old capped dependencies are vulnerability-free. Existing dateutil/coloredlogs/GCP/Azure caps and known warnings remain. PyPI source archives can require compilation: acquire build tools separately, use the pinned backend and prepare an OS-specific wheelhouse for disconnected installation. The AWS/core hash lock authenticates published runtime release files, not arbitrary build tools downloaded by an isolated sdist backend.

The package uses the supported [setuptools pyproject metadata interface](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html). Pinning, hash checking and wheelhouse guarantees differ; see [pip repeatable installs](https://pip.pypa.io/en/stable/topics/repeatable-installs/).

## Reproduce

Use private environments outside the checkout. The following uses POSIX notation; on Windows select `Scripts/python.exe`, create environments with `py -3.11 -m venv`, and set environment variables using PowerShell. Run setup/acquisition separately from guarded verification. Do not authenticate cloud CLIs or supply credentials.

```sh
python3.11 -m venv /outside/build-env
/outside/build-env/bin/python -m pip --isolated install -r constraints/build-py311.txt
SOURCE_DATE_EPOCH=1793404800 PIP_NO_INDEX=1 /outside/build-env/bin/python -m build \
  --no-isolation --outdir /outside/dist /path/to/checkout
```

For strongest separation, copy the explicitly named build inputs (`ScoutSuite`, metadata, requirements, constraints, tests/support and manifest-listed tools) to a temporary staging tree and build there. The recorded builds used a staging tree outside the checkout, not a copy of unrelated root files. Generated distributions are not committed. The same source/runtime assets and fixed epoch produced byte-identical wheels in two builds; sdist hashes differ when included Docker/tool inputs change. No universal byte-identical sdist guarantee is claimed.

Minimal dependency checks:

```sh
python3.11 -m venv /outside/aws-env
/outside/aws-env/bin/python -m pip --isolated install setuptools==80.9.0 wheel==0.45.1
/outside/aws-env/bin/python -m pip --isolated install --no-build-isolation \
  --require-hashes -r constraints/aws-core-py311.lock
/outside/aws-env/bin/python -m pip check
cd /outside
/outside/aws-env/bin/python -I -B /path/to/checkout/tools/verify_distribution.py \
  --source /path/to/checkout --profile aws --output /outside/aws-smoke.json
```

For a core-only dependency environment, install `-r requirements-core.txt -c constraints/aws-core-py311.txt` after the same build-tool bootstrap, then use `--profile core`. Both minimal profiles assert that unrelated provider SDKs and the combined ScoutSuite distribution are absent. No tests are skipped to obtain that isolation.

Combined artifact checks:

```sh
python3.11 -m venv /outside/artifact-env
/outside/artifact-env/bin/python -m pip --isolated install setuptools==80.9.0 wheel==0.45.1
/outside/artifact-env/bin/python -m pip --isolated install --no-build-isolation \
  -c /path/to/checkout/constraints/combined-py311.txt /outside/dist/scoutsuite-5.14.0.tar.gz
/outside/artifact-env/bin/python -m pip check
cd /outside
/outside/artifact-env/bin/python -I -B /path/to/checkout/tools/verify_distribution.py \
  --source /path/to/checkout --profile combined --output /outside/artifact-smoke.json
```

Repeat with the wheel in a separate clean environment. Dependency installation is acquisition; the smoke tool subsequently installs M01 guards before application imports. `-I` prevents source/PYTHONPATH shadowing, and the tool asserts the installed package is outside the checkout. It checks all source/data hashes, metadata, entry-point loading and in-process `--help`, strict AWS Stubber/unstubbed-call rejection, and real installed AWS/Azure/GCP rules/report round trips. It never launches a scanner, browser or cloud login. Launcher registration is checked through installed console-script metadata; native launcher subprocess execution is deliberately not used to bypass M01.

Default pytest still requires all three provider SDKs. The guard's new `required_providers` argument is used only for explicit minimal dependency probes; default collection and its negative tests remain unchanged. For the full suite, follow `tests/README.md` and use the unchanged combined dependency environment.

## Docker source provenance

Canonical builds now use the repository root as context:

```sh
./docker/build.sh base
./docker/build.sh aws
```

The base recipe copies this fork's named source/metadata inputs and installs the **local path**, with the combined compatibility constraints. It never requests `pip install scoutsuite` from PyPI. The legacy installer helper requires an explicit local `SCOUTSUITE_SOURCE` and fails if it is absent. The build context is allowlisted to exclude assessment outputs, credential files, unrelated root files and private modules.

AWS/Azure/GCP wrapper images now default to the freshly built local fork base instead of an upstream NCC image. Their provider/SDK/CLI installer scripts were not modernized; the Azure/GCP wrapper changes only route the base/context to this fork. `combined` aliases the base combined image. Local image names are `scoutsuite-fork-base:local` and `scoutsuite-fork-{aws,azure,gcp}:local`; old config-file image tag customization is no longer used by the helper. Direct `docker build -f docker/Dockerfile-base . --build-arg VCS_REF=<revision>` is also supported. Use that explicit Dockerfile on Windows; the historical `docker/Dockerfile` Git symlink may be materialized as text. Targeted `.gitattributes` rules keep Docker shell scripts LF on Windows checkouts.

**Docker build/run verification is blocked.** The engine was unavailable, and automatic approval review rejected the combined public-registry authentication / Docker Desktop start command with only “blocked by policy” as its reason. That action was not retried through another route. Shell syntax and source-install routing were reviewed; an image build, dependency/native-library check inside the image and image CLI smoke are not claimed. The Python base tag and Debian packages are also not digest/version locked; this increment does not claim bit-reproducible container images. An enabled/authorized Docker engine is needed to close this acceptance item.

## Evidence, remaining gates and rollback

See `evidence/M02_A_RESULTS.json` for hashes and actual guarded smoke results. Full regressions: Windows 3.11.9 **134 passed, 150 warnings, 22 subtests**; Ubuntu/WSL2 3.11.18 **134 passed, 161 warnings, 22 subtests**, no skips/xfails. These include the original M01 Windows/fixture/CLI/isolation cases plus dependency-contract tests. Existing warnings are retained, not filtered. `pip check` passes in clean core/AWS profiles and installed combined-artifact environments. Repository lint and whitespace checks pass.

Exact regression command, run from the checkout with each platform's private M01 interpreter:

```sh
python -B -m pytest -q -p no:cacheprovider --tb=short --show-capture=no
python -m flake8 .
git diff --check
bash -n docker/build.sh docker/bin/container-install-scoutsuite.sh
```

The 150 Windows warnings comprise 50 existing application escape-sequence warnings and 100 GCP protobuf deprecations; Linux also reports 11 `pkg_resources` warnings. Rule coverage remains 19 AWS rules / 23 verified cases, one Azure rule / four cases, and one GCP rule / four cases; 128/80/118 rules respectively remain untested. Neither package inclusion nor a default ruleset loading successfully constitutes full rule coverage.

| M02-A acceptance item | Status and evidence |
| --- | --- |
| Valid metadata and unchanged CLI registration | Pass: parser contracts, installed metadata and in-process `--help` |
| Reproducible AWS/core dependency inputs | Pass on Windows/Linux 3.11: exact closure, hash-locked AWS installs, `pip check` |
| Clean artifact installation outside checkout | Pass: Windows wheel and Linux sdist-to-wheel build/install, all 1,379 asset hashes and 49 requirements |
| Other-provider preservation | Pass within offline coverage: unchanged SDK specs/source/rules, combined suite and installed AWS/Azure/GCP reports |
| Docker installs this fork | Source routing corrected; **execution blocked**, not a passing image smoke |
| Regression and isolation gates | Pass: 134 tests plus 22 subtests on each OS; no skips/xfails |

**M02A-D01** tracks the remaining Docker gate. Owner: packaging maintainer. Close only after a permitted working engine builds the fork image, runs `pip check`, verifies installed revision/assets and executes the guarded smoke with external networking denied. No exception permits publishing a verified-image claim before that evidence. Python versions beyond 3.11 and independent minimal provider application distributions remain later scoped work.

No files under `ScoutSuite/`, `requirements.txt` or `.github/` changed. Other providers' SDK specs, checks and source behavior are unchanged. This is not an AWS API/rule upgrade, browser certification, advisory/reachability audit, Python 3.12+ support certification, or CI modernization. The package default remains combined. Minimal dependency checks must not be advertised as an AWS-only application wheel. Hosted CI still has the previously documented blockers; M02-B has not been started.

For rollback, revert this branch's two implementation commits in reverse order. There is no report-schema or cloud-data migration. Restore prior package artifacts/environments if already deployed; reinstall the old combined dependencies in a fresh environment, not by downgrading a shared interpreter. Restore old local Docker tags explicitly if applicable; no images were built/published by this task. The original upstream-PyPI Docker fallback must not be used to verify rollback of the fork. M01 stays in place, and two human reviews remain required before merging.
