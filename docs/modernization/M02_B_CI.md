# M02-B — reliable GitHub Actions and offline CI

Date: 2026-10-31. Parent: M02-A `07aa46fc`; stacked PR #3 targets PR #2.
Scope is CI, test tooling and evidence. No scanner, provider, security-rule or
Azure/GCP SDK change is included. M02A-D01 (Docker execution) remains separate.

## Workflow contract

One `Offline CI` workflow replaces both obsolete workflows. The frontend dummy
job did no build and was removed. No frontend build is claimed; bundled assets
are checked as package inputs, with reproducible frontend work still M09.

The two required lanes use `ubuntu-24.04` / CPython 3.11.18 and `windows-2022` /
CPython 3.11.9, x64. These are the interpreter versions verified in M01/M02-A;
additional Python versions are not advertised by CI. Hosted OS image revisions
and bundled compiler versions remain moving inputs recorded in setup logs.
The matrix uses `fail-fast: false`, a 35-minute per-job timeout and cancellation
of superseded runs for the same PR/ref. Push and PR events both run intentionally:
feature pushes validate before a PR exists, and PR runs validate its merged tree.
Their event refs differ, so they may run concurrently.

Actions are pinned to reviewed full commit SHAs; see
[the scoped review record](../../.github/ACTION_PINS.md). Cache keys contain OS,
architecture, exact Python, all requirement/constraint inputs, pyproject metadata
and the CI driver. Only dependency downloads/compiled dependency wheels are
cached, never virtual environments or assessments. There are no broad restore
prefixes. Tool versions are pinned in `constraints/ci-py311.txt` and
`constraints/build-py311.txt`; existing combined/AWS constraints remain intact.
pip 24.0 retains the M01 installer version; it is not a new pip support claim.

## Credentials, networking and phases

The workflow uses only `contents: read`; all other token permissions, including
OIDC, are disabled. It references no cloud secrets/environments or cloud-login
actions. Checkout does not persist its GitHub credential. Child environments
clear AWS/Azure/GCP/OCI and GitHub/runtime token variables and use a private home.
No ambient credential store is inspected. Cloud SDK/auth discovery remains
guarded by M01 rather than treating local-report flags as isolation.

1. **Online acquisition only:** create private build/core/AWS environments,
   acquire pinned tool/runtime inputs and dependency wheels, verify AWS lock
   hashes and actionlint 1.7.12 release SHA256. No scanner, cloud CLI or resource
   API is invoked. Cache misses must work exactly like hits.
2. **Enforce OS isolation:** Linux offline subprocesses run in a fresh network
   namespace through `sudo unshare`, then drop back to the runner user. Windows
   temporarily enables firewall profiles and blocks outbound traffic for the
   base interpreter and all six environment interpreters. Setup fails if the
   rules/profiles cannot be enforced; no permissive fallback exists. Cleanup
   removes only the job's rules and restores prior profile settings.
3. **Offline build/install:** actionlint validates actual workflow syntax and
   expressions. A tracked `git archive` is built outside the checkout. Build
   isolation is disabled with pinned tools preinstalled; installation uses
   `--no-index --find-links` only. Independent wheel and sdist environments and
   a source-test environment install from the acquired wheelhouse.
4. **Independent enforced gates:** `pip check` in all six environments; configured
   flake8; the complete default pytest suite; four guarded dependency/artifact
   smoke profiles. A lint/dependency/test failure does not prevent other already
   provisioned gates from running. Every failure remains a failed job; there is
   no `continue-on-error`, broad xfail/skip or warning suppression.
5. **Evidence:** logs include each exact command and complete resolved package
   versions. An always-run job summary marks each gate PASSED/FAILED/NOT RUN and
   includes artifact SHA256, warning sources, fixture verification and untested
   counts. No reports, assessments, coverage or customer artifacts are uploaded.

Installed artifact hashes are compared to the archived Git source used in the
build, rather than a Windows checkout's CRLF representation. Raw byte equality
is retained. The M01 guard loaded for that smoke also comes from the same archived
revision. Source tests still run on the actual checkout, including native Linux
symlinks and Windows text aliases.

This isolates trusted tests, not arbitrary malicious code with runner admin
access. The orchestration process only performs fixed setup/file/gate operations;
SDK/test execution uses the M01 guard. The Windows firewall covers the Python
processes, not every runner process; GitHub's Node runner/cache communication
continues. Linux gates have no external network interfaces. No customer data is
available to either lane.

## Honest execution and baseline debt

`tools/ci.py` verifies actual JUnit results in addition to pytest's exit code.
It requires all six formerly asynchronous CLI methods, M01 guard self-tests,
wrong-CLI-result self-checks and cross-provider characterization to be present.
Skipped/failed/error cases or missing/invalid/unverified declared fixtures fail
the gate. Twelve new tests exercise these rejection paths and synthetic token
scrubbing; they do not replace or deselect existing tests.

Historical baseline remains **46 passed, 2 failed, 1 skipped, 63 warnings**, with
six false async passes. M02-A had **134 passed + 22 subtests**, 150 Windows /
161 Linux warnings. Local M02-B Windows source suite has **146 passed + 22
subtests, 150 warnings**, no failures/skips/xfails. Hosted acceptance evidence,
exact final revision and log links are maintained in
[PR #3](https://github.com/romanoff5/ScoutSuite/pull/3) and its per-job summaries.
Check the PR head's completed checks rather than interpreting this local result
or an earlier branch run as final hosted acceptance.

The initial Ubuntu PR job at `6ac9d1da` passed all gates with 146 tests, 22
subtests and 192 warnings. Its [logs](https://github.com/romanoff5/ScoutSuite/actions/runs/41189112975/job/124502027830)
exposed 31 new `record_property`/xunit2 compatibility warnings. The driver now
selects supported `junit_family=xunit1`, which preserves those fixture properties;
no warning filter or assertion was removed. Final warning counts and outcomes
are recorded in the current PR checks. JUnit lists 146 cases; pytest separately
reports the 22 passing subtests, so these are not conflated in the evidence.

The retained warnings are 50 application string/regex escape deprecations and
100 old GCP protobuf warnings; Linux additionally reports 11 `pkg_resources`
warnings. They remain visible. Rule coverage still leaves 128 AWS / 80 Azure /
118 GCP rule keys untested; 31 declared cases must all verify. `flake8` enforces
the existing limited syntax/undefined-name configuration, not a repository-wide
style rewrite. No advisory audit, full provider coverage, browser certification,
Docker verification or Python 3.12+ support is inferred from a green job.

## Reproduction and rollback

Use a fresh external root and a private CPython 3.11 environment; do not point
the driver at an existing environment or directory containing reports:

```sh
export SCOUT_CI_ROOT=/outside/scoutsuite-ci
python -B tools/ci.py acquire
python -B tools/ci.py workflows
python -B tools/ci.py build
python -B tools/ci.py dependencies
python -B tools/ci.py lint
python -B tools/ci.py tests
python -B tools/ci.py packaging
python -B tools/ci.py summary
```

On PowerShell use `$env:SCOUT_CI_ROOT = Join-Path $env:TEMP 'scoutsuite-ci-new'`
and the same commands. Commit intended inputs before `build`: staging uses Git
HEAD, not uncommitted/untracked files. Local default execution uses M01 guards;
it does not alter the developer's firewall or request sudo. CI additionally sets
`SCOUT_CI_ENFORCE_OS_ISOLATION=1`. Do not set that flag locally without a separately
prepared disposable OS; the firewall helper is restricted to hosted CI.

The test gate runs `python -B -m pytest -q -p no:cacheprovider --tb=short
--show-capture=no -o junit_family=xunit1 --junitxml=<external-output>
--offline-manifest-report=<external-output>`. Do not omit the default guard,
change test selections, add broad skips or filter the retained warnings.

Rollback by reverting only M02-B commits in reverse order, retaining M01/M02-A.
No scanner, dependency SDK, schema, permission or assessment migration is needed.
Old workflows are retired and cannot count as successful validation after a
revert; keep using the documented guarded local suite. Cache keys can be bumped
to discard dependency caches without deleting data. Two human reviewers remain
required; no branch protection settings or merges were performed.
