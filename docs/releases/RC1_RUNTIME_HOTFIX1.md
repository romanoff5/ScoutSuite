# RC1 runtime hotfix build 1 (2026-11-02)

Task 14 / M10 corrective slice. The published RC1 assets remain immutable.
The local wheel uses standard build tag `1`, package version
`5.14.0+romanoff5.m10rc1`, a separate SHA256 and an implementation commit.
This is a locally built repair, not a new published GitHub release.
A checkout fast-forward alone does not update an installed wheel.

## Corrected behavior and compatibility

- All 13 Network Firewall, Macie and Bedrock rules execute their declared
  evidence policies. Multi-rule policies bind explicitly to the published
  filename and resource path. Existing rule IDs, resource paths, severities
  and permissions are preserved. Missing data, a negative heuristic and recent
  Macie activity do not establish compliance.
- SSM and Network Firewall encode internal operation/error codes before
  recording collection issues. Colons no longer cause a secondary exception
  that aborts collection/reporting. Bedrock retains its compatibility helper.
  The strict 64-character schema remains enforced; long codes retain a digest
  and raw SDK error messages are not copied into issue metadata.
- The installed-distribution gate executes evidence policies from the packaged
  default AWS/Azure/GCP rulesets in addition to CLI help.

No collection fields or templates change; no new API fields or customer content
are retrieved. Evaluation summaries use the existing v1 schema and retain
unknown resource paths. Existing JSON/SQLite reports remain readable and are
not rewritten. No rule returns verified compliance.

## Offline validation

Windows, CPython 3.11.9. Repository `conftest.py` installs network, credential,
subprocess and SDK guards before application test imports. No AWS scan,
credential lookup or customer-report read was performed.

The old `scoutsuite-m02b/pipeline/test` environment predates M11: full run
669 passed, 4 failed, 111 warnings (three outdated foreign-provider SDK
contracts and a Windows symlink privilege failure). This is not release
validation. Using the installed fork interpreter with its RC1 dependencies,
and appending the old test site-packages only to load pytest/pytest-cov,
the full guarded suite gave **672 passed, 1 failed, 34 subtests passed,
zero warnings**. The failure is
`test_zip_symlink_and_existing_symlink_destinations_are_rejected`:
Windows refuses OS symlink creation with `WinError 1314`. No assertion,
guard or test was weakened. The final focused selection additionally includes
two new malformed-page regressions: **159 passed, zero warnings**.

Commands from repository root (use the private interpreters):

```powershell
# Test dependencies are appended after the fork's own packages; none are installed.
& $forkPython -B -c 'import sys; sys.path.append(sys.argv.pop(1)); import pytest; raise SystemExit(pytest.main(sys.argv[1:]))' $testSite -q -p no:cacheprovider --tb=short tests/test_main.py tests/test_rc1_runtime_regressions.py tests/test_m04_completeness.py tests/test_m08_evidence_semantics.py tests/test_m10_ssm.py tests/test_m10_ssm_evidence_hardening.py tests/test_m10_networkfirewall.py tests/test_m10_macie.py tests/test_m10_bedrock.py tests/test_m07_deferred_provider_preservation.py tests/test_m11_sdk_compatibility.py tests/test_characterization.py tests/test_m09_versioned_reports.py tests/test_m09b_sqlite_hardening.py
git diff --check
```

The new regression module checks every published policy against empty
inventories, positive findings through the real default processing engine,
secure/unknown/inapplicable cases, denied APIs and malformed pages under an
active RunContext, bounded codes and absence of raw SDK messages.
Cross-provider gates cover imports/contracts, normalization, templates,
JSON/SQLite round trips and exceptions. No browser code was changed.

## Local installation and rollback

Build with the pinned isolated build interpreter:

```powershell
python -m build --wheel --no-isolation '--config-setting=--build-option=--build-number=1' --outdir <local-hotfix-directory>
```

The local user launcher `ridgepay-scout-fork-install-run-v2.ps1` pins the
repair SHA256 and source commit. `-SkipGitSync -InstallOnly` installs only into
`.venv-scout-fork` with `--no-index --no-deps --force-reinstall`. It verifies
every installed package file against the wheel, build number, all packaged
evidence policies and synthetic denied-API diagnostics with an active context.
The original provenance retains its immutable base-release fields and gains
an explicit `runtime_hotfix` record, also included in future scan contexts.
Subsequent runs verify and reuse the repair. Stable installation, Toolkit
selection, credentials and target account/region settings are untouched.

Rollback: stop the fork process, reinstall the original hash-verified wheel
into the fork venv using `--no-index --no-deps --force-reinstall`, restore the
pre-repair launcher backup and remove only `runtime_hotfix` from its provenance
JSON. Preserve all reports. The original RC1 still contains the documented
bugs; rollback is for recovery, not a passing assessment baseline.
Live cloud behavior and new-release publication remain unverified.

Installed validation passed: 1,560 packaged files matched source, 50 runtime
requirements matched, and guarded AWS/Azure/GCP CLI/rules/report checks passed.
Two launcher `-SkipGitSync -InstallOnly` invocations passed installation and
reuse, checking 55 AWS policies and denied-API diagnostics. Source commit:
`70cf29d5579864543b6363e7a271a84216bb6837`. Local repair wheel SHA256:
`bcf9ca2e419f6f745cdf9ee14c1f0186074f6d07c85ab8a8987c940f00970c0e`.
