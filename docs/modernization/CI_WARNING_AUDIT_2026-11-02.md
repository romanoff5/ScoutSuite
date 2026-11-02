# Offline CI warning audit — 2026-11-02

## Scope and evidence

Baseline: [master Offline CI #41376017062](https://github.com/romanoff5/ScoutSuite/actions/runs/41376017062),
Ubuntu Python 3.11.18 and Windows Python 3.11.9. Both reported **441 passed,
34 subtests passed, 206 warnings**. This document is based on actual pytest
warning sections and the structured `warnings` map in the CI results.
No live AWS, Azure, GCP or customer environment was accessed.

| Origin | Count each OS | Root cause | Ownership |
| --- | ---: | --- | --- |
| `ScoutSuite/providers/utils.py` | 50 | Invalid Python string escape sequences (`\\-`, `\\.`) inside secret detector regex literals | Fork code |
| `google-cloud-kms==1.3.0` | 127 | Old generated protobuf descriptors and invalid docstring escapes; includes one `UserWarning` from legacy client | Legacy GCP dependency |
| `google-cloud-monitoring==1.1.0` | 17 | Invalid escapes in old generated protobuf/gapic SDK | Legacy GCP dependency |
| `pkg_resources` | 10 | `declare_namespace` deprecations induced by old Google namespace packages | Legacy packaging dependency |
| `azure-mgmt-sql==1.0.0` | 2 | Invalid docstring escape in generated SDK | Legacy Azure dependency |
| **Total** | **206** |  | |

Note: the GCP/SDK count refers to warning **instances observed in this exact
run**; it does not imply 127 distinct root causes. The exact structured
warning paths and ceilings are listed in `tools/ci.py` as
`LEGACY_VENDOR_WARNING_BUDGET` for reproducibility.

## Fixes in this slice

- Changed Python *source string literals* for all 87 secret-detector
  `re.compile` expressions in `ScoutSuite/providers/utils.py` to raw
  strings. This corrects the 50 Python invalid-escape warnings without
  removing detector regex escapes, changing the dictionary of recognized
  token types or masking any genuine match.
- Added a warning-as-error **compile-time** regression test for that module
  and synthetic positive/negative token matching tests. No secret values
  are used in fixtures or emitted into logs.
- Added `verify_warning_debt()` to CI: an explicit, per-path,
  per-category **maximum** for the 156 known legacy vendor warnings.
  Every first-party or unrecognized warning fails CI. Vendor warnings
  remain fully visible in pytest output and warning manifests; there is
  **no blanket warning filter** or warning count reduction by test skipping.
- This is an interim, version-pinned technical-debt budget, not a claim
  that all deprecations have been fixed. The budget should only be reduced
  after real dependency migration and preservation tests.

Expected new baseline: **0 fork warnings + up to 156 legacy dependency warnings**.
Actual Windows/Ubuntu results are recorded in `MODERNIZATION_PROGRESS.md`
after CI completion and promotion.

## Why the remaining 156 are not silently removed

The combined requirements explicitly pin `google-cloud-kms==1.3.0`,
`google-cloud-monitoring==1.1.0`, `azure-mgmt-sql==1.0.0`, and
`protobuf==3.20.3` via `constraints/combined-py311.txt`. They are part
of the legacy GCP/Azure preservation matrix, which must remain functional
until explicitly modernized. The fork's current active modernization
scope is AWS; upgrading these SDK major versions without updating
client call contracts is not a safe warning-only change.

The correct follow-up is an independent legacy SDK compatibility slice:
1. Inventory every GCP KMS/Monitoring and Azure SQL SDK import and
   operation used by the existing providers; build synthetic SDK-model/
   transport tests covering those operations without network credentials.
2. In an isolated branch, upgrade the affected packages and namespace
   dependencies with a reviewed lockfile, verify the new SDK method/model
   contracts, and preserve old provider report structures.
3. Re-run the complete Windows/Ubuntu offline suites, all AWS/Azure/GCP
   imports, report viewer/XSS/SQLite tests and packaged-wheel checks.
4. Remove the corresponding vendor-budget entries only after they no
   longer emit warnings; then validate a strict zero-warning gate.

Do not patch installed `site-packages`, add global `filterwarnings =
ignore`, exclude Azure/GCP tests, lower test coverage, or modify
`PYTHONWARNINGS` to create the appearance of a clean run.
