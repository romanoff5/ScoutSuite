# P5-Hardening — mandatory three-state attack-path coverage

## Scope

This phase extends the reusable Phase-1 regression catalog from 33 to **53**
independently declared synthetic cases, without cloud credentials, Docker
containers or external network access. Existing Phase-2 production processing,
SQLite/HTTP, report rendering, Playwright and Phase-3 source-pinned CloudGoat /
CloudFoxable smoke regressions remain unchanged and mandatory.

## New coverage

The added fixtures include independent positive / explicit-negative / unknown
oracles for:

- IAM `lambda:UpdateFunctionConfiguration` + code + invocation via PassRole
- IAM EC2 occupied instance-profile mutation with both Add/Remove grants
- ECS RegisterTaskDefinition + bounded RunTask synthetic revision witness
- S3 Access Point cross-account resource policy with scoped explicit Deny
- IAM **user**, not just role, to privileged Lambda workload delegation

Existing detectors are also given missing `UNKNOWN` cases such as
uncollected boundaries, incomplete trust or collection. An unobserved API
result does **not** imply PASS. The S3 AP collector now marks incomplete or
denied access-point policy enumeration as `partial`, instead of treating it
as a verified empty policy. Normal reports still preserve real ARNs; only
synthetic identifiers appear in this catalog.

## Mandatory coverage gate

- `tests/data/p5_detector_coverage.json` pins one distinct positive,
  negative and UNKNOWN scenario for each of **14 production graph edge types**,
  plus a known positive witness for every **8 enabled P5 finding rules**.
- `tools/p5_coverage_matrix.py --check` uses only Python stdlib and
  parses the actual `attack_paths_p5d.py` **AST**, not a duplicated fixed
  detector list. It recognizes both literal emit kinds and the statically
  enumerated IAM service-create emitters.
- A new emitted graph kind, an unreviewed dynamic emitter, a new/disabled
  P5 rule, a missing case or missing/contradictory oracle state causes a hard
  failure. Tests mutate the manifest and source AST to verify failure.
- `tools/ci.py` runs `p5_coverage` as an independent mandatory offline
  gate on **Ubuntu/Windows × Python 3.11/3.14**, in the same isolation policy
  as existing tests. The `tests` gate also runs the mutation tests.
- Phase-2 SQLite/HTTP end-to-end integration processes all **53** cases,
  including the new IAM user rule and EC2 profile mutation. Browser E2E
  still samples one representative case; browser-per-detector expansion and
  exact golden action/provenance assertions are separate hardening tasks.

Run offline:

```bash
python tools/p5_coverage_matrix.py --check
python -m pytest -q tests/test_p5_phase1_synthetic_aws.py tests/test_p5_hardening_coverage.py
python tools/verify_p5_phase2_pipeline.py
```

The last command needs loopback plus installed browser dependencies; it is
automatically run by the Ubuntu `sqlite_http` CI gate.

## Accuracy boundaries

This is a fixture **coverage** gate, not a cloud correctness oracle. It
ensures changes to declared detectors cannot pass CI without reviewed positive,
negative and UNKNOWN facts; it does **not** establish AWS effective IAM
authorization, real runtime exploitability, external cross-account IAM, real
Kubernetes pod execution or field FP/FN rates. The AST gate currently targets
the production P5-D cross-service graph and its eight enabled findings; it
is **not** an all-272 AWS finding-rule coverage claim.
