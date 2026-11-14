# P3-C — Offline Detection Coverage Quality Gate

## Purpose and privacy boundary

This stage adds a **public, anonymized** benchmark derived from two confidential
assessments without publishing client names, resource identifiers, AWS account IDs,
domain names, exploit evidence, proprietary prose or the original report files.

The source-set labels `A` and `B` are synthetic identifiers. The 66 case
abstracts are manually normalized; they are **not original findings** and are
**not live scanner results**.

## Case inventory and interpretation

| Metric | Baseline |
| --- | ---: |
| Source set A / B | 39 / 27 |
| AWS configuration cases | 63 |
| Direct rule-contract mappings | 32 |
| Partial semantic mappings | 22 |
| Genuine rule gaps | 9 |
| Application / dependency outside scanner scope | 3 |
| Direct mapping share of in-scope cases | 50.79% |
| Direct plus partial mapping share | 85.71% |

A **direct** mapping means the existing rule evaluates the **general control
condition** described by the abstract case. It does *not* mean the original
finding would have been flagged under the observed scope, permissions or runtime
state. **Partial** denotes narrower detection, missing correlation or external
evidence; **gap** means no adequate implemented rule; **out_of_scope** excludes
application and SCA findings from the AWS configuration denominator.

The gap IDs are stable anonymized control references; they can inform future
roadmap tasks without importing confidential report content. The test harness
fails on missing/deleted entries and invalid rule references.

## Actual-rule synthetic TP / TN / UNKNOWN matrix

The `tests/data/p3c_detection_triads.json` corpus defines 18 synthetic
triplets. The gate runs the *actual* JSON `conditions` through
`ScoutSuite.core.utils.recurse`, and the *actual* evidence policy through
`evaluate_rule_evidence`.

- Positive configuration → must flag one affected resource and classify
  `insecure` (**TP**), otherwise **FN**.
- Negative configuration → must not flag; verified `secure` is **TN**.
  Policy-conservative `unknown` remains **unverified**, not `TN`.
- Denied/missing/partial evidence surrogate → must remain `unknown` and
  `incomplete`, never turn into a successful compliance assertion.

The gate fails on **any** synthetic FP, FN, unknown false alert, unknown falsely
classified secure, invalid rule mapping, missing test scenario, crosswalk
parity overclaim or accidentally embedded client identifier. Coverage breadth
and synthetically estimated quality must not be confused with field accuracy.

These tests exercise rules **after resource normalization**; existing P0–P3-B
adapter regression suites test their own normalization paths. They do not
estimate actual internet reachability, AWS API permissions, missing external
controls or customer-specific false-positive rates.

## Security Hub / Prowler semantic crosswalk

`tests/data/p3c_external_crosswalk.json` contains authoritative reference
URLs and a pinned Prowler Git SHA. All crosswalk entries are deliberately
marked **related** or **partial**; none is certified equivalent. Differences
in scope, exclusion rules, AWS organisation context, temporal windows and
incomplete evidence must be reviewed before claiming parity.

The Security Hub relationship is between **CSPM controls**, not a network call
to Security Hub or a comparison of live Security Hub findings.
The Prowler relationship is to **check metadata**, not full behavioral
equivalence to a particular Prowler release or configuration profile.

## Usage (offline; no AWS credentials)

```shell
python -B -m tools.p3c_quality --check
python -B -m tools.p3c_quality --json p3c-summary.json --markdown p3c-summary.md
```

The first command is part of the four-platform Offline CI workflow.
The second writes artifacts locally for additional manual review; such
generated artifacts are not automatically uploaded or committed.

The output uses the explicit indicator
`field_detection_verified: false` and does not claim an empirical
false-positive or false-negative rate. To establish those metrics, conduct an
authorised blind replay against independent, verified AWS fixture inventories
and later a separate approved field-assessment sample.

## Updating the benchmark

1. Classify the new abstract control as direct/partial/gap/out_of_scope.
2. Validate its rule contract and affected resource type and explain caveats.
3. Add genuine offline positive/negative/incomplete tests when supported.
4. Update the crosswalk only after reading the external check's official
   semantics; prefer `partial` over unsupported equivalence claims.
5. Run the gate with `--check`, the full CI matrix and report/browser tests.
6. Never use the confidential source report or its literal findings in Git.
