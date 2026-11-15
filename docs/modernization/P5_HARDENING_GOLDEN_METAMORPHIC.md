# P5-Hardening 2 — Exact Golden Evidence and One-Fact Metamorphic Tests

## Scope

This phase tightens the **existing** Phase-1 → Phase-2 end-to-end regression
harness. No cloud credentials, AWS CLI, or actual exploitation are needed.

### Independent exact edge goldens

All **17 positive** synthetic P5-D witnesses (covering all 14 edge types)
now pin the complete graph edge contract in the checked-in
`tests/data/p5_phase1_synthetic_aws.json`:

- exact AWS `action` (including composite mutation actions)
- `verification`, `confidence`, `collection`
- `evidence.source`, `evidence.resource`, and exact `evidence.basis` (report
  provenance and caveat, not independently verified AWS execution)
- both effective-authorization and workload-execution flags set to `false`

`assert_p5_graph_goldens` reconstructs the deterministic 24-hex edge ID
from the independently pinned source/target/type/action using SHA-256,
then compares the **entire** production edge map to the pinned oracle.
A new edge, omitted edge, altered source, changed action, confidence
inflation, action ID drift, or evidence-basis change is a hard failure.
No expected value is generated from the detector's current output.

The same equality check now runs before and **after** SQLite serialization
and live loopback HTTP retrieval. P5-B2 finding-card checks also validate
the exact expected source pointer and rendered supporting-evidence detail
(type, source, target, action, basis), and explicitly pin candidate vs
review confidence rather than allowing a broad LOW/MEDIUM range.

### Metamorphic single-fact transitions

`tests/data/p5_metamorphic_transitions.json` declares **30** separate
synthetic mutations: one `negative` and one `unknown` transition for
each of 14 detector types, and two `invariant` checks for a narrowly
unrelated explicit Deny. Each transition applies **exactly one** additional
fixture patch (one collected fact or one policy statement), after the
reviewed baseline scenario. Test inputs are deep-copied and checked for
genuine changes.

Examples:

- PassRole → explicit matching Deny: candidate disappears; unrelated
  S3 Deny must preserve the **same ID, provenance and confidence**
- Lambda update/code controls, EC2 profile mutation, ECS task registration,
  and ECS execution role REVIEW are checked separately
- IAM boundary unknown → `partial` graph and no falsely verified path
- IRSA wrong audience → no candidate; missing cluster record → partial
- Pod Identity `Describe` AccessDenied → partial and absent graph edge
- S3 bucket and S3 Access Point explicit Deny vs denied policy collection
- KMS key-policy/grant restrictions vs incomplete collection
- Lambda invoke policy Deny vs missing function record
- Single ECS execution-role change adds **LOW-confidence REVIEW** while
  preserving the existing **MEDIUM-confidence task-role candidate**

The mandatory cross-platform offline `p5_coverage` gate rejects any
missing exact golden fields, unrecognized source-derived detector,
or a detector without a negative and unknown one-fact transition.
Mutation tests intentionally corrupt action, basis, provenance, confidence,
flags, and manifest entries to demonstrate that the suite fails closed.

### CI invocation

```bash
python tools/p5_coverage_matrix.py --check
python -m pytest -q tests/test_p5_phase1_synthetic_aws.py \
  tests/test_p5_hardening_metamorphic.py \
  tests/test_p5_hardening_golden_oracles.py
python tools/verify_p5_phase2_pipeline.py
```

The final command requires real localhost HTTP plus installed browser
dependencies; the existing Ubuntu CI `sqlite_http` phase supplies both.
The `tests` and `p5_coverage` phases run on Ubuntu/Windows Python
3.11/3.14 with the existing network restrictions.

### Limits

These checks prove code consistency against deliberately **independent,
hand-reviewed synthetic oracles**, not effective permissions in AWS.
Provenance is a precise snapshot of ScoutSuite graph source/action/basis;
it is **not** CloudTrail invocation evidence. The exact confidence is
a rule-engine classification, never a probability or exploit proof.
Field FP/FN and externally constrained IAM permissions still require
authorized CloudGoat/CloudFoxable or comparable deployments.
