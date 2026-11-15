# P5 regression harness — Phase 1: synthetic AWS facts and pinned oracles

**Scope:** reproducible, read-only AWS service/policy fixtures and independent
expected attack-path results. No SQLite, HTTP, HTML report, Docker container,
network access, cloud credentials or IAM exploitation is part of Phase 1.

## Files and CI

- `tests/data/p5_phase1_synthetic_aws.json`: 10 named normalized AWS inventory
  templates and 33 independently pinned positive/negative/partial scenarios.
- `tests/test_p5_phase1_synthetic_aws.py`: loads and deep-copies fixture
  templates, applies strictly defined `set`, `append` and `delete` edits,
  exercises the production P5-D cross-service correlator and checks **exact**
  edge tuples and graph/collection completeness. The Pod Identity branch runs
  raw-shaped EKS `ListPodIdentityAssociations` →
  `DescribePodIdentityAssociation` through the real read-only collector,
  with a local deterministic client; it does not fake a `roleArn` in List.

Pytest discovers these tests automatically in the already-enforced
`tools/ci.py tests` gate of `.github/workflows/offline.yml` on every PR and
push (Ubuntu/Windows, Python 3.11/3.14). They do not require Docker or AWS.
Run locally with:

```bash
python -m pytest -q tests/test_p5_phase1_synthetic_aws.py
```

## Synthetic cases by service

| Template | Representative cases |
| --- | --- |
| IAM → Lambda | PassRole+Create+Invoke; matching Deny; unrelated Deny; missing Invoke; opaque permissions boundary |
| IAM → EC2 | Profile exists, profile absent, RunInstances denied |
| ECS | Real task role candidate; RunTask denied; execution role agent-only REVIEW |
| EKS IRSA | Correct issuer/aud/sub; incorrect audience; explicit trust Deny |
| EKS Pod Identity | Real List→Describe; no OIDC issuer; List/Describe denied; session policy; targetRoleArn; TagSession Deny |
| S3 | Prefix-scoped external grant; matching Deny; policy AccessDenied; conditional grant; GovCloud partition |
| KMS | External key policy; matching Deny; policy unavailable; unconstrained grant; encryption-context constraint; failed grants collection |
| Lambda resource policy | External invoke-only REVIEW; explicit Deny |

Every case has its own checked-in expected `graph_status`, explicit service
collection expectations where relevant, and **exact source, target, type and
verification** for each edge. A negative fixture requires *zero* edges, not
merely the absence of one named finding. Every emitted candidate is explicitly
`effective_permission_verified=False` and
`execution_verified=False`. Unknown/denied sources must not be promoted to
safe or complete coverage.

All IDs and account numbers are synthetic test values. The fixtures contain
no real account credentials or customer scan artifacts.

## Boundaries and next steps

The fixtures use normalized service data plus a real EKS Pod Identity API
collector; they do **not** prove AWS API permission effects, a running
Kubernetes workload, a network path, a successful attack or real-world false
positive/false negative rates. Runtime dependencies (SCP/RCP, external IAM,
live Pod authorization, reachable services) remain unobserved.

- **Phase 2:** feed these same fixtures through the actual processing engine,
  finding/confidence/evidence assembly, persistent SQLite serialization and
  loopback HTTP report endpoints; do not duplicate the catalog.
- **Phase 3:** pin golden full-report/card/HTTP assertions and browser security
  checks. Compare detector changes against expected UNKNOWN/POTENTIAL/REVIEW
  classifications; add an optional, separate Docker packaging smoke check.
