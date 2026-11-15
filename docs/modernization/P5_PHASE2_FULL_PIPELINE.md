# P5 phase 2 — full report regression pipeline

## Objective and execution boundary

Exercise production transformations of synthetic AWS inventory facts into:
P4-B IAM relationship graph, P5-D cross-service graph, P5-D rule evaluation,
P5-B confidence, P5-B2 resource cards, versioned RESULTS SQLite database,
true HTTP/TCP API, and SQLite-backed HTML report.

The source oracle remains the checked-in independent
tests/data/p5_phase1_synthetic_aws.json: 33 cases and ten collection templates.
No AWS credentials, customer snapshots, cloud requests, nonlocal hosts,
IAM exploitation, mutation or outside URL downloads.

## Activation fix

Phase 2 discovered that the P5-D finding definitions existed but were not
enabled in the standard aws/rules/rulesets/default.json. A graph could exist
in RESULTS while the normal findings and dashboard lacked any P5-D entries.
Phase 2 enables all eight rules in the default AWS ruleset with REVIEW severity.
The harness loads actual default Ruleset('aws') objects and fails if any rule
is disabled or missing. Potential paths are not assigned proven High severity.

Privileged synthetic IAM roles now include three explicit broad Allow grants
spread across separate policy statements. Real build_relationship_graph
derives the admin-like hint instead of trusting hard-coded fixture status.
The inputs and accounts remain synthetic.

## Required CI

tools/ci.py runs tools/verify_p5_phase2_pipeline.py after the existing
verify_sqlite_http.py in the mandatory sqlite_http gate. Both run in the
existing Linux loopback-only network namespace without an external interface,
AWS credentials, production scan files or Internet. Ubuntu/Python 3.11 and
3.14 on PRs and master pushes enforce the gate. Socket-blocked pytest and
Windows platform gates remain unchanged.

Each of the 33 independent scenarios:
1. Applies synthetic AWS fact changes, with real List->Describe collector code
   and a deterministic SDK stub for EKS Pod Identity.
2. Runs the production IAM relationship and P5-D attack path correlators,
   asserting exact pinned edge tuples, graph status and source/target.
3. Runs production Ruleset and ProcessingEngine with real rule conditions:
   checked/flagged counts, evidence classifiers, confidence and resource cards.
   Only oracle-pinned resources may be flagged; UNKNOWN and AccessDenied
   must never become verified PASS. External Lambda invoke is LOW REVIEW.
   ECS execution-role evidence is graph-only REVIEW, not a task-role finding.
4. Serializes the actual RESULTS structure into SQLite using ScoutResultEncoder,
   reads it through the real Server over loopback HTTP and verifies summary,
   full and page endpoints, counts, confidence, source/target and exact ARNs.
5. Generates a real SQLite HTML report through ScoutReport and serves its
   assets through the same-origin API. Playwright with installed Chrome/
   Chromium renders a real P5-D finding card. Browser errors, missing ARN/
   evidence, external HTTP requests and unescaped content fail the gate.

Run locally with loopback available:
    python tools/verify_p5_phase2_pipeline.py

Phase 1 oracle tests without a socket:
    python -m pytest -q tests/test_p5_phase1_synthetic_aws.py

## Boundaries and phase 3

These are deterministic regression invariants, not proof of effective AWS
authorization, exploitation or real-account detection precision. SCP/RCP,
actual reachability and live Kubernetes Pods remain unverified. Phase 3
can pin golden card/API snapshots, add mutation checks, and run an optional
Docker packaging smoke independent from the detector correctness oracle.
