# P5-Hardening 3 — Finding Goldens, Unknown Fail-Closed, and P5-C Privacy

This is the **third regression-hardening step**, on top of the merged
Phase-1/2/3 and P5-Hardening 1/2. This remains an entirely offline,
read-only synthetic regression suite, not a live AWS permission oracle.

## Independent expected findings

`tests/data/p5_finding_goldens.json` pins **53** exact case identities.
For each case, it declares the **eight enabled P5-D finding rules'** only
expected flagged resource paths and original, confidential-report
`resource_arn` values (and explicitly affected UNKNOWN scopes). The
manifest is **separate from** graph-edge expected output and production
rule conditions, so an erroneous graph-to-finding mapping cannot
self-validate. In particular, ECS agent execution role is a graph-only
`REVIEW` witness, never an IAM task-role escalation finding.

`tools/p5_finding_goldens.py` performs strict independent checks:
- Exactly the pinned finding resources, with **no extras, duplicates or
  omitted findings** (FP/FN); checked on every enabled P5-D rule
- Exact `flagged_items`, classified `insecure` counts, per-resource
  `POTENTIAL/MEDIUM` or `REVIEW/LOW` confidence and original ARN
- Evidence pointers back to `iam.attack_paths_p5d.edges.<id>`, explicit
  remaining `NOT_VERIFIED` limitations
- For every pinned incomplete/AccessDenied scope, `unknown` cannot
  become `secure`, `PASS`, `NO_MATCH_OBSERVED`,
  `CONFIRMED_CONFIGURATION`, `POLICY_VIOLATION`, or `HIGH`
- The checks run **both before and after SQLite serialization and real
  loopback HTTP retrieval** on all 53 fixture scenarios. The full
  graph-edge golden contract from step 2 is retained.

The manifest includes resource IDs as real-format **synthetic ARNs**.
Customer confidential reports continue preserving their actual ARN,
resource identifiers and resource names as requested; only P5-C
external replay exports are anonymized.

## P5-C replay privacy assertions

`tests/test_p5_hardening_findings_replay.py` scans representative
synthetic P5-D scenarios spanning IAM users/roles, EKS IRSA/Pod Identity,
S3/GovCloud/access points, KMS key policies/grants and Lambda, including
partial-collection scenarios.

It then supplies those real-format, nested P5-D graph objects to the
production `semantic_replay.export_semantic_facts`. Assertions ensure:

- The **27 allowlisted semantic adapters** emit only safe enum values and
  `hmac:<40-hex>` pseudonymous resource tokens; no raw account IDs,
  IAM policies, ARNs, OIDC issuers, graph evidence, key names or private
  sentinels appear in the export
- Repeat export with the same key and data is deterministic; a different
  key changes pseudonymous identities; wrong key cannot replay
- Semantic export is read-only: original full Scout RESULTS, actual
  report IDs, and graph evidence are unchanged
- An incomplete collection cannot replay as a complete verified scan,
  and replay explicitly makes no effective IAM/Cloud API claims
- Even an internally re-signed malformed snapshot containing a raw ARN
  in token, enum value or extra field fails schema validation

Existing P5-C direct 27-adapter adversarial regressions and HMAC integrity
tests are retained. This suite does **not** make new P5-D rule predicates
available in semantic replay; this requires a separately reviewed adapter.

## CI commands

```bash
python tools/p5_finding_goldens.py
python -m pytest -q tests/test_p5_hardening_findings_replay.py
python tools/verify_p5_phase2_pipeline.py
```

All pytest checks are enforced by the existing `tests` CI gate on
Ubuntu/Windows × Python 3.11/3.14. End-to-end SQLite/HTTP/HTML checks run
inside the existing network-isolated Ubuntu `sqlite_http` gate.
No Docker image, cloud account, or new CI job is required.

## Accuracy boundary

The independent goldens defend against regression in rule mapping,
confidence, provenance, serialisation, leakage and false PASS. They
do **not** measure real AWS attack-path false-positive/false-negative
rates or certify effective IAM permissions, SCP/RCP, actual pods,
network reachability or cross-account remote IAM.
