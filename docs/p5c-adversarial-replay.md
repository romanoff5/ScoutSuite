# P5-C — adversarial AWS rule regression and semantic replay

## Exact scope and non-claims

P5-C extends the **allowlisted P4-F2 semantic replay** from **5 to 27** JSON
finding predicates (22 added). Services: IAM **10**, EC2 **4**,
RDS **8**, S3 **3**, CloudWatch **2**. The source catalogue is larger:
**27/272 is not broad AWS-catalogue coverage**. The original P3-C
**30 synthetic triads** stay separate and are not relabelled as
field-validated coverage.

This is **read-only offline re-execution of known low-cardinality status
annotations** by the installed ScoutSuite `recurse/pass_conditions` engine,
not collector replay, SDK response emulation, route validation, service
authorization simulation, a successful exploit or an end-to-end AWS scan.
Normal RESULTS/HTML continue to show *real* IDs, names and ARNs; the
separately exported HMAC-authenticated semantic snapshot never contains them.

The IAM PassRole/AssumeRole/OIDC values are policy **candidates** only:
SCP/RCP, permission boundaries, resource policies, session policies,
action-specific authorization, service execution and IAM simulation remain
unverified. EC2 public HTTPS means *potential exposure*; RDS local alarm
presence does not verify alert delivery to an external SIEM; S3 effective
public exposure is a *bucket-level* observation.

## Fixed independent regression oracles

`tests/data/p5c_semantic_cases.json` pins **27 synthetic
positive / negative / UNKNOWN cases**, independent of the current JSON
predicates. `tests/test_p5c_adversarial_replay.py` asserts:

1. Expected positive finding and known-negative non-finding against the
   **production** JSON rule evaluator, with a single raw semantic fact
   changing between the two states.
2. One-field inverse mutation produces a newly flagged synthetic resource.
3. Invalid/missing scalar facts are converted to `unknown` and preserve a
   partial result; denied/incomplete collection cannot be called clean.
4. Each of **27 targeted predicate mutants** changes the finding's
   allowlisted literal(s) to the independently pinned negative value.
   A mutant is killed only when the actual replayed **resource identities**
   flip; SHA drift alone does not count as a kill.
5. Threshold and protocol boundaries: 443 vs neighbouring ports and TCP
   ranges, world vs restricted IPv4/IPv6 CIDRs, IAM SourceAccount scope,
   RDS backup retention 0/1/29/30 days, and unknown S3 BPA inputs.
6. Historical **five-rule** P4-F2 facts remain replayable after upgrade,
   while arbitrary signed inventories are rejected.

**Caveat:** IAM B2 candidate-only collectors currently use `unknown`
when absence is not proven. The explicitly fabricated `not_applicable`
negative cases exercise rule *predicates* only; they **do not assert that
these IAM collectors can confirm a safe negative in production**. A
negative detector outcome over incomplete collection is `UNKNOWN`,
not PASS.

## Reproducible checks

```bash
python -m pytest -q tests/test_p5c_adversarial_replay.py
python -m pytest -q tests/test_p4f2_semantic_replay.py tests/test_p4f2_history_ui.py
python -m pytest -q tests/test_p3c_quality_gate.py tests/test_metamorphic_adversarial.py
python tools/p4f_evidence.py facts-export --report RESULTS.json --key-file .p4f.snapshot-key --output p5c-facts.json
python tools/p4f_evidence.py facts-replay --snapshot p5c-facts.json --key-file .p4f.snapshot-key
```

The browser's local **Scans & Snapshots** view previews all 27 enums without
a key or network request. Imported HMAC snapshots are **not authenticated
in the browser**, and the preview is not a cryptographically verified
rule-engine replay. Use `facts-replay` for integrity and executable predicates.

A v1 P4-F2 artifact with exactly the historical five-rule inventory
continues to replay. New v1 exports contain exactly 27 entries. An
arbitrary subset is rejected even with a correct HMAC; change to the
snapshot format and allowed grammar requires a reviewed migration.

## Benchmark and acceptance interpretation

| Measure | Fixed scope / acceptance criterion |
| --- | --- |
| Existing P3-C triads | 30 unchanged; pre-existing P3-C gate must pass |
| P5-C replayable JSON rules | 27 (was 5; +22) |
| Synthetic labeled positives | 27 expected, zero misses in rule-engine test |
| Synthetic labeled negatives | 27 expected, zero false findings in rule-engine test |
| UNKNOWN/denial transitions | 27 expected fail-closed |
| Predicate mutation operator | 27 literal-to-safe mutants; all must change selected identity |
| Boundary variants | Additional concrete AWS syntax/threshold tests |
| P5-C rule coverage | 27 fixed rule IDs, not a denominator for AWS detection quality |

Precision and recall may be calculated on a **controlled, independently
labeled synthetic corpus**, but success in CI does **not** establish
precision/recall on real AWS accounts without ground truth. The fixed
mutation operator is deliberately narrow; its 100% kill target is **not**
a general mutation score over every possible code or collector change.

When expanding this allowlist, require a reviewed status producer, an
independent negative oracle, explicit UNKNOWN and denial transitions,
bounded predicate grammar, privacy review, and updated HTML parity tests.
Complex IAM policy simulation, numerical thresholds and raw CIDR/ARN
matching need dedicated typed adapters and must not be silently
approximated by strings or absence of findings.
