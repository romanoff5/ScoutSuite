# M08-A — evidence-aware AWS rules and first versioned policy profile

Date: 2026-11-01. Branch base: `c1d8412b40afee2dce04d705435a6ca5b627f06c`.

## Shipped rule semantics

Three existing AWS rule definitions opt into additive version-1 evidence
classification:

| Existing rule key | Policy identifier | Evidence |
| --- | --- | --- |
| `kms-cmk-rotation-disabled` | `kms-automatic-rotation-v1` | Customer-managed, enabled AWS_KMS symmetric ENCRYPT_DECRYPT keys; effective rotation state |
| `cloudtrail-no-data-logging` | `cloudtrail-data-events-v1` | Collected event selector status and `DataEventsEnabled` |
| `cloudtrail-partial-data-logging` | `cloudtrail-data-coverage-v1` | Collected selector status and wildcard event coverage |

The legacy finding IDs, `id_suffix`, condition evaluation, severity,
`checked_items`, `flagged_items`, `items`, exception IDs and default
ruleset selection remain unchanged. Each opted-in rule additionally emits
`evaluation_summary`: `version`, `policy`, `assessment_status`,
counts for `secure`, `insecure`, `unknown` and `not_applicable`,
`unknown_resources`, `evaluated_resources` and the explicit
`compliance_verified: false` flag. When unknown evidence exists, its
finding is marked `assessment_status=incomplete` and the run records
`RuleEvidenceUnknown` in `collection_status`. Zero applicable resources
is `not_applicable`, *not* evidence of passing a benchmark.

Unknown, denied or conflicting data must never be silently interpreted as
secure. Unsupported KMS types (asymmetric, HMAC, imported/custom material)
are `not_applicable` to **automatic** rotation. AWS-managed keys are
excluded from the customer-managed control. These are not statements about
manual or on-demand rotation coverage. AWS KMS automatic rotation for
customer managed keys is supported only on AWS_KMS symmetric encryption
keys, subject to compatible key states.

## Versioned ruleset

`ScoutSuite/providers/aws/rules/rulesets/aws-security-focused-2026-11.json`
is an **opt-in, three-control, explicitly versioned experimental profile**.
It is not a CIS, NIST, AWS Foundational Security Best Practices or other
licensed standard mapping. Its `profile_id=aws-security-focused` and
`profile_version=2026.11.0` are carried through the existing Ruleset and
attached to each evaluated finding. The original `default.json` remains
the default; only an explicit `--ruleset` selection enables the focused
three-control profile. A separate release must determine catalog ownership,
profile lifecycle, validated mappings and full coverage.

### Primary references (reviewed 2026-11-01)

- AWS KMS API, `GetKeyRotationStatus`:
  https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html
- AWS CloudTrail API, `GetEventSelectors`:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html

## Acceptance and boundaries

Guarded offline tests verify secure, insecure, denied/unavailable, missing
and not-applicable resource cases; exact existing finding paths,
checked/flagged counts, profile metadata and additive JSON result serialization.
Prior M04 collection errors remain authoritative. AWS/Azure/GCP
characterization and package smoke must pass on Windows and Ubuntu Python 3.11.

**Not complete M08:** RDS certificate lifecycle, ALB/ELB TLS policy
capability catalogs, full S3 encryption/exposure semantics, IMDSv2 and Lambda
runtime end-of-support, historical CIS edition mapping review, full rule
exception round trips for changed findings, catalog source provenance
update automation and Python 3.14. The HTML viewer still lacks a dedicated
unknown evidence panel (M09); the machine-readable assessment fields are
additive only.

No live cloud API, credentials or AWS write permissions were used.
