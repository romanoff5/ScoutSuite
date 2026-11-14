# Policy-driven findings and severity (AWS)

## Why a separate REVIEW status?

Cloud security observations do not all represent an established vulnerability.
For example, shared EC2 SSH KeyName, unlimited CloudWatch log retention, or a
log group using **AWS-managed** encryption instead of customer-managed KMS
can be acceptable configurations for a particular organization.

A standard `default` or `detailed` AWS scan retains these observations but
categorizes six policy-dependent rules as **REVIEW** (a neutral disposition,
not a risk severity). The report records:

- `finding_category: policy_dependent`
- `finding_disposition: REVIEW`
- `severity_assigned: false`
- `assessment_status: review`, except where evidence is incomplete

A nonmatching review rule must **not** assert that any external compliance
requirement was met. A service with only review observations must not become
a standard warning/medium-severity security incident.

## Explicit compliance profile

The opt-in example is:

```bash
scout aws --ruleset aws-compliance-policy-2026-11
```

The example profile version `2026.11.0` is **not** an industry-approved
baseline. The included maximum retention of **365 days**, customer KMS
requirements, shared SSH key restriction and internet egress restriction are
illustrative values ONLY. Review them with the organization's approved
retention, encryption, access control and threat model requirements *before*
using this profile as evidence in an assessment.

In an approved profile, selected policy rules use explicit `warning` or
`danger` severity. Report findings carry their profile ID/version,
`policy_requirement`, and `policy_threshold`, including the numeric
retention maximum where applicable. `POLICY_VIOLATION` is not a claim that
a universal security benchmark was violated.

### Retention control

`max_cloudwatch_retention_days: 365` means:

| Observed retention | Result |
| --- | --- |
| indefinite | policy violation |
| 366 days | policy violation |
| 365 days | within selected threshold |
| 90 days | within selected threshold |
| unavailable or malformed API evidence | UNKNOWN / incomplete |

The numeric rule is selected **only** in the opt-in profile; it is not an
unrequested risk-severity escalation in the standard ruleset.

### Safely customize the profile

Copy `ScoutSuite/providers/aws/rules/rulesets/aws-compliance-policy-2026-11.json`
and select it by path. Change `profile_id` and `profile_version` for
controlled updates. To change the retention maximum, change both
`policy_thresholds.max_cloudwatch_retention_days` and the matching rule
`args: ["365"]` to the same decimal value. Valid bounds: 1–3650 days.

Other policy assertions must be explicitly `true` when their rules are
enabled. To omit a requirement, remove its rule. Unrecognized keys, false
assertions for selected rules, invalid thresholds, and mismatched rule
arguments cause a **hard validation failure** rather than silent fallback.

If the organization has approved exceptions, assess and document them
separately. The rules do not independently prove SOC 2/ISO 27001 compliance,
contractual sufficiency, end-to-end encryption or notification delivery.

## Regression invariants

1. No default policy observation is automatically Medium/High.
2. REVIEW does not become PASS because there are zero flagged resources.
3. Incomplete resource evidence remains incomplete.
4. Approved policy thresholds are versioned and validated before scanning.
5. Ordinary security findings retain their existing severity and IDs.
6. Existing external review findings still require the analyst to decide
   whether a policy requirement actually applies.
