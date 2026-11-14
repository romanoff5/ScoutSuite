# P5-B: finding confidence and evidence quality (2026-11-15)

## Contract

This is an additive **report metadata** schema. Existing finding IDs, severities,
resource paths, original account IDs/ARNs, and rule conditions are unchanged.
`confidence_assessment.schema_version=1` has:

- `claim_type`: explicit scope of what is being asserted, NOT severity.
- `verification_status`: `CONFIRMED_CONFIGURATION`, `POTENTIAL`,
  `OBSERVED_PARTIAL_SCOPE`, `REVIEW`, `POLICY_VIOLATION`,
  `NO_MATCH_OBSERVED`, `NOT_APPLICABLE` or `UNKNOWN`.
- `confidence`: `HIGH`, `MEDIUM` or `UNKNOWN`, backed by reason codes
  and versioned classifier evidence. This is not a numerical exploit probability.
- `evidence_quality`: `COMPLETE`, `PARTIAL` or `UNAVAILABLE`.
- `evaluation_summary.observations`: structured per-resource `resource_path`,
  `outcome`, `evidence_policy` and allowlisted `observed_attributes`. It
  retains actual identifiers in normal confidential reports. Only insecure
  and unknown classifier outcomes are stored; secure observations remain
  summarized in the existing counts. No observation is silently truncated.
- `effective_permission_verified`, `external_reachability_verified` and
  `compliance_verified`: false; no unsupported proof is inferred.

A known actionable configuration can be confirmed while overall assessment
quality is partial due to other UNKNOWN resources. A possible exploit path
never becomes a confirmed exploit merely because its policy statements are
readable. Evidence disagreement is `UNKNOWN`, not `PASS`.

## Explicit boundaries for remaining accuracy work

| Domain | Current statement | Not yet proven |
| --- | --- | --- |
| IAM/OIDC | Candidate identity/trust relationships | Effective authorization through policy simulator, SCP/RCP, session/boundary controls and execution |
| EC2/ALB/WAF | Potential direct backend/HTTPS exposure | Complete routes, NACLs, host firewall and end-to-end reachability |
| CloudWatch/SIEM | `MISSING` means local CloudWatch gap only | External SIEM coverage and successful notification delivery are `EXTERNAL_UNVERIFIED`; `VERIFIED_CONFIGURED` needs explicit verified delivery evidence |
| ACM/TLS | Certificate SAN against visible Route 53 aliases | Expected production hostnames beyond this inventory and live SNI handshakes |
| AWS Backup | Backup/restore job inventory observations | Application validation, contractual RPO and RTO measurements |
| Policy rules | REVIEW without selected policy | An approved compliance profile must enable an explicit policy threshold before severity is assigned |

## Compatibility and rollback

Older JSON/SQLite reports lacking `confidence_assessment` and
`evaluation_summary.observations` remain readable. These fields are additive
and are escaped by the Handlebars dashboard. The public P4-F/P4-F2 snapshot
projection continues to discard source resource paths/observed attributes:
never export confidential report evidence to public regression fixtures.

Rollback: revert the P5-B commit; historical reports are not modified.
No new AWS API permissions, cloud credentials, network probes or live scans.


## P5-B IAM Deny precision

The IAM relationship graph now evaluates policy statements for the **specific
action and target ARN** instead of making every identity indeterminate when an
unrelated `Deny` occurs. Explicit matching Deny overrides Allow; conditional
matching Deny, `NotAction`, `NotResource`, incomplete documents and missing
permission-boundary evidence cannot produce a confirmed path. Both P4-B and
P4-B2 remain *potential* privilege escalation analysis, not policy simulator
verification. No new API permissions were requested.
