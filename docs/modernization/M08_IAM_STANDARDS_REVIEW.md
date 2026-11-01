# M08 — IAM policy freshness and benchmark mappings (2026-11-01)

This is a **non-certifying, dated review**, not a replacement for an AWS policy simulator, IAM Access Analyzer, or an authoritative benchmark.

## IAM policy evaluation limitations

- The built-in IAM finding rules inspect **policy-document syntax** (for example Allow Action:* Resource:* or NotAction). They do not calculate effective permissions. Evaluation needs identity policies, resource policies, permission boundaries, SCP/RCP, session policies, trust relationships, explicit denies, and request context.
- The `policyuniverse` dependency is an external *static* action catalog, not an authoritative live AWS service-authorization model. Do not interpret its action expansion as proof of currently authorized actions. An out-of-date catalog must not silently produce a clean finding.
- Do not infer the IAM account password policy applies to IAM Identity Center, OIDC/SAML federated users, or access keys. `GetAccountPasswordPolicy` only describes IAM user console-password controls. An unavailable result must not be converted into a weak or compliant password policy.
- Future action-catalog work requires a dated upstream manifest, a deterministic offline snapshot, a version/hash, and test cases for newly introduced AWS actions. Live AWS policy simulation is out of scope.

## CIS mappings: preserve, do not assert current equivalence

The inherited `ScoutSuite/providers/aws/rules/rulesets/cis-1.2.0.json` remains a **historical CIS v1.2.0 mapping**; it is not a current CIS benchmark. No automatic re-numbering or equivalence with a newer benchmark was made. We deliberately do **not** publish a new CIS profile without verified licensed control wording, applicability, service support, and traceability per control. A control name or similar goal is not a control-equivalence proof.

The default fork profile and `aws-security-focused-2026-11.json` are not certifications. The latter remains an opt-in, explicitly non-CIS experimental three-control profile. Historical mappings and finding keys remain intact.

## Required next IAM/standards slice

Verify action coverage against dated AWS Service Authorization Reference data, capture hash and supported service versions, isolate synthetic regression tests, and explicitly mark unknown action catalog coverage. For CIS create a licensed, versioned mapping matrix identifying control number/text edition, resource scope, collection dependency, test cases and license permission before publishing a new ruleset.
