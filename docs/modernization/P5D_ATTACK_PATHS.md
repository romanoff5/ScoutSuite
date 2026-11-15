# P5-D AWS cross-service attack-path candidates

This phase adds a deterministic, bounded, read-only cross-service graph under `iam.attack_paths_p5d`, plus report finding rules with P5-B evidence/confidence. Production reports retain actual IAM ARNs, account IDs, bucket/function/task/key names. Exported P4-F/F2 replay data remains governed by its separate anonymization allowlist.

## Paths

- IAM identity Allow + `iam:PassRole` + Lambda `CreateFunction` and `InvokeFunction` on the same resource witness, or controlled `UpdateFunctionConfiguration`, `UpdateFunctionCode` and `InvokeFunction` on one observed function, with a compatible service trust.
- IAM + compatible EC2 trust + verified instance profile association + `ec2:RunInstances` scoped six-resource synthetic witness.
- IAM + ECS task service trust + `iam:PassRole` + `ecs:RunTask` on an observed task definition using the target role, or `ecs:RegisterTaskDefinition` with a separately tested synthetic next-revision RunTask witness.
- IRSA: EKS cluster OIDC issuer correlated to role Federated trust, exact `aud=sts.amazonaws.com` and `system:serviceaccount:namespace:name` subject; **service account or Pod existence is not asserted**.
- EKS Pod Identity: bounded EKS API association census, name/namespace/role plus compatible `pods.eks.amazonaws.com` AssumeRole and TagSession trust. A denied/incomplete list is UNKNOWN.
- S3 bucket / access point named cross-account principals with action- and resource-scoped evaluation and explicit Deny precedence, with BPA restriction awareness.
- KMS explicit external key policy Decrypt or observed unconstrained grant Decrypt. Root-account trust alone is not direct access.
- External Lambda resource-policy InvokeFunction is **REVIEW only**; invocation never implies executing arbitrary code or assuming its execution role.

## Evidence semantics

`edges[].verification = POTENTIAL` (or `REVIEW`). `effective_permission_verified = false`, `execution_verified = false`; P5-B finding metadata states `POTENTIAL_ATTACK_PATH`. Incomplete identity census, permissions boundary, ambiguous Deny, unknown policy condition or failed API suppresses positive IAM correlation. Synthetic creation witnesses test permission scope but do not assert that a service API would succeed or a resource exists. No AWS API mutations, network tests or IAM simulation.

## Limits

- Organizations SCPs/RCPs, session policies, remote-account identity policies, capacity/network scheduling and IAM simulation are not collected. Cross-account access is not confirmed without both sides.
- EKS Kubernetes RBAC, live ServiceAccount/Pod inventory and pod execution are not fetched; IRSA emits a **trust-based candidate** only.
- S3 object existence, access point/bucket combined authorization, KMS encryption-context requirements and external KMS IAM permissions are not verified. Only explicitly permitted named principals are emitted.
- Scope bounded by `MAX_SOURCES`, `MAX_TARGETS`, `MAX_PAIRS`, `MAX_EDGES` and service inventory caps; truncation marks the graph `partial`.
- Rule-level negative evidence is UNKNOWN rather than a universal proof of no exposure. High confidence is not assigned to cross-service exploit paths.

Test with `python -m pytest tests/test_p5d_attack_paths.py -q` and the repository's Offline CI across its configured platforms. Do not merge on red CI.

## Correctness audit follow-up (P5-A/B/B2/C/D/D2)

- P5-A admin-looking role hints aggregate independent broad IAM/EC2/S3
  Allow statements rather than requiring all three actions in one statement.
  Relevant scoped Deny still vetoes a candidate. S3 synthetic witness
  respects the partition (commercial, GovCloud and China).
- P5-B and P5-B2 flag mismatched rule-engine and independently classified
  insecure counts as UNKNOWN/PARTIAL, not medium/high confidence.
- P5-C maintains its reviewed 27-rule fixed semantic replay allowlist,
  HMAC integrity, and no raw ARN/policy serialization. Existing and
  cross-phase mutation/privacy tests remain enforced.
- P5-D records observed/partial/unknown source-inventory census before
  truncating at each resource cap. No incomplete service census may claim
  complete cross-service graph coverage.
- ECS task roles and execution roles are distinct. The ECS agent execution
  role is review-only (LOW confidence); it is not directly available to
  application containers. Existing task-role paths remain POTENTIAL.
- S3 bucket policy witnesses preserve the actual AWS partition in both the
  deterministic graph target and P5-B2 per-resource evidence binding.
- P5-D2 retains real ARNs in confidential reports, while replay export
  remains anonymized. EKS Pod Identity List→Describe trust/denial/session
  restrictions are unchanged.

### KMS grant API status fidelity

Previously the generic AWS paginator returned an empty list after some
`AccessDenied` or malformed responses, so an unreadable KMS grants
inventory could be indistinguishable from a legitimately empty one.
Read-only `ListGrants` now uses bounded 100-item pages and at most 20
pages per key, with explicit `Truncated/NextMarker` validation. Errors,
duplicate grant IDs, malformed pages and page-limit overruns yield
`grants_collection_status=partial`, not a verified empty list. Successful
policy reads separately record `policy_collection_status=complete`.
Both states appear on KMS report details and in P5-D service coverage.
Missing account IDs in malformed grant entries no longer crash parsing.

These are collection facts and do not prove the external principal can
decrypt: KMS key policy/grants, external IAM, constraints and AWS
Organizations restrictions remain separate authorization checks.
