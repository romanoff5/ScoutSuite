# P5-D AWS cross-service attack-path candidates

This phase adds a deterministic, bounded, read-only cross-service graph under `iam.attack_paths_p5d`, plus report finding rules with P5-B evidence/confidence. Production reports retain actual IAM ARNs, account IDs, bucket/function/task/key names. Exported P4-F/F2 replay data remains governed by its separate anonymization allowlist.

## Paths

- IAM identity Allow + `iam:PassRole` + Lambda `CreateFunction` or controlled `UpdateFunctionConfiguration` and `UpdateFunctionCode`, with a compatible service trust.
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
