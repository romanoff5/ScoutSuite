# P4-B IAM relationship graph (role-only preview)

## Scope

Runs **offline over previously collected IAM data**, with no additional AWS API calls and no AWS mutations. It indexes IAM role ARNs and OIDC provider ARNs, then creates edges for OIDC trust and for plausible PassRole-to-privileged-service-role paths.

The graph is exported as `services.iam.relationship_graph`:

- `nodes` — stable ARN-keyed IAM roles and referenced OIDC providers.
- `edges` — deterministic SHA-256-truncated keys for `oidc_trust` and `passrole_privileged_role_candidate`, including service and source policy references.
- `status` — `complete`, `partial`, or `unknown` for **graph collection**, not effective IAM authorization.
- `limitations` — missing dimensions of actual AWS authorization.

The three findings are marked `REVIEW` in default/detailed profiles, not automatically Medium/High.

## Initial path coverage

- `iam:PassRole` to a role with an administrator-like Allow policy, paired with `ec2:RunInstances` / `lambda:CreateFunction` and respective service trust.
- IAM role trust with an OIDC provider using `sts:AssumeRoleWithWebIdentity`.
- Broad OIDC subject scope; admin-like policy on a federated role.

**No effective permission evaluation.** Explicit Deny, NotAction, NotResource, condition expressions, permissions boundaries, unknown policy documents and pagination/API failures must be treated conservatively. SCP/RCP, session policies, resource-based policies, IAM policy simulation, GitHub environment protection and EKS Kubernetes RBAC are not evaluated.

## Known limitations / work for later P4-B phases

1. The initial graph considers only **role principals** and currently collected inline/managed policies. It does not correlate IAM users and group policies.
2. Managed policy collection and role attachment mappings are inherited from the current IAM facade; missing links result in UNKNOWN rather than a verified PASS.
3. The graph is bounded at 2,500 roles and 4,000 edges. Truncation marks graph partial.
4. "Administrator-like" is inferred from broad identity-based Allow statements and **is not proof** of effective admin access.
5. PassRole edges are candidates, not active attack paths. No AWS role assumption, resource creation, network call, or scan of credentials is performed.
6. OIDC trust scopes vary by IdP; GitHub rejects certain unbounded subjects during role creation, so missing GitHub conditions are marked UNKNOWN.

Before deploying findings as enforcement, validate against IAM Access Analyzer and organization-specific effective policy boundaries.

## Regression requirements

All new rules must be tested through actual rule JSON traversal and tri-state evidence classification. Required negative tests: scoped GitHub OIDC, malformed/missing trust, explicit Deny, conditional privileges, permissions boundaries, missing managed policy documents and graph bound exhaustion.

## P4-B evidence completeness hardening

The source IAM `ListRoles` inventory is not sufficient to evaluate permissions
boundaries. For each role, `GetRole` is now required to establish an explicit
`role_boundary_collection_status`; a denied or malformed response is UNKNOWN.
`ListAttachedRolePolicies` separately verifies the *exact* managed policy
attachments (including the successful empty case). Requests are read-only, bounded
at 20 pages / 500 policies per role, and failures never become empty lists. The
graph joins returned ARNs to the already-collected managed policy documents;
missing documents remain UNKNOWN. This increases IAM API requests per role.

An incomplete role graph invalidates the P4-B OIDC and PassRole candidates as
well as the overall graph status. CI covers boundary restrictions, empty and
denied role attachments, missing managed documents and truncation.
