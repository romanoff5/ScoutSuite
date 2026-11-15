# P5-D2 — report evidence and EKS Pod Identity API fidelity

## Correct Pod Identity census

The EKS `ListPodIdentityAssociations` API returns a summary without `roleArn`.
P5-D2 uses read-only, bounded pagination (`maxResults=100`, at most 20 pages,
1,000 unique associations per cluster) and **DescribePodIdentityAssociation**
for each association (8 concurrent API calls). A candidate requires:

1. A matching `associationId`, cluster name, namespace, service account and
   association ARN between List and Describe.
2. A verified same-account primary `roleArn` from Describe.
3. A complete association census: partial/denied/malformed list or failed
   Describe never becomes verified absence or a candidate.
4. Compatible service trust for `pods.eks.amazonaws.com` with
   `sts:AssumeRole` and `sts:TagSession`, subject to scoped Deny checks.
5. An admin-policy **hint** for the primary IAM role, not a simulated effective
   authorization or proof that a live Pod can assume that role.

IRSA and Pod Identity are independent: absence of OIDC issuer does not
prevent Pod Identity correlation. EKS identity association summaries do not
prove presence of a Kubernetes ServiceAccount, pod, Pod Identity Agent or
credential issuance.

`targetRoleArn` represents another authorization hop (including cross-account
role chaining). Session policies can limit effective permissions. **If
`targetRoleArn` is set, or if a session policy is present/unknown, a primary
admin-like role is not surfaced as a verified privileged Pod Identity
destination.** Collect only the target ARN and a boolean session policy
presence; never store raw policy JSON or secret payloads.

This implementation does not claim to simulate the target role trust,
organization SCPs/RCPs, resource policies, permission boundaries,
Kubernetes RBAC, ServiceAccount existence or effective IAM authorization.
For targeted cross-account Pod Identity chains, additional read-only
cross-account evidence must be collected before asserting the path.

## Report integration

AWS report resource modals now include the escaped `p5d.attack_paths`
partial for IAM users/roles, EKS clusters, S3 buckets/access points,
KMS keys and Lambda functions. Each candidate links to a deterministic
graph `id`, source/target ARN, action, mechanism, evidence basis, and
verification/confidence. Resource details use the original identifiers in
the local, confidential report. P4-F anonymous replay remains separately
governed by its allowlist and never exports this graph raw.

EKS cluster details additionally display verified Pod Identity association
ARN, namespace/service account, primary and chained target role ARNs,
per-association Describe status and session policy presence (no policy body).

P5-B2 per-resource evidence cards require both the resource classifier
state and a matching graph witness for `POTENTIAL` confidence; missing or
inconsistent graph evidence is `UNKNOWN`. AWS effective authorization,
reachability and runtime execution remain `NOT_VERIFIED`. Lambda external
invocation grants are `REVIEW` with `LOW` confidence, not privilege escalation.

## Regression gates

`tests/test_p5d2_report_podidentity.py` exercises List→Describe with
no role in List, missing/denied Describe, malformed and cross-account
primary roles, duplicate pagination, session restrictions, role-chaining
suppression, no-OIDC Pod Identity, exact graph provenance and escaped
report templates. Existing P5-D tests were updated to make Describe
completeness explicit. The Offline CI report browser suite renders the EKS
and attack-path partial with hostile HTML in a real browser and asserts
it is treated as text. The complete Offline CI platform matrix and P3-C
quality gate must be green before merge.

References:
- https://docs.aws.amazon.com/eks/latest/APIReference/API_ListPodIdentityAssociations.html
- https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribePodIdentityAssociation.html
- https://docs.aws.amazon.com/eks/latest/userguide/pod-id-assign-target-role.html

## Verification hardening (follow-up audit)

- A graph witness must be a SHA-256-derived canonical edge id and must belong
  to the *specific resource* under evaluation: IAM source role/user, EKS target
  role or cluster, S3 bucket/access point, KMS key, or Lambda function.
  A valid edge attached to an unrelated resource, or a tampered detail field,
  remains `UNKNOWN` for that resource's mandatory evidence predicate.
- EKS modal counts now distinguish **retained association summaries**,
  **successfully described associations** and **unresolved associations**;
  partial evidence must not be labelled as successfully described.

- IAM role trust grants for `sts:AssumeRole` and `sts:TagSession` may be
  provided by two separate unconditional `Allow` statements. Both are
  independently checked, with matching/uncertain explicit Deny precedence;
  unknown trust conditions remain unsupported rather than assumed true.

- Fail closed for legacy/incomplete Pod Identity records: an omitted
  `detail_collection_status` is `UNKNOWN`, never an implicit successful
  `DescribePodIdentityAssociation`.
