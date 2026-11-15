# P5 Phase 3 — selective CloudGoat / CloudFoxable mapping

**Status: static, source-anchored offline regression, not a deployed AWS lab.**
These tests consume normalized, independently constructed AWS-shaped semantic
facts derived from upstream public Terraform. They do not call AWS APIs,
provision resources, use AWS credentials, exploit roles, or demonstrate
effective permissions. The real cloud/field validation below remains optional
and **has not been executed** in CI. Exact report ARN/account IDs are kept in
normal reports; the tests use artificial account IDs only.

## Upstream pin (auditable provenance)

- CloudGoat (RhinoSecurityLabs), commit
  `63c65bd26edc6919499adfa20b176c450e35c33c`:
  [lambda_privesc IAM](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/cloudgoat/scenarios/aws/lambda_privesc/terraform/iam.tf),
  [iam_privesc_by_attachment IAM](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/cloudgoat/scenarios/aws/iam_privesc_by_attachment/terraform/iam.tf),
  [mighty role](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/cloudgoat/scenarios/aws/iam_privesc_by_attachment/terraform/iam_mighty.tf),
  [meek profile](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/cloudgoat/scenarios/aws/iam_privesc_by_attachment/terraform/iam_meek.tf),
  [ecs_privesc_evade_protection IAM](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/cloudgoat/scenarios/aws/ecs_privesc_evade_protection/terraform/iam.tf).
- CloudFoxable (BishopFox), commit
  `fc49b7f637268031515ced9fee4b643d3e68db67`:
  [Trust me OIDC Terraform](https://github.com/BishopFox/cloudfoxable/blob/fc49b7f637268031515ced9fee4b643d3e68db67/aws/challenges/Trust%20me/trust-me.tf).

Pinned sources document actual scenario semantics, not an instruction to run
their attack steps. A simplified policy used below is marked explicitly where
the source uses an AWS managed policy.

## Coverage matrix (tested)

| Lab source | Correlation | Offline oracle / boundary |
| --- | --- | --- |
| CloudGoat lambda_privesc | AssumeRole manager -> PassRole -> Lambda create/invoke -> debug role | **POTENTIAL**, never verified execution. The chain starts at the manager role in P5-D; the preceding Chris AssumeRole hop is separate. Synthetic broad-allow policy stands in for debug's managed AdministratorAccess, with production admin inference. |
| CloudGoat iam_privesc_by_attachment | PassRole, RunInstances, *observed occupied* meek profile, RemoveRoleFromInstanceProfile and AddRoleToInstanceProfile -> mighty EC2 role | **POTENTIAL** `iam_ec2_profile_mutation`. Nine single-condition adversarial mutations must suppress this candidate. This distinct route was absent in the prior P5-D graph. |
| CloudGoat ecs_privesc_evade_protection | PassRole -> ECS taskRole -> RunTask | Separate synthetic **admin-like ECS analogue** verifies detector wiring. Moving target to ECS executionRole must produce **REVIEW only**, never a container escalation candidate. |
| CloudGoat ECS *actual* s3-critical | AmazonS3FullAccess, not AdministratorAccess | **Known P5-D target-classification gap**: current graph targets only `admin_policy_candidate`, so this real data-access path is **not covered by positive P5-D escalation detection**. The regression explicitly asserts incomplete/unknown inventory when the managed policy document is missing; it does not invent admin privilege. |
| CloudFoxable Trust me | GitHub OIDC provider, `repo:owner/repo:*` subject and audience | P4-B relationship graph marks `review_wildcard`; changing only the subject to an exact branch produces `scoped_subject`. This GitHub OIDC path is **not EKS IRSA**, and does not prove a runnable GitHub workflow can assume the role. |
| Supplemental S3 (independent of above labs) | Explicit external GetObject under prefix | Positive/explicit Deny/condition/API denied assertions. No inferred remote IAM grant or object existence. |
| Supplemental KMS (independent of above labs) | Explicit cross-account customer-managed key policy | Positive/explicit Deny/encryption-context/API denied assertions. Newly enforced: no policy candidate if GetKeyPolicy was not completely collected, and no grant candidate if ListGrants incomplete. |

The supplemental S3 and KMS cases are **not claimed to occur in the selected
upstream Terraform**. They are synthetic negative-boundary regressions for
requested high-risk correlation classes.

All tests are automatically collected by the existing offline `tests` gate:

    python -m pytest -q tests/test_p5_phase3_lab_cases.py

They run alongside Phase-1 53-fixture graph checks and Phase-2 mandatory
SQLite -> loopback HTTP -> HTML browser integration. No Docker dependency is
needed for correctness checks.

## Opt-in **real AWS** field validation protocol (not run)

Use a **dedicated, disposable AWS account** that does not contain corporate
data, production connectivity or unrelated resources. Run only a small set of
the upstream scenarios; the full CloudFoxable environment is not required.
Set AWS Budgets and review the selected Terraform plan for costly resources,
external/public access and IAM trust before provisioning. Do not expose
long-lived credentials to a shared Docker socket, GitHub Actions secrets
or test logs. Collect read-only scanner data only.

Suggested sequence and priority:
1. **CloudGoat `lambda_privesc`**: low infrastructure footprint; compare
   caller->manager AssumeRole evidence and manager->Lambda privileged role
   candidate. Never infer the first hop from an unattested principal.
2. **CloudGoat `iam_privesc_by_attachment`**: review IAM profile mutation
   candidate; EC2 instances/VPC/resources can incur charges. Validate
   occupancy and mutator permissions separately from a successful launch.
3. **CloudGoat `ecs_privesc_evade_protection`**: more expensive/complex;
   requires Docker/ECR and running compute; defer until cheaper scenarios pass.
   Record the non-admin `AmazonS3FullAccess` target gap as a known FN
   against a data-access-oriented oracle.
4. **CloudFoxable `Trust me`**: intentionally scoped GitHub OIDC trust;
   enable only that challenge and inspect exact audience/subject and trust
   precedence. A real private repo and separate setup are required.
5. **S3 and KMS**: run in separately created disposable read-only test
   fixtures using explicit test principals and resource policies; never
   assert CloudGoat/CloudFoxable coverage unless the upstream scenario
   actually contains the relevant resource-policy grant. No external account
   access or KMS Decrypt should be attempted by the regression harness.
6. **EKS Pod Identity**: deferred. Continue deterministic List->Describe and
   trust-condition tests; no paid EKS cluster is necessary for this phase.

For each authorized scan, record: upstream commit, Terraform plan digest,
account/Region, selected services, API collection outcomes (including
AccessDenied), expected source/target/action, graph edge ID, finding ID,
verification, confidence, evidence, SQLite persistence and browser card.
Distinguish **detection** from **effective authorization** and preserve
`UNKNOWN` for uncollected API or insufficient external trust information.

Destroy only lab-created resources per upstream instructions, then verify the
AWS console/CloudTrail and billing inventory for stragglers, instance
profiles, ECR images, log groups, S3 objects and manually created resources.
CloudGoat explicitly warns that its destroy command does not remove arbitrary
resources created manually during exploitation.

## Exit criteria for claiming field validation

The static source-mapped tests passing is a *necessary but not sufficient*
regression gate. Actual field validation requires separately provisioned
AWS assets and an audited scanner run, with positive and negative ground
truth per case. Claims of real-world precision/recall, effective PassRole,
successful EC2/Lambda/ECS execution or live EKS authorization are prohibited
without this evidence.
