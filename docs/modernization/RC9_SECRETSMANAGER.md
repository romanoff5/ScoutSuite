# RC9: Secrets Manager metadata and rules

Before RC9 the Secrets Manager service collected secrets but had no rules, so
the dashboard showed it as "Not assessed". Listing, detail and policy failures
were printed and swallowed: a denied `GetResourcePolicy` produced an empty
policy that looked like "no policy".

## API/permission contract

Regional, read-only metadata APIs only:

- `secretsmanager:ListSecrets` with `IncludePlannedDeletion=true`. The paging
  limit is 5,000 pages of 100, which covers the default quota of 500,000
  secrets per Region. Hitting the limit records `partial/PageLimit`.
- `secretsmanager:DescribeSecret` for each secret.
- `secretsmanager:GetResourcePolicy` for each secret.

`GetSecretValue` and `BatchGetSecretValue` are never called. The strict
Stubber tests fail on any unqueued operation, and a source assertion guards
against either name. Secret values therefore cannot reach the report.

## Collected, normalized and displayed fields

`secretsmanager.regions.<region>.secrets.<id>` keeps these SDK fields:

- Identity and description: `arn`, `name`, `description`.
- Dates: `created_date`, `last_changed_date`, `last_accessed_date`,
  `last_rotated_date`, `next_rotation_date`, `deleted_date`.
- Ownership and replication: `owning_service`, `primary_region`,
  `replication_status`, `tags`.
- Versions: `secret_versions_to_stages`, which holds version IDs and stage
  labels only.
- Encryption: `kms` (the original `KmsKeyId`).
- Rotation: `rotation_enabled` (the original value), `rotation_lambda_arn`,
  `rotation_interval`, `rotation_schedule`, `rotation_window`.
- `policy`: the full resource policy document.

Additive derived fields:

| Field | Values |
|---|---|
| `details_status` | `complete`, `unknown` (DescribeSecret failed) |
| `kms_key_type` | `aws_managed`, `customer_managed` |
| `rotation_status` | `enabled`, `disabled`, `unknown`, `scheduled_for_deletion` |
| `unused_status` | `in_use`, `unused`, `recently_created`, `unknown`, `scheduled_for_deletion` |
| `days_since_last_access`, `unused_threshold_days` | integers (threshold 90) |
| `policy_status` | `present`, `none`, `unknown` (denied or malformed) |
| `policy_exposure` | `none`, `private`, `conditional`, `cross_account`, `public`, `unknown` |
| `policy_external_principals` | principal strings outside the owning account |

The legacy boolean `rotation` is kept for compatibility. It is now `true` only
when rotation is verified as enabled.

`DescribeSecret` omits `RotationEnabled` when rotation was never configured,
so its absence counts as `disabled` only when `DescribeSecret` succeeded.
Otherwise it is `unknown`. AWS also omits `LastAccessedDate` for a secret
never retrieved in the Region; such a secret counts as `unused` only when
`DescribeSecret` succeeded and it is older than 90 days.

Policy exposure rules:

- An Allow to `*`, or with `NotPrincipal`, is `public`, unless a condition
  binds callers with one of these keys: `aws:PrincipalOrgID`,
  `aws:PrincipalOrgPaths`, `aws:PrincipalAccount`, `aws:PrincipalArn`,
  `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrgID`,
  `aws:SourceOrgPaths`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:userid`. In
  that case it is `conditional`. A condition such as `aws:SecureTransport` does
  not restrict callers.
- Account roots or ARNs of other accounts make the policy `cross_account`.
- Unique-ID principals or a malformed policy make it `unknown`.

## Rules (default and detailed rulesets)

| Rule | Level | Flags | Evidence policy |
|---|---|---|---|
| `secretsmanager-secret-rotation-disabled` | warning | `rotation_status == disabled` | `secretsmanager-rotation-v1` |
| `secretsmanager-secret-unused` | warning | `unused_status == unused` | `secretsmanager-unused-v1` |
| `secretsmanager-secret-policy-public` | danger | `policy_exposure == public` | `secretsmanager-policy-public-v1` |
| `secretsmanager-secret-policy-cross-account` | warning | `policy_exposure == cross_account` | `secretsmanager-policy-cross-account-v1` |

Evidence that is unknown because of a denied or failed detail or policy read
marks the rule `incomplete`; it never counts as a pass. Each failure is
recorded with the reason code `<Operation>AccessDenied` or `<Operation>Error`,
plus `MalformedSecretList`, `MalformedSecret`, `InvalidPaginationToken` or
`MalformedResourcePolicy` where those apply. SDK messages are never stored.

## Compatibility and rollback

Fields are additive, and existing field names keep their meaning. The one
exception is `rotation`, which is no longer `false` when the evidence is
unknown. Old reports render with the new partial, but their derived fields
are empty. To roll back, revert the RC9 Secrets Manager commit. The rules are
new IDs, so no existing exception identifiers change.
