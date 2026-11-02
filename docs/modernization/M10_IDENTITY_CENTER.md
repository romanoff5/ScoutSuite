# M10-L — IAM Identity Center / AWS account assignment coverage

The `identitycenter` service is included in ordinary `scout aws`
selection, and can be explicitly selected or skipped. This is a
**read-only, region-scoped inventory** of visible IAM Identity Center
instances, permission sets, provisioned AWS accounts and user/group
assignments, with direct group membership expansion.

## Required AWS read-only actions

`sso:ListInstances`, `sso:ListPermissionSets`,
`sso:DescribePermissionSet`,
`sso:ListManagedPoliciesInPermissionSet`,
`sso:ListCustomerManagedPolicyReferencesInPermissionSet`,
`sso:GetInlinePolicyForPermissionSet`,
`sso:GetPermissionsBoundaryForPermissionSet`,
`sso:ListAccountsForProvisionedPermissionSet`,
`sso:ListAccountAssignments`,
`identitystore:DescribeUser`, `identitystore:DescribeGroup`,
`identitystore:ListGroupMemberships`.

Access must be delegated at the IAM Identity Center instance/identity-store
level: generic `SecurityAudit` permissions cannot be assumed to grant
organization-level visibility. Only instances visible to the caller in the
selected regions can be enumerated. The absence of instances never proves
that no organization-wide IAM Identity Center deployment exists.

## Diagnostic/report data

Full instance, permission set, account and identity store IDs; user/group and direct
membership ARNs, identity revisions, membership IDs; instance name,
status/reason, creation date, permission-set name/description/session length,
AWS-managed policy ARNs, customer-managed policy references, inline-policy
presence, permissions boundary, provisioned account IDs, assignment identities,
user names, email addresses, external IDs, direct group members and their
emails. The local JSON/SQLite report retains all necessary IDs; the offline
HTML template HTML-escapes untrusted strings.

Inline policy text is **not** stored because the free-form policy document
could contain secrets; absence/presence is recorded instead. The assessment
must not claim full effective-permission analysis or complete privilege
coverage from this limited policy metadata. No user attributes unrelated to
access investigation, credentials, tokens, SCIM synchronization secrets,
authentication events or sensitive application data are collected.

## Limits, interpretation and rollback

List calls use 100 records per page, up to 1000 pages / 100,000 entries per
enumeration; SDK calls are awaited sequentially and wrapped in the existing
run-concurrency mechanism. Bad pages, limits, repeated tokens, access denied,
missing principals, unresolvable memberships, unsupported APIs and permission
set/account mismatches produce explicit collection issues and/or incomplete
flags. Unknown permissions are not considered safe.

`identitycenter-aws-admin-policy-assignment` flags only **positively
observed assignments** where the permission set references the exact
AWS-managed `AdministratorAccess` policy. Other assignments are not proven
least-privilege, and additional inline/customer-managed policy permissions
are not classified by this rule. SCPs, permission boundaries and session
restrictions may reduce effective AWS permissions; the rule is an actionable
review warning, not definitive privilege escalation.

Run synthetic botocore/strict mock tests and complete AWS/Azure/GCP
offline, Windows/Ubuntu, JSON/SQLite and browser/security gates.
No live AWS account or customer identity data is assessed in CI. Rollback
by reverting the additive M10-L change or excluding
`--skip-services identitycenter`.

## Integrated verification

The merged build passed offline CI on both Ubuntu and Windows:
https://github.com/romanoff5/ScoutSuite/actions/runs/41422635182.
The integration commit is f11f1d8777ec55e71f782a0c022489875d9852aa.
No live AWS access was used.
