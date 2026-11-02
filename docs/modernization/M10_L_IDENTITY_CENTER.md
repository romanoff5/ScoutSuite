# M10-L — AWS IAM Identity Center

Implementation scope: read-only identity and AWS-account assignment inspection.
Included in the default AWS scan as `identitycenter`, selectable with
`--services identitycenter` or excludable through `--skip-services identitycenter`.
No dedicated M10 scan mode and no changes to Azure/GCP collectors.

## Collection and displayed evidence

- Regional `sso-admin:ListInstances`: instance ARN/name/status, Identity Store ID,
  owner account ID, region, creation time.
- `ListPermissionSets` / `DescribePermissionSet`: ARN, name, description,
  created date, session duration, relay state.
- `ListManagedPoliciesInPermissionSet`: complete policy names and ARNs.
- `ListCustomerManagedPolicyReferencesInPermissionSet`: complete policy
  reference names/paths; **not** customer-managed policy contents.
- `GetInlinePolicyForPermissionSet`: original JSON string plus parsed object.
  This is policy metadata; no runtime user-generated content is retrieved.
- `GetPermissionsBoundaryForPermissionSet`: policy ARN or customer-managed
  policy reference (or absent boundary).
- `ListAccountsForProvisionedPermissionSet` and `ListAccountAssignments`:
  account IDs, instance/permission-set ARNs, USER/GROUP principal identifiers.
- `identitystore:ListUsers`, `ListGroups`, `ListGroupMemberships`:
  original principal IDs, user/display names, available email addresses,
  primary email, group membership IDs and user IDs, group member email addresses
  and external identity references.
- AWS Organizations `DescribeOrganization`, `ListAccounts` (and `ListRoots`
  by reuse of the existing Organizations inventory adapter): management
  account, current account, organization ID, enumerated account names,
  contact email addresses, ARNs and state.

All API calls are read-only. Permission-policy names, full ARNs, user IDs,
account contacts and emails are preserved because they identify remediation
owners. No authentication tokens, secret values or passwords are collected.

## Security logic and limitations

1. **Administrative candidate:** AWS `AdministratorAccess` managed policy,
   or an inline Allow `Action: "*"` with a wildcard resource and no condition.
2. **Broad permission candidate:** AWS PowerUserAccess/IAMFullAccess or other
   service-wide wildcards / allow-NotAction. This is a review signal.
3. **Cross-account administrative candidate:** a user or group granted an
   administrative candidate in at least two AWS accounts; user membership
   can link administrator assignments across different groups.

These are static candidates, **not simulated effective permissions**.
AWS Organizations SCPs/RCPs, resource policies, deny statements, permissions
boundaries, delegated administration and customer-managed policy documents may
affect effective access. No absence of a candidate is presented as a proof
that a permission set is least privilege.

Failures in account enumeration, permission sets, policy reads, memberships,
assignments, pagination, region discovery, client construction or malformed
responses must emit collection issues. Successfully collected pages are retained
with `partial` status. Repeated tokens and page limits (10,000 pages per
operation) mark collection incomplete. Region/instance/permission-set status
is preserved separately from findings. An AWS Organizations management-account
match **and** full account roster are required before labeling management
scope complete; a member or delegated admin without those signals remains
`partial`. This is a management-account-visible IAM Identity Center scan;
it does not assume cross-account credentials or inspect all member account
resources. Unknown users, group members or account IDs never become PASS.

## Testing, rollback and permissions

Offline tests: `tests/test_m10_identitycenter.py` and
`tests/test_m10_default_services.py`; check SDK shapes, Stubber pagination,
read-only API dispatch, user emails, malformed/denied partial collection,
organization scope and finding classification. Report partials use escaped
Handlebars substitutions, with no unescaped HTML/JS insertion.

IAM read permissions required, scoped to the expected instance/store where
supported: `sso:ListInstances`, `sso:ListPermissionSets`,
`sso:DescribePermissionSet`,
`sso:ListManagedPoliciesInPermissionSet`,
`sso:ListCustomerManagedPolicyReferencesInPermissionSet`,
`sso:GetInlinePolicyForPermissionSet`,
`sso:GetPermissionsBoundaryForPermissionSet`,
`sso:ListAccountsForProvisionedPermissionSet`,
`sso:ListAccountAssignments`, `identitystore:ListUsers`,
`identitystore:ListGroups`, `identitystore:ListGroupMemberships`,
`organizations:DescribeOrganization`, `organizations:ListAccounts`,
`organizations:ListRoots`. Denied operations are reported, not concealed.

Rollback: omit with `--skip-services identitycenter`, or revert the
M10-L commits. Historical report payloads are untouched. Existing saved
reports without the service remain valid.
