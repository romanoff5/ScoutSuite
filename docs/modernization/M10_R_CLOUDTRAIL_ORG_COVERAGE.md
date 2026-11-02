# M10-R — CloudTrail organization-wide logging coverage

## Purpose and default operation

M10-R runs automatically during the normal AWS scan when both
\`organizations\` and \`cloudtrail\` are selected. It does not replace
CloudTrail's current trail, event-selector, status, encryption or
CloudWatch checks, and it makes no SDK calls in report postprocessing.

1. AWS Organizations supplies **all ACTIVE accounts**, with ID, Name,
   e-mail, management account and collection completeness.
2. AWS Account Management \`ListRegions\` supplies per-account
   opt-in state (\`ENABLED\`, \`ENABLED_BY_DEFAULT\`, \`ENABLING\`,
   \`DISABLING\`, \`DISABLED\`). Pagination, errors and bounds are explicit.
3. Existing CloudTrail \`DescribeTrails\`, \`GetTrailStatus\` and
   \`GetEventSelectors\` supply organization/multi-Region flags, the
   home Region, logging state, selectors and delivery errors.
4. Postprocessing produces one account-by-Region configuration matrix
   in \`organizations.accounts[account_id].m10r_cloudtrail_coverage\`.
   The same account retains its full name, e-mail and ID for remediation.
   Organization summaries appear in \`organizations.organizations\` and
   \`cloudtrail.m10r_organization_coverage\`.

### Findings and evidence semantics

- \`configured\`: organization trail configuration is sufficient to
  cover management read and write events in the account's known enabled
  Region; this is **not verified delivery**.
- \`gap\`: after complete collection, no effective organization trail
  covers the enabled Region (single-Region restriction, disabled trail,
  unsupported home Region, or restrictive management selectors).
  Rule: \`m10r-org-cloudtrail-config-gap.json\`.
- \`unknown\`: denied/partial Organizations inventory, Account Management,
  CloudTrail describe/status/selector collection, opt-in transition or
  scoped \`--regions\` census. Missing evidence does not become a PASS.
- \`not_applicable\`: disabled Region or suspended/closed account.

A management or delegated administrator can create an organization trail
that AWS replicates across all member accounts. However, **AWS may still
report delivery errors** from missing S3 bucket policy, SNS, CloudWatch
Logs or KMS permissions. Neither replication nor successful
\`GetTrailStatus\` in the management account proves that *each member*
delivered its own recent events. The scan therefore permanently reports
\`per_account_delivery_verified: false\`; actual member delivery requires
independent per-account log delivery evidence, e.g. verified recent log
files/events under the relevant account/Region with read-only permissions,
which this phase does not collect.

### Optional access and permissions

Required for full account-by-Region configuration matrix:

- \`organizations:DescribeOrganization\` and \`organizations:ListAccounts\`.
- \`cloudtrail:DescribeTrails\`, \`cloudtrail:GetTrailStatus\`,
  \`cloudtrail:GetEventSelectors\`.
- **\`account:ListRegions\`**, read-only. For cross-account \`AccountId\`,
  call from the management account or the Account Management delegated
  administrator. The organization must have all features and trusted
  access for \`account.amazonaws.com\` enabled. The management account
  must query itself without \`AccountId\`.
- If Account Management trusted access/permissions are absent, the report
  retains account and CloudTrail inventory with \`UNKNOWN\` Region status.
  No automatic write, enable-trusted-access or cross-account AssumeRole.

A restricted service selection, \`--regions\` list, incomplete
Organizations pagination, and failure to inspect the scanner account's
enabled Regions must never create a complete organization verdict.

## Validation

\`\`\`sh
python -B -m pytest -q -p no:cacheprovider tests/test_m05_cloudtrail.py tests/test_m10_organizations.py tests/test_m10_cloudtrail_org_coverage.py
python -B -m pytest -q -p no:cacheprovider
\`\`\`

All API tests use Stubber/mocks without network or credentials. Windows and
Ubuntu offline CI must pass on the final merged commit before claiming a
completed integration.

References:

- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html
- https://docs.aws.amazon.com/accounts/latest/APIReference/API_ListRegions.html
