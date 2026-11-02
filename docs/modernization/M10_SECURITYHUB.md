# M10-C — public Security Hub regional inventory (default AWS scan)

The ordinary AWS scan enables this read-only slice automatically. Exclude it
with `--skip-services securityhub`. It does not access findings, account/member
lists, policies, controls or organization configuration.

## APIs and completeness

Regional permissions: `securityhub:DescribeHub`,
`securityhub:GetEnabledStandards`. Existing region selection may request
`ec2:DescribeRegions`. At most 500 pages/25,000 standards per region are accepted as a safety
budget (the previous 10-page/500-subscription cap could omit inventories). AWS SDK retries/timeouts and per-run contexts are
unchanged. A subscribed hub is stored at
`services.securityhub.regions.<region>.hubs.<stable-id>`, with normalized
`standards` entries under the hub and a verified
`standards_inventory_complete` boolean. Subscription ARN, full
standards ARN, status and reason, control updatability and provider
are preserved for remediation.

Denied, unsupported, missing hub, malformed payloads, duplicate subscription
ARNs, cycles in pagination and exceeded limits are **not** reported as clean
coverage. A confirmed unsubscribed Region (DescribeHub
`ResourceNotFoundException`, or `InvalidAccessException` with the exact
service message "Account <id> is not subscribed to AWS Security Hub [CSPM]",
which is what AWS returns in practice) is negative evidence reported by
`securityhub-region-not-subscribed`, not a collection issue (RC5, RC8). Any
other `InvalidAccessException` or denial stays UNKNOWN. A failed standards
request produces a partial hub with `standards_inventory_complete=false`.

The only warning flags a confirmed `FAILED` or `INCOMPLETE` standard
subscription state; `READY` is healthy **for this status check only**,
other/missing states are unknown. A zero-subscription hub gets no "secure"
finding. No organization-wide assessment, Security Hub CSPM compliance
certification, or CIS benchmark mapping is asserted.

## Tests and rollback

Synthetic SDK model/Stubber, pagination, denied, malformed, duplicate,
status evidence, rule processing, catalog, HTML escaping, and installed
wheel/sdist tests. Existing Azure/GCP preservation gates remain mandatory.
Live AWS execution is out of scope.

Revert the M10-C changes or use `--skip-services securityhub`
to avoid all newly introduced collection calls.
