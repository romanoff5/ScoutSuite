# M10-C — public Security Hub regional inventory (opt-in)

Only explicit `--services securityhub` enables this read-only slice. It does
not change legacy default service selection and does not access findings,
account/member lists, policies, controls or organization configuration.

## APIs and completeness

Regional permissions: `securityhub:DescribeHub`,
`securityhub:GetEnabledStandards`. Existing region selection may request
`ec2:DescribeRegions`. At most 10 pages of 50 standards each (500 total)
are accepted per region. AWS SDK retries/timeouts and per-run contexts are
unchanged. A subscribed hub is stored at
`services.securityhub.regions.<region>.hubs.<stable-id>`, with normalized
`standards` entries under the hub and a verified
`standards_inventory_complete` boolean.

Denied, unsupported, missing hub, malformed payloads, duplicate subscription
ARNs, cycles in pagination and exceeded limits are **not** reported as clean
coverage. A missing subscribed hub is an explicit not-applicable collection
issue, not a false Security Hub enablement finding; a failed standards request
produces a partial hub with `standards_inventory_complete=false`.

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

Revert the M10-C changes or omit `securityhub` from `--services`
to avoid all newly introduced collection calls.
