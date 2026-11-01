# M06-A — RDS per-session cache isolation and optional cluster fields

The original RDS facade cached DB instances, snapshots, subnet groups, and
asyncio locks at **class level**, with only the region name as a key. A
single Python process scanning two AWS accounts in the same region could
reuse the first account's resource inventory. These caches and locks are
now *instance-owned* and therefore bound to the specific facade/session.
The normalized resource schema and API calls are otherwise preserved.

`DescribeDBClusters` can omit `MultiAZ`; this does not overwrite an
existing instance's `MultiAZ` property. Removed an unused
`sts:GetCallerIdentity` call on every RDS tag lookup. Legacy Classic
resources remain represented via the existing `EC2-Classic` value,
without inferring a VPC from absent API fields.

IAM permission change: **none** (one redundant STS call removed).
Offline tests verify two accounts, repeat same-account cache hits, and
snapshot/subnet cache isolation. Azure/GCP components unchanged.
