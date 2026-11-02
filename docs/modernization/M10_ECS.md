# M10-F — public ECS regional cluster metadata (opt-in)

The explicit `--services ecs` activates the public collector; legacy default
service behavior remains unchanged. A separately installed proprietary ECS
extension retains historical precedence. Azure/GCP are not modernized.

API permissions: `ecs:ListClusters`, `ecs:DescribeClusters`. Region discovery
may use `ec2:DescribeRegions`. The collector limits listing to 50 pages ×
100 clusters (5,000 per region) and describe batches to 100 ARNs. The SDK
will not list services, tasks, containers, task definitions or secrets;
no ExecuteCommand, writes or resource mutations.

Every region records full cluster ARN/name/status, settings, tags, run/task
counts, capacity provider strategy, ECS Exec configuration (including KMS
key and logging), and other returned operational metadata. The only rule
flags explicitly `containerInsights=disabled`. `enabled` and `enhanced`
are secure **only** for this configuration check. Missing, malformed or
unexpected settings are UNKNOWN and must not be reported as clean.

Denied/unsupported, malformed response, duplicate/foreign cluster ARN,
pagination token replay, maximum page limit, missing descriptions and
failed describe operations cause collection issues; verified results
remain intact. No conclusion is drawn about task logging, ECS Exec usage
or organization-level ECS deployment coverage.

Validate Botocore model/Stubber, pagination/limit errors, rule evidence,
HTML escaping, packaging and full offline Windows/Ubuntu preservation
before master merge. No live AWS scan or CIS compliance claim.
