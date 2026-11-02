# M10-G — EKS regional cluster inventory (default AWS scan)

EKS is included in the standard AWS scan without `--services`. The optional
private-provider integration is preserved. No calls to
Kubernetes API or task/Pod data are made. AWS/Azure/GCP preservation required.

AWS actions: `eks:ListClusters`, `eks:DescribeCluster`, plus pre-existing
`ec2:DescribeRegions` for optional region discovery. List up to 20 pages of
100 names, cap at 1,000 clusters/region, describe one by one. Invalid lists,
repeated tokens or names, missing details, cross-account/region ARNs and
access denial are recorded as incomplete. No writes, credential requests,
ExecCommand, secrets or cluster access tokens.

Report includes full cluster ARN/name/version/status, endpoint, IAM role,
VPC endpoint access modes and CIDRs, tags, logging, encryption, access and
upgrade configuration, plus health/deletion protection when returned.
No user-controlled values are truncated or inserted into HTML unescaped.

The rule `eks-public-api-unrestricted` flags **only** an explicitly public
cluster endpoint whose returned CIDR list contains `0.0.0.0/0` or `::/0`.
A disabled public endpoint is secure *for this narrow check*; a public
endpoint with restricted CIDRs is secure for unrestricted reachability.
Missing/malformed CIDRs or endpoint state are UNKNOWN, not secure.
The rule makes no claim about authentication, RBAC, secrets, kube-audit
logging, node groups or workload vulnerabilities.

The contract requires synthetic Botocore Stubber, pagination/error, evidence
and report tests, installed wheel/sdist, offline Windows and Ubuntu CI.
No live AWS scan or CIS compliance scoring. Revert the slice to roll back.

## M10-H control-plane audit logging

Existing `eks:DescribeCluster` response includes
`logging.clusterLogging`. A single explicit `audit` observation with
`enabled=false` is a warning; `enabled=true` is a pass only for this
configuration check. Missing, malformed or conflicting audit settings
remain unknown. This does not verify CloudWatch retention, SIEM forwarding,
or log delivery.
