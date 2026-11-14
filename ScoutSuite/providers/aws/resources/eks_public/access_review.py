"""Conservative EKS Access Entry analysis (not a Kubernetes RBAC census)."""

CLUSTER_ADMIN_POLICY = 'AmazonEKSClusterAdminPolicy'
CLUSTER_WIDE_ADMIN_POLICY = 'AmazonEKSAdminPolicy'


def classify_eks_cluster_admin(policies, collection_status):
    if collection_status != 'complete' or not isinstance(policies, list):
        return 'unknown'
    observed = set()
    for row in policies:
        if not isinstance(row, dict):
            return 'unknown'
        arn, scope = row.get('policy_arn'), row.get('scope')
        if not isinstance(arn, str) or scope not in ('cluster', 'namespace'):
            return 'unknown'
        # EKS-managed AWS predefined policies only; never infer privileges
        # from arbitrary third-party policy ARNs with similar suffixes.
        parts = arn.split(':', 5)
        if (len(parts) != 6 or parts[0] != 'arn' or not parts[1].startswith('aws')
                or parts[2] != 'eks' or parts[3] or parts[4] != 'aws'
                or not parts[5].startswith('cluster-access-policy/')):
            continue
        if scope == 'cluster':
            observed.add(parts[5].split('/', 1)[1])
    if CLUSTER_ADMIN_POLICY in observed:
        return 'cluster_admin'
    if CLUSTER_WIDE_ADMIN_POLICY in observed:
        return 'admin'
    # No explicit EKS-managed admin policy found; other Kubernetes grants
    # (ConfigMap/RBAC groups/creator) remain outside this check.
    return 'not_detected'
