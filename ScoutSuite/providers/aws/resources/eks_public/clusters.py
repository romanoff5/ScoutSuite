"""Normalize Kubernetes API endpoint exposure without guessing CIDRs."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Clusters(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw in await self.facade.eks.get_clusters(self.region):
            parsed = self._parse_cluster(raw)
            if parsed is None:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'eks', 'InvalidCluster')
                continue
            key, value = parsed
            if key in self:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'eks', 'DuplicateClusterKey')
                continue
            self[key] = value

    def _parse_cluster(self, raw):
        if not isinstance(raw, dict):
            return None
        arn, name = raw.get('arn'), raw.get('name')
        if (not isinstance(arn, str) or not arn.startswith('arn:')
                or not isinstance(name, str) or not name):
            return None
        vpc = raw.get('resourcesVpcConfig')
        vpc = vpc if isinstance(vpc, dict) else {}
        public = vpc.get('endpointPublicAccess')
        cidrs = vpc.get('publicAccessCidrs')
        cidrs = cidrs if isinstance(cidrs, list) and all(
            isinstance(value, str) for value in cidrs) else None
        unrestricted = public is True and cidrs is not None and any(
            value in ('0.0.0.0/0', '::/0') for value in cidrs)
        created = raw.get('createdAt')
        if hasattr(created, 'isoformat'):
            created = created.isoformat()
        key = get_non_provider_id(arn)
        return key, {
            'id': key, 'name': name, 'cluster_arn': arn, 'region': self.region,
            'status': raw.get('status'), 'version': raw.get('version'),
            'platform_version': raw.get('platformVersion'),
            'created_at': created, 'endpoint': raw.get('endpoint'),
            'cluster_role_arn': raw.get('roleArn'),
            'public_endpoint_access': public,
            'private_endpoint_access': vpc.get('endpointPrivateAccess'),
            'public_access_cidrs': cidrs,
            'public_endpoint_unrestricted': unrestricted,
            'resources_vpc_config': vpc,
            'logging': raw.get('logging') or {},
            'encryption_config': raw.get('encryptionConfig') or [],
            'access_config': raw.get('accessConfig') or {},
            'upgrade_policy': raw.get('upgradePolicy') or {},
            'tags': raw.get('tags') or {},
            'health': raw.get('health') or {},
            'deletion_protection': raw.get('deletionProtection'),
        }
