"""Normalize Kubernetes API endpoint exposure without guessing CIDRs."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id
from .access_review import classify_eks_cluster_admin


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
        await self._enrich_access()


    async def _enrich_access(self):
        """Record only EKS API-issued permissions; never infer complete Kubernetes RBAC."""
        import asyncio
        gate = asyncio.Semaphore(4)
        async def enrich(cluster):
            mode = cluster.get('access_config', {}).get('authenticationMode')
            method = getattr(self.facade.eks, 'get_access_entries', None)
            if method is None:
                result = {'status': 'unknown', 'entries': []}
            else:
                async with gate:
                    try:
                        result = await method(self.region, cluster['name'], mode)
                    except Exception:
                        context = get_current_run_context()
                        if context is not None:
                            context.record_collection_issue(
                                'partial', 'eks', 'EKSAccessEntriesEnrichmentFailed')
                        result = {'status': 'unknown', 'entries': []}
            cluster['access_entry_inventory_status'] = result.get('status', 'unknown')
            cluster['access_authentication_mode'] = mode
            mapped = {}
            partial = result.get('status') not in ('complete', 'not_applicable')
            for row in result.get('entries', []):
                principal = row.get('principal_arn') if isinstance(row, dict) else None
                if not isinstance(principal, str) or not principal or get_non_provider_id(principal) in mapped:
                    partial = True
                    continue
                key = get_non_provider_id(principal)
                policies = row.get('policies')
                policy_status = row.get('policy_collection_status')
                permission = classify_eks_cluster_admin(policies, policy_status)
                mapped[key] = {
                    'id': key, 'name': principal, 'principal_arn': principal,
                    'region': self.region, 'cluster': cluster['name'],
                    'policy_collection_status': policy_status,
                    'admin_grant_status': permission, 'policies': policies,
                }
            if partial and result.get('status') == 'complete':
                cluster['access_entry_inventory_status'] = 'partial'
            cluster['access_entries'] = mapped
            cluster['access_entries_count'] = len(mapped)

        await asyncio.gather(*(enrich(c) for c in self.values()))

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
        logging = raw.get('logging')
        entries = logging.get('clusterLogging') if isinstance(logging, dict) else None
        audit_values = [
            entry.get('enabled') for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get('types'), list)
            and 'audit' in entry['types']
        ] if isinstance(entries, list) else []
        audit_enabled = (
            audit_values[0] if len(audit_values) == 1
            and isinstance(audit_values[0], bool) else None)
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
            'audit_logging_enabled': audit_enabled,
            'audit_logging_disabled': audit_enabled is False,
            'encryption_config': raw.get('encryptionConfig') or [],
            'access_config': raw.get('accessConfig') or {},
            'upgrade_policy': raw.get('upgradePolicy') or {},
            'tags': raw.get('tags') or {},
            'health': raw.get('health') or {},
            'deletion_protection': raw.get('deletionProtection'),
        }
