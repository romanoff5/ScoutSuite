"""Region-level RDS DB clusters, including Aurora and Multi-AZ clusters.

Read-only DescribeDBClusters inventory. Customer identifiers remain in the
private report for remediation; CI uses only synthetic identifiers.
"""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class RDSClusters(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        try:
            clusters = await AWSFacadeUtils.get_all_pages(
                'rds', self.region, self.facade.session,
                'describe_db_clusters', 'DBClusters')
        except Exception:
            # Denials, malformed responses and transport failures are not
            # evidence that the region contains zero DB clusters.
            self._issue('DescribeDBClustersIncomplete')
            return
        if not isinstance(clusters, list):
            self._issue('MalformedDBClusterInventory')
            return
        for raw in clusters:
            if not isinstance(raw, dict):
                self._issue('MalformedDBCluster')
                continue
            identifier = raw.get('DBClusterIdentifier')
            if not isinstance(identifier, str) or not identifier:
                self._issue('MalformedDBCluster')
                continue
            key = get_non_provider_id(identifier)
            if key in self:
                self._issue('DuplicateDBCluster')
                continue
            self[key] = {
                'id': key,
                'name': identifier,
                'DBClusterIdentifier': identifier,
                'DBClusterArn': raw.get('DBClusterArn'),
                'Engine': raw.get('Engine'),
                'Status': raw.get('Status'),
                'DeletionProtection': raw.get('DeletionProtection'),
                'DBClusterMembers': [
                    item.get('DBInstanceIdentifier')
                    for item in (raw.get('DBClusterMembers') or [])
                    if isinstance(item, dict) and isinstance(item.get('DBInstanceIdentifier'), str)
                ] if isinstance(raw.get('DBClusterMembers'), list) else [],
            }
            if (raw.get('DBClusterMembers') is not None
                    and not isinstance(raw['DBClusterMembers'], list)):
                self._issue('MalformedDBClusterMembers')

    @staticmethod
    def _issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'rds', reason)
