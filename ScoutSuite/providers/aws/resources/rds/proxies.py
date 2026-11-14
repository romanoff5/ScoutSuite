"""Regional RDS Proxy configuration and complete target health evidence (read-only)."""
import asyncio

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id
from .proxy_health import classify_proxy_targets, summarize_proxy_targets


class RDSProxies(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    @staticmethod
    def _issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'rds', reason)

    async def fetch_all(self):
        records = await self.facade.rds.get_db_proxies(self.region)
        gate = asyncio.Semaphore(4)

        async def inspect(item):
            if not isinstance(item, dict):
                return item, {'status': 'unknown', 'targets': []}
            method = getattr(self.facade.rds, 'get_db_proxy_targets', None)
            name = item.get('DBProxyName')
            if method is None or not isinstance(name, str) or not name:
                return item, {'status': 'unknown', 'targets': []}
            async with gate:
                try:
                    return item, await method(self.region, name)
                except Exception:
                    self._issue('DescribeDBProxyTargetsUncaughtException')
                    return item, {'status': 'unknown', 'targets': []}

        for item, collection in await asyncio.gather(*(inspect(row) for row in records)):
            arn = item.get('DBProxyArn') if isinstance(item, dict) else None
            if not isinstance(arn, str) or not arn.startswith('arn:'):
                self._issue('MalformedDBProxy')
                continue
            key = get_non_provider_id(arn)
            if key in self:
                self._issue('DuplicateDBProxy')
                continue
            tls = item.get('RequireTLS')
            status = classify_proxy_targets(item.get('Status'), collection, None)
            if collection.get('status') != 'complete':
                self._issue('DBProxyTargetInventoryIncomplete')
            self[key] = {
                'id': key, 'name': item.get('DBProxyName') or arn,
                'DBProxyArn': arn, 'DBProxyName': item.get('DBProxyName'),
                'RequireTLS': tls if isinstance(tls, bool) else None,
                'tls_status': 'disabled' if tls is False else
                              'enforced' if tls is True else 'unknown',
                'Status': item.get('Status'),
                'EngineFamily': item.get('EngineFamily'),
                'VpcId': item.get('VpcId'), 'region': self.region,
                'target_collection_status': collection.get('status', 'unknown'),
                'target_health_status': status,
                'targets_count': len(collection.get('targets', [])),
                'targets': summarize_proxy_targets(collection),
            }
