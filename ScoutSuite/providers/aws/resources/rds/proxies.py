"""Regional RDS Proxy configuration; no database credentials or target contents."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

class RDSProxies(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region=region

    @staticmethod
    def _issue(reason):
        ctx=get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial','rds',reason)

    async def fetch_all(self):
        for item in await self.facade.rds.get_db_proxies(self.region):
            arn=item.get('DBProxyArn') if isinstance(item,dict) else None
            if not isinstance(arn,str) or not arn.startswith('arn:'):
                self._issue('MalformedDBProxy')
                continue
            key=get_non_provider_id(arn)
            if key in self:
                self._issue('DuplicateDBProxy')
                continue
            tls=item.get('RequireTLS')
            self[key]={
                'id':key,'name':item.get('DBProxyName') or arn,
                'DBProxyArn':arn,'DBProxyName':item.get('DBProxyName'),
                'RequireTLS':tls if isinstance(tls,bool) else None,
                'tls_status':'disabled' if tls is False else
                             'enforced' if tls is True else 'unknown',
                'Status':item.get('Status'),
                'EngineFamily':item.get('EngineFamily'),
                'VpcId':item.get('VpcId'),
                'region':self.region,
            }
