"""Read-only RDS Proxy TLS audit with direct rule traversal."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from ScoutSuite.providers.aws.resources.rds.proxies import RDSProxies
from ScoutSuite.providers.aws.facade.rds import RDSFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

NAME='rds-proxy-require-tls-disabled.json'
def test_proxy_tls_status_and_rule():
    async def records(region):
        return [
            {'DBProxyArn':'arn:aws:rds:eu-central-1:123:db-proxy:proxy1',
             'DBProxyName':'test','RequireTLS':False},
            {'DBProxyArn':'arn:aws:rds:eu-central-1:123:db-proxy:proxy2',
             'DBProxyName':'safe','RequireTLS':True}]
    obj=RDSProxies.__new__(RDSProxies)
    obj.region='eu-central-1'
    obj.facade=SimpleNamespace(rds=SimpleNamespace(get_db_proxies=records))
    asyncio.run(obj.fetch_all())
    services={'rds':{'regions':{'eu-central-1':{'proxies':dict(obj)}}}}
    rule=json.loads((Path(__file__).resolve().parents[1]/
                     'ScoutSuite/providers/aws/rules/findings'/NAME).read_text())
    cfg=SimpleNamespace(filename=NAME,conditions=rule['conditions'],path=rule['path'],
                        evidence_policy=rule['evidence_policy'],checked_items=0)
    hits=recurse(services,services,cfg.path.split('.'),[],cfg,True)
    evidence=evaluate_rule_evidence(cfg,services)
    assert len(hits)==1
    assert evidence['counts']['insecure']==1
    assert evidence['counts']['secure']==1

def test_proxy_access_denied_not_empty_complete_inventory():
    facade=RDSFacade(object())
    with patch.object(AWSFacadeUtils,'get_client',return_value=None):
        result=asyncio.run(facade.get_db_proxies('eu-central-1'))
    assert result==[]
    assert facade.proxy_inventory_status['eu-central-1']=='unknown'
