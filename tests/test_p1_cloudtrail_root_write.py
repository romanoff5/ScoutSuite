"""P1 regional root management write observations from read-only Event History."""
import asyncio
import json
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from ScoutSuite.providers.aws.facade.cloudtrail import CloudTrailFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.resources.cloudtrail.root_write_events import RootWriteEvents

REGION='eu-central-1'

def event(identity='Root', readonly=False):
    return {'EventId':'id-1','EventName':'UpdateWebACL',
            'EventSource':'wafv2.amazonaws.com',
            'EventTime':datetime.now(timezone.utc),
            'CloudTrailEvent':json.dumps({'userIdentity':{'type':identity},
                                          'readOnly':readonly})}
def test_lookupevents_root_write_filtered_without_raw_json_retention():
    cli=SimpleNamespace(lookup_events=lambda **kw:{'Events':[event(),event('IAMUser'),event('Root',True)]})
    with patch.object(AWSFacadeUtils,'get_client',return_value=cli):
        facade=CloudTrailFacade(object())
        rows=asyncio.run(facade.get_recent_root_write_events(REGION))
    assert len(rows)==1 and rows[0]['event_name']=='UpdateWebACL'
    assert 'CloudTrailEvent' not in rows[0]
    assert facade.root_history_status[REGION]=='complete'
    root=RootWriteEvents.__new__(RootWriteEvents)
    root.facade=SimpleNamespace(cloudtrail=SimpleNamespace(
        get_recent_root_write_events=lambda region: None))
    async def fetch(region):return rows
    root.facade.cloudtrail.get_recent_root_write_events=fetch
    root.region=REGION
    asyncio.run(root.fetch_all())
    rule=json.loads((Path(__file__).resolve().parents[1]/
        'ScoutSuite/providers/aws/rules/findings/cloudtrail-root-management-write-recent.json').read_text())
    c=SimpleNamespace(filename='cloudtrail-root-management-write-recent.json',path=rule['path'],
                      conditions=rule['conditions'],evidence_policy=rule['evidence_policy'],checked_items=0)
    services={'cloudtrail':{'regions':{REGION:{'root_write_events':dict(root)}}}}
    assert len(recurse(services,services,c.path.split('.'),[],c,True))==1
    assert evaluate_rule_evidence(c,services)['counts']['insecure']==1

def test_root_event_history_failure_cannot_appear_complete():
    cli=SimpleNamespace(lookup_events=lambda **kw: (_ for _ in ()).throw(PermissionError('denied')))
    with patch.object(AWSFacadeUtils,'get_client',return_value=cli):
        facade=CloudTrailFacade(object())
        assert asyncio.run(facade.get_recent_root_write_events(REGION))==[]
    assert facade.root_history_status[REGION]=='unknown'
