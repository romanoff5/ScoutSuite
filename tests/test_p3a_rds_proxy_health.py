"""P3-A read-only source-to-finding tests using production Scout Suite rule traversal."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils

ROOT = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'


def rule_result(filename, services):
    raw = json.loads((ROOT / filename).read_text(encoding='utf-8'))
    rule = SimpleNamespace(filename=filename, path=raw['path'],
                           conditions=raw['conditions'],
                           evidence_policy=raw['evidence_policy'],
                           checked_items=0)
    hits = recurse(services, services, rule.path.split('.'), [], rule, True)
    return hits, evaluate_rule_evidence(rule, services)

from ScoutSuite.providers.aws.facade.rds import RDSFacade
from ScoutSuite.providers.aws.resources.rds.proxy_health import classify_proxy_targets
from ScoutSuite.providers.aws.resources.rds.proxies import RDSProxies


def target(state, reason=None):
    return {'TargetArn': 'arn:aws:rds:eu-central-1:123:db:one',
            'TargetHealth': {'State': state, 'Reason': reason}}


def test_rds_health_requires_complete_inventory_and_available_proxy():
    assert classify_proxy_targets('available', {'status': 'complete', 'targets': []}, None) == 'no_targets'
    assert classify_proxy_targets('available', {'status': 'partial', 'targets': []}, None) == 'unknown'
    assert classify_proxy_targets('creating', {'status': 'complete', 'targets': []}, None) == 'unknown'
    assert classify_proxy_targets('available', {'status': 'complete',
        'targets': [target('UNAVAILABLE')]}, None) == 'all_unavailable'
    assert classify_proxy_targets('available', {'status': 'complete',
        'targets': [target('AVAILABLE'), target('UNAVAILABLE')]}, None) == 'degraded'
    assert classify_proxy_targets('available', {'status': 'complete',
        'targets': [target('AVAILABLE')]}, None) == 'healthy'
    assert classify_proxy_targets('available', {'status': 'complete',
        'targets': [target('REGISTERING')]}, None) == 'transitioning'
    assert classify_proxy_targets('available', {'status': 'complete',
        'targets': [{'TargetArn': 'x'}]}, None) == 'unknown'


def test_rds_target_pagination_and_errors_preserve_uncertainty():
    calls = []
    def page(**kw):
        calls.append(kw)
        if 'Marker' not in kw:
            return {'Targets': [target('AVAILABLE')], 'Marker': 'token'}
        return {'Targets': [target('UNAVAILABLE')]}
    client = SimpleNamespace(describe_db_proxy_targets=page)
    facade = RDSFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.get_db_proxy_targets(REGION, 'app-proxy'))
    assert result['status'] == 'complete' and len(result['targets']) == 2
    assert calls[1]['Marker'] == 'token'

    def fail_second(**kw):
        if 'Marker' in kw:
            raise PermissionError('denied')
        return {'Targets': [target('AVAILABLE')], 'Marker': 'token'}
    client.describe_db_proxy_targets = fail_second
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.get_db_proxy_targets(REGION, 'app-proxy'))
    assert result['status'] == 'partial' and len(result['targets']) == 1
    assert classify_proxy_targets('available', result, None) == 'unknown'

    client.describe_db_proxy_targets = lambda **kw: {'Targets': [], 'Marker': 'cycle'}
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        result = asyncio.run(facade.get_db_proxy_targets(REGION, 'app-proxy'))
    assert result['status'] == 'partial'
    with patch.object(AWSFacadeUtils, 'get_client', return_value=None):
        result = asyncio.run(facade.get_db_proxy_targets(REGION, 'app-proxy'))
    assert result['status'] == 'unknown'


def test_rds_proxy_rule_paths_really_emit_findings():
    records = [
        {'DBProxyArn': f'arn:aws:rds:{REGION}:123:db-proxy:one',
         'DBProxyName': 'empty', 'Status': 'available', 'RequireTLS': True},
        {'DBProxyArn': f'arn:aws:rds:{REGION}:123:db-proxy:two',
         'DBProxyName': 'outage', 'Status': 'available', 'RequireTLS': True},
        {'DBProxyArn': f'arn:aws:rds:{REGION}:123:db-proxy:three',
         'DBProxyName': 'degraded', 'Status': 'available', 'RequireTLS': True}
    ]
    async def inventory(region):
        return records
    async def targets(region, name):
        states = {'empty': [], 'outage': [target('UNAVAILABLE')],
                  'degraded': [target('AVAILABLE'), target('UNAVAILABLE')]}
        return {'status': 'complete', 'targets': states[name]}
    facade = SimpleNamespace(rds=SimpleNamespace(
        get_db_proxies=inventory, get_db_proxy_targets=targets))
    resources = RDSProxies.__new__(RDSProxies)
    resources.region = REGION
    resources.facade = facade
    asyncio.run(resources.fetch_all())
    services = {'rds': {'regions': {REGION: {'proxies': dict(resources)}}}}
    for rule in ('rds-proxy-no-registered-targets.json',
                 'rds-proxy-all-targets-unavailable.json',
                 'rds-proxy-partial-target-degradation.json'):
        hits, evidence = rule_result(rule, services)
        assert len(hits) == 1
        assert evidence['counts']['insecure'] == 1
        assert evidence['counts']['unknown'] == 0


def test_rds_denied_target_listing_must_not_emit_empty_findings():
    async def inventory(region):
        return [{'DBProxyArn': 'arn:aws:rds:eu-central-1:123:db-proxy:one',
                 'DBProxyName': 'denied', 'Status': 'available'}]
    async def denied(region, name):
        return {'status': 'partial', 'targets': []}
    resources = RDSProxies.__new__(RDSProxies)
    resources.region = REGION
    resources.facade = SimpleNamespace(rds=SimpleNamespace(
        get_db_proxies=inventory, get_db_proxy_targets=denied))
    asyncio.run(resources.fetch_all())
    services = {'rds': {'regions': {REGION: {'proxies': dict(resources)}}}}
    hits, summary = rule_result('rds-proxy-no-registered-targets.json', services)
    assert hits == []
    assert summary['counts']['unknown'] == 1
