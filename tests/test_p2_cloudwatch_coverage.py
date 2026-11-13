"""P2 integration: real AWS rule JSON traversal with read-only synthetic inventories."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

RULES = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'


def check_rule(name, services):
    data = json.loads((RULES / name).read_text(encoding='utf-8'))
    cfg = SimpleNamespace(filename=name, path=data['path'], conditions=data['conditions'],
                          evidence_policy=data['evidence_policy'],
                          id_suffix=data.get('id_suffix'), checked_items=0)
    matches = recurse(services, services, cfg.path.split('.'), [], cfg, True)
    summary = evaluate_rule_evidence(cfg, services)
    return matches, summary

from ScoutSuite.providers.aws.facade.cloudwatch import CloudWatch as CloudWatchFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.cloudwatch.log_groups import LogGroups
from ScoutSuite.providers.aws.resources.cloudwatch.alarms import Alarms


def test_cloudwatch_log_groups_retention_and_kms_rule_semantics():
    async def listing(region):
        return [
            {'logGroupName': '/aws/audit', 'arn': 'arn:aws:logs:eu-central-1:123:log-group:/aws/audit'},
            {'logGroupName': '/aws/app', 'retentionInDays': 30,
             'kmsKeyId': 'arn:aws:kms:eu-central-1:123:key/abc'}
        ]
    groups = LogGroups.__new__(LogGroups)
    groups.facade = SimpleNamespace(cloudwatch=SimpleNamespace(get_log_groups=listing))
    groups.region = REGION
    asyncio.run(groups.fetch_all())
    assert len(groups) == 2
    services = {'cloudwatch': {'regions': {REGION: {'log_groups': dict(groups)}}}}
    for filename in ('cloudwatch-log-group-unlimited-retention.json',
                     'cloudwatch-log-group-no-customer-kms.json'):
        hits, evidence = check_rule(filename, services)
        assert len(hits) == 1 and evidence['counts']['insecure'] == 1
        assert evidence['counts']['secure'] == 1
    audit = next(row for row in groups.values() if row['name'] == '/aws/audit')
    assert audit['customer_kms_status'] == 'aws_managed'  # Encrypted using AWS-managed keys.
    assert audit['retention_status'] == 'unlimited'


def test_cloudwatch_actions_disabled_rule_with_real_alarm_parser():
    parser = Alarms.__new__(Alarms)
    rows = {}
    for name, enabled, actions in [
        ('off', False, ['arn:aws:sns:eu-central-1:123:topic']),
        ('on', True, ['arn:aws:sns:eu-central-1:123:topic']),
        ('none', False, [])
    ]:
        id_, record = parser._parse_alarm({
            'AlarmArn': 'arn:aws:cloudwatch:eu-central-1:123:alarm:' + name,
            'AlarmName': name, 'ActionsEnabled': enabled,
            'AlarmActions': actions})
        rows[id_] = record
    services = {'cloudwatch': {'regions': {REGION: {'alarms': rows}}}}
    hits, evidence = check_rule('cloudwatch-metric-alarm-actions-disabled.json', services)
    assert len(hits) == 1
    assert evidence['counts'] == {
        'secure': 1, 'insecure': 1, 'unknown': 0, 'not_applicable': 1}


def test_cloudwatch_denied_log_group_inventory_is_unknown():
    cli = SimpleNamespace(get_paginator=lambda operation: (_ for _ in ()).throw(
        PermissionError('denied')))
    facade = CloudWatchFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
        assert asyncio.run(facade.get_log_groups(REGION)) == []
    assert facade.log_group_collection_status[REGION] == 'unknown'


def test_cloudwatch_successful_empty_inventory_stays_complete():
    cli = SimpleNamespace(get_paginator=lambda operation: SimpleNamespace(
        paginate=lambda: iter([])))
    facade = CloudWatchFacade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
        assert asyncio.run(facade.get_log_groups(REGION)) == []
    assert facade.log_group_collection_status[REGION] == 'complete'
