"""P0 CloudWatch: real API paginator outcomes and alarm/filter linkage."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ScoutSuite.providers.aws.facade.cloudwatch import CloudWatch as CloudWatchFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.cloudwatch.base import CloudWatch
from ScoutSuite.core.rule_evidence import classify_cloudwatch_security_metric_alerting

REGION = 'eu-central-1'
ROOT_PATTERN = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
TRANSFORM = [{'metricNamespace': 'Security', 'metricName': 'RootUsage', 'metricValue': '1'}]


def _finalized(filters, alarms, filters_status='complete', alarms_status='complete'):
    service = CloudWatch.__new__(CloudWatch)
    service.facade = SimpleNamespace(cloudwatch=SimpleNamespace(
        metric_filter_collection_status={REGION: filters_status},
        alarm_collection_status={REGION: alarms_status}))
    service['regions'] = {REGION: {'metric_filters': filters, 'alarms': alarms}}
    asyncio.run(service.finalize())
    return service['regions'][REGION]


def _filter(pattern=ROOT_PATTERN):
    return {'pattern': pattern, 'metric_transformations': TRANSFORM}


def _alarm(namespace='Security', name='RootUsage', actions=True):
    return {'Namespace': namespace, 'MetricName': name,
            'AlarmActions': ['arn:aws:sns:eu-central-1:123:topic'],
            'ActionsEnabled': actions}


def test_empty_complete_inventory_flags_region():
    region = _finalized({}, {})
    assert region['security_metric_alerting_status'] == 'missing'
    assert classify_cloudwatch_security_metric_alerting(region) == 'insecure'


def test_missing_alarms_and_disabled_delivery_are_flagged():
    for alarms in ({}, {'a': _alarm(actions=False)},
                   {'a': dict(_alarm(), AlarmActions=[])}):
        region = _finalized({'f': _filter()}, alarms)
        assert region['security_metric_alerting_status'] == 'missing'
        assert classify_cloudwatch_security_metric_alerting(region) == 'insecure'


def test_noncanonical_patterns_are_unknown_not_misreported_missing():
    region = _finalized({'f': _filter('{ $.userIdentity.type = "Root" }')},
                        {'a': _alarm()})
    assert region['security_metric_alerting_status'] == 'unrecognized_filter_patterns'
    assert classify_cloudwatch_security_metric_alerting(region) == 'unknown'


def test_known_security_filter_without_matching_actionable_alarm():
    region = _finalized({'f': _filter()},
                        {'cpu': _alarm('AWS/EC2', 'CPUUtilization')})
    assert region['security_metric_alerting_status'] == 'unlinked_security_filters'
    assert classify_cloudwatch_security_metric_alerting(region) == 'insecure'
    assert region['metric_filters']['f']['security_pattern_categories'] == ['root_usage']


def test_linked_configuration_requires_end_to_end_verification():
    region = _finalized({'f': _filter()}, {'a': _alarm()})
    assert region['security_metric_alerting_status'] == 'review_required'
    assert classify_cloudwatch_security_metric_alerting(region) == 'unknown'


def test_metric_math_or_missing_action_metadata_are_unknown():
    for alarm in ({'Metrics': [{'Id': 'expr'}], **_alarm()},
                  {'MetricName': 'RootUsage', 'Namespace': 'Security',
                   'AlarmActions': ['arn:aws:sns:topic']}):
        region = _finalized({'f': _filter()}, {'a': alarm})
        assert classify_cloudwatch_security_metric_alerting(region) == 'unknown'


def test_api_access_denied_does_not_look_like_empty_successful_inventory():
    client = Mock()
    client.get_paginator.return_value.paginate.side_effect = PermissionError('denied')
    facade = CloudWatchFacade(object())

    async def scenario():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            assert await facade.get_metric_filters(REGION) == []
            assert await facade.get_alarms(REGION) == []
    asyncio.run(scenario())
    assert facade.metric_filter_collection_status[REGION] == 'unknown'
    assert facade.alarm_collection_status[REGION] == 'unknown'
    assert classify_cloudwatch_security_metric_alerting(_finalized(
        {}, {}, filters_status='unknown', alarms_status='unknown')) == 'unknown'


def test_client_construction_failure_remains_unknown():
    facade = CloudWatchFacade(object())

    async def scenario():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=None):
            assert await facade.get_alarms(REGION) == []
    asyncio.run(scenario())
    assert facade.alarm_collection_status[REGION] == 'unknown'


def test_successfully_empty_paginator_is_complete():
    client = Mock()
    client.get_paginator.return_value.paginate.return_value = []
    facade = CloudWatchFacade(object())

    async def scenario():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            assert await facade.get_metric_filters(REGION) == []
            assert await facade.get_alarms(REGION) == []
    asyncio.run(scenario())
    assert facade.metric_filter_collection_status[REGION] == 'complete'
    assert facade.alarm_collection_status[REGION] == 'complete'


def test_p0_rule_in_default_and_detailed_profiles():
    base = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'
    rule = json.loads((base / 'findings/cloudwatch-security-metric-alerting-missing.json').read_text())
    assert rule['path'] == 'cloudwatch.regions.id'
    assert 'unlinked_security_filters' in str(rule['conditions'])
    for name in ('default.json', 'detailed.json'):
        rules = json.loads((base / 'rulesets' / name).read_text())['rules']
        assert rules['cloudwatch-security-metric-alerting-missing.json'][0]['enabled']
