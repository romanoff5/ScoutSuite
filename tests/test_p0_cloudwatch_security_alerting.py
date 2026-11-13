"""P0: empty CloudWatch inventory must alert; denied API calls must be UNKNOWN."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ScoutSuite.providers.aws.facade.cloudwatch import CloudWatch as CloudWatchFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.cloudwatch.base import CloudWatch
from ScoutSuite.core.rule_evidence import classify_cloudwatch_security_metric_alerting

REGION = 'eu-central-1'
ROOT_PATTERN = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'


def _finalized(filters, alarms, filters_status='complete', alarms_status='complete'):
    service = CloudWatch.__new__(CloudWatch)
    service.facade = SimpleNamespace(cloudwatch=SimpleNamespace(
        metric_filter_collection_status={REGION: filters_status},
        alarm_collection_status={REGION: alarms_status}))
    service['regions'] = {REGION: {'metric_filters': filters, 'alarms': alarms}}
    asyncio.run(service.finalize())
    return service['regions'][REGION]


def test_empty_inventory_flags_region_once():
    region = _finalized({}, {})
    assert region['security_metric_alerting_status'] == 'missing'
    assert classify_cloudwatch_security_metric_alerting(region) == 'insecure'


def test_missing_metric_alarms_or_alarm_actions_is_flagged():
    filters = {'f': {'pattern': ROOT_PATTERN}}
    assert classify_cloudwatch_security_metric_alerting(_finalized(filters, {})) == 'insecure'
    assert classify_cloudwatch_security_metric_alerting(_finalized(
        filters, {'alarm': {'AlarmActions': []}})) == 'insecure'


def test_alternate_filters_without_recognized_patterns_stay_explicit():
    region = _finalized({'f': {'pattern': 'non canonical alternative'}},
                        {'a': {'AlarmActions': ['arn:aws:sns:test']}})
    assert region['security_metric_alerting_status'] == 'missing_recognized_filters'
    assert classify_cloudwatch_security_metric_alerting(region) == 'insecure'


def test_candidate_configuration_is_not_marked_verified_clean():
    region = _finalized({'f': {'pattern': ROOT_PATTERN}},
                        {'a': {'AlarmActions': ['arn:aws:sns:test']}})
    assert region['security_metric_alerting_status'] == 'review_required'
    assert classify_cloudwatch_security_metric_alerting(region) == 'unknown'


def test_failed_collection_is_unknown_even_when_returning_empty_lists():
    facade = CloudWatchFacade(object())
    async def scenario():
        with patch.object(AWSFacadeUtils, 'get_all_pages', new_callable=AsyncMock,
                          side_effect=PermissionError('denied')):
            assert await facade.get_metric_filters(REGION) == []
            assert await facade.get_alarms(REGION) == []
    asyncio.run(scenario())
    assert facade.metric_filter_collection_status[REGION] == 'unknown'
    assert facade.alarm_collection_status[REGION] == 'unknown'
    region = _finalized({}, {}, filters_status='unknown', alarms_status='unknown')
    assert classify_cloudwatch_security_metric_alerting(region) == 'unknown'


def test_p0_region_rule_enabled_in_profiles():
    base = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'
    definition = json.loads((base / 'findings/cloudwatch-security-metric-alerting-missing.json').read_text())
    assert definition['path'] == 'cloudwatch.regions.id'
    for name in ('default.json', 'detailed.json'):
        rules = json.loads((base / 'rulesets' / name).read_text())['rules']
        assert rules['cloudwatch-security-metric-alerting-missing.json'][0]['enabled']
