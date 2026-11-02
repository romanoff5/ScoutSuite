"""M10-A: strict, offline AWS Access Analyzer service vertical-slice contracts."""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_access_analyzer
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.accessanalyzer import AccessAnalyzerFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.accessanalyzer.analyzers import Analyzers
from ScoutSuite.providers.aws.resources.accessanalyzer.base import AccessAnalyzer


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ARN = 'arn:aws:access-analyzer:us-east-1:000000000000:analyzer/test'


def record(suffix, status='ACTIVE'):
    return {
        'arn': ARN + suffix,
        'name': 'synthetic' + suffix,
        'type': 'ACCOUNT',
        'createdAt': datetime(2026, 1, 1, tzinfo=timezone.utc),
        'status': status,
    }


def client():
    return boto3.client('accessanalyzer', region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def test_access_analyzer_api_model_and_allowed_methods():
    operation = get_session().get_service_model('accessanalyzer').operation_model('ListAnalyzers')
    assert {'maxResults', 'nextToken'} <= set(operation.input_shape.members)
    assert {'analyzers', 'nextToken'} <= set(operation.output_shape.members)
    assert {'arn', 'name', 'type', 'status'} <= set(operation.output_shape.members['analyzers'].member.members)


def test_two_page_stubber_and_regional_resources():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_analyzers', {'analyzers': [record('a')], 'nextToken': 'next'},
                                  {'maxResults': 100})
                stub.add_response('list_analyzers', {'analyzers': [record('b', 'DISABLED')]},
                                  {'maxResults': 100, 'nextToken': 'next'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = AccessAnalyzerFacade(object())
                    rows = await facade.get_analyzers(REGION)
                    assert len(rows) == 2
                    assert rows[1]['status'] == 'DISABLED'
                    get_client.assert_called_once_with('accessanalyzer', facade.session, REGION)
                stub.assert_no_pending_responses()
        finally:
            sdk.close()

        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            accessanalyzer=SimpleNamespace(get_analyzers=AsyncMock(return_value=rows)),
        )
        resource = AccessAnalyzer(facade)
        await resource.fetch_all(regions=[REGION])
        assert resource['regions_count'] == 1
        assert resource['analyzers_count'] == 2
        items = list(resource['regions'][REGION]['analyzers'].values())
        assert {item['status'] for item in items} == {'ACTIVE', 'DISABLED'}
        assert all(item['id'].startswith('scoutid-') for item in items)
        assert all(item['tags'] == {} and 'findings' not in item for item in items)
        assert items[0]['arn'].startswith('arn:aws:')
    asyncio.run(scenario())


def test_empty_inventory_is_distinct_from_denied():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_analyzers', {'analyzers': []}, {'maxResults': 100})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    ctx = RunContext('aws').setup()
                    try:
                        assert await AccessAnalyzerFacade(object()).get_analyzers(REGION) == []
                        assert not ctx.collection_issues
                    finally:
                        await ctx.aclose()
                stub.assert_no_pending_responses()
            with Stubber(sdk) as stub:
                stub.add_client_error('list_analyzers', service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={'maxResults': 100})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    ctx = RunContext('aws').setup()
                    try:
                        assert await AccessAnalyzerFacade(object()).get_analyzers(REGION) == []
                        assert ctx.collection_issues[0]['status'] == 'denied'
                        assert ctx.collection_issues[0]['scope'] == 'accessanalyzer'
                    finally:
                        await ctx.aclose()
                stub.assert_no_pending_responses()
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_partial_on_denied_second_page_and_no_extra_api_calls():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_analyzers', {'analyzers': [record('a')], 'nextToken': 'next'},
                                  {'maxResults': 100})
                stub.add_client_error('list_analyzers', service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'maxResults': 100, 'nextToken': 'next'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await AccessAnalyzerFacade(object()).get_analyzers(REGION)
                assert len(result) == 1
                assert ctx.collection_issues[0]['status'] == 'partial'
                stub.assert_no_pending_responses()
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_malformed_and_token_loop_are_recorded_without_unbounded_work():
    async def scenario():
        for responses, reason in [
            ([{}], 'MalformedPage'),
            ([{'analyzers': [], 'nextToken': 'repeat'},
              {'analyzers': [], 'nextToken': 'repeat'}], 'InvalidPaginationToken'),
            ([{'analyzers': [record(str(i))] , 'nextToken': str(i)} for i in range(8)],
             'PageLimit'),
            ([{'analyzers': [record(str(i)) for i in range(6)]}], 'ResultLimit'),
        ]:
            sdk = Mock()
            sdk.list_analyzers.side_effect = responses
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk), \
                     patch('ScoutSuite.providers.aws.facade.accessanalyzer.MAX_PAGES', 8), \
                     patch('ScoutSuite.providers.aws.facade.accessanalyzer.MAX_ANALYZERS',
                           5 if reason == 'ResultLimit' else 100):
                    items = await AccessAnalyzerFacade(object()).get_analyzers(REGION)
                assert len(items) <= (5 if reason == 'ResultLimit' else 100)
                assert ctx.collection_issues[-1]['reason_code'] == reason
                assert sdk.list_analyzers.call_count <= 8
            finally:
                await ctx.aclose()
    asyncio.run(scenario())


def test_normalization_is_stable_and_invalid_state_is_not_silent():
    parser = Analyzers.__new__(Analyzers)
    parser.region = REGION
    key, active = parser._parse_analyzer(record('a'))
    assert key == parser._parse_analyzer(record('a'))[0]
    assert active['inactive'] is False
    assert classify_access_analyzer(active) == 'secure'
    _, disabled = parser._parse_analyzer(record('b', 'DISABLED'))
    assert disabled['inactive'] is True
    assert classify_access_analyzer(disabled) == 'insecure'
    _, failed = parser._parse_analyzer(record('c', 'FAILED'))
    assert classify_access_analyzer(failed) == 'insecure'
    _, creating = parser._parse_analyzer(record('d', 'CREATING'))
    assert creating['evaluation_status'] == 'partial'
    assert classify_access_analyzer(creating) == 'unknown'
    assert parser._parse_analyzer({'arn': ARN, 'status': 'UNRECOGNIZED'}) is None
    assert parser._parse_analyzer({'status': 'ACTIVE'}) is None
    assert classify_access_analyzer({}) == 'unknown'


def test_security_rule_end_to_end_with_incomplete_evidence(tmp_path):
    config = {'about': 'Synthetic M10 isolated rule',
              'rules': {'accessanalyzer-analyzer-inactive.json': [
                  {'enabled': True, 'level': 'warning'}]}}
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(config), encoding='utf-8')
    statuses = ['ACTIVE', 'DISABLED', 'FAILED', 'CREATING']
    analyzer = {'regions': {REGION: {'analyzers': {
        state.lower(): {'status': state, 'inactive': state in ('DISABLED', 'FAILED')}
        for state in statuses
    }}}}
    provider = SimpleNamespace(services={'accessanalyzer': analyzer}, service_list=['accessanalyzer'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        finding = provider.services['accessanalyzer']['findings']['accessanalyzer-analyzer-inactive']
        assert finding['flagged_items'] == 2
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 2, 'unknown': 1, 'not_applicable': 0,
        }
        assert finding['assessment_status'] == 'incomplete'
        assert all(item.startswith('accessanalyzer.regions.us-east-1.analyzers.')
                   for item in finding['items'])
    finally:
        context.cleanup()


def test_new_service_requires_explicit_opt_in():
    fake_config = lambda credentials: SimpleNamespace(
        credentials=credentials, iam={}, accessanalyzer={}, s3={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake_config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value='000000000000'):
        default = AWSProvider(credentials=credentials)
        explicit = AWSProvider(credentials=credentials, services=['accessanalyzer'])
    assert 'accessanalyzer' not in default.service_list
    assert explicit.service_list == ['accessanalyzer']


def test_report_metadata_rules_and_html_are_safe_and_packaged():
    meta = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert meta['security']['accessanalyzer']['resources']['analyzers']['path'] == (
        'services.accessanalyzer.regions.id.analyzers')
    catalog = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json').read_text(encoding='utf-8'))
    assert catalog['rules']['accessanalyzer-analyzer-inactive.json'][0]['enabled']
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.accessanalyzer.regions.id.analyzers.html').read_text(encoding='utf-8')
    assert '{{name}}' in template
    assert '{{arn}}' in template
    assert 'single_accessanalyzer_analyzer_template' in template
    assert '{{{' not in template
    assert 'onclick=' not in template and 'href="javascript:' not in template
