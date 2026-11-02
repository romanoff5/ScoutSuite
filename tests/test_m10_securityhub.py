"""M10-C Security Hub: bounded SDK calls, evidence and catalog regressions."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_securityhub_standard
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.securityhub import SecurityHubPublicFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.securityhub.base import SecurityHubPublic
from ScoutSuite.providers.aws.resources.securityhub.hubs import Hubs


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
HUB = 'arn:aws:securityhub:us-east-1:000000000000:hub/default'
STANDARD = 'arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0'


def client():
    return boto3.client('securityhub', region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def subscription(index, status='READY'):
    return {
        'StandardsSubscriptionArn': HUB + '/standards/' + str(index),
        'StandardsArn': STANDARD,
        'StandardsInput': {},
        'StandardsStatus': status,
    }


def test_public_botocore_api_contract():
    model = get_session().get_service_model('securityhub')
    assert 'HubArn' in model.operation_model('DescribeHub').output_shape.members
    listing = model.operation_model('GetEnabledStandards')
    assert {'MaxResults', 'NextToken'} <= set(listing.input_shape.members)
    assert {'StandardsSubscriptions', 'NextToken'} <= set(listing.output_shape.members)
    shape = listing.output_shape.members['StandardsSubscriptions'].member
    assert {'StandardsSubscriptionArn', 'StandardsArn', 'StandardsStatus'} <= set(shape.members)


def test_two_page_sdk_stubber_and_normalized_hub():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('describe_hub', {
                    'HubArn': HUB, 'AutoEnableControls': False})
                stub.add_response('get_enabled_standards', {
                    'StandardsSubscriptions': [subscription(1, 'READY')],
                    'NextToken': 'next'}, {'MaxResults': 50})
                stub.add_response('get_enabled_standards', {
                    'StandardsSubscriptions': [subscription(2, 'FAILED')]},
                    {'MaxResults': 50, 'NextToken': 'next'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = SecurityHubPublicFacade(object())
                    raw = await facade.get_hub(REGION)
                    get_client.assert_called_once_with('securityhub', facade.session, REGION)
                stub.assert_no_pending_responses()
            assert raw['hub_arn'] == HUB
            assert raw['standards_inventory_complete'] is True
            assert len(raw['standards']) == 2
            assert raw['auto_enable_controls'] is False
            assert 'findings' not in raw
            upstream = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                securityhub=SimpleNamespace(get_hub=AsyncMock(return_value=raw)))
            resources = SecurityHubPublic(upstream)
            await resources.fetch_all(regions=[REGION])
            assert resources['regions_count'] == 1
            assert resources['hubs_count'] == 1
            hub = next(iter(resources['regions'][REGION]['hubs'].values()))
            assert hub['standards_count'] == 2
            assert hub['standards_inventory_complete'] is True
            assert hub['id'].startswith('scoutid-')
            statuses = {value['status']: value for value in hub['standards'].values()}
            assert statuses['READY']['unhealthy'] is False
            assert statuses['FAILED']['unhealthy'] is True
            assert all(k.startswith('scoutid-') for k in hub['standards'])
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_denied_hub_not_reported_as_empty_success():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('describe_hub', service_error_code='InvalidAccessException',
                                      http_status_code=401, expected_params={})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await SecurityHubPublicFacade(object()).get_hub(REGION) is None
                stub.assert_no_pending_responses()
            assert any(row['status'] == 'denied' and row['scope'] == 'securityhub'
                       for row in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_standards_denied_preserves_partial_hub_and_avoids_false_clean():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('describe_hub', {'HubArn': HUB}, {})
                stub.add_client_error('get_enabled_standards',
                                      service_error_code='InvalidAccessException',
                                      http_status_code=401,
                                      expected_params={'MaxResults': 50})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await SecurityHubPublicFacade(object()).get_hub(REGION)
                stub.assert_no_pending_responses()
            assert result['hub_arn'] == HUB
            assert result['standards'] == []
            assert result['standards_inventory_complete'] is False
            assert any(issue['status'] == 'partial' and issue['reason_code'] == 'GetStandardsDenied'
                       for issue in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_malformed_duplicate_limit_and_looped_pages_fail_closed():
    async def scenario():
        cases = [
            ([{}], 'MalformedStandardsList'),
            ([{'StandardsSubscriptions': [None]}], 'MalformedStandard'),
            ([{'StandardsSubscriptions': [subscription(1), subscription(1)]}],
             'DuplicateSubscription'),
            ([{'StandardsSubscriptions': [], 'NextToken': 'loop'},
              {'StandardsSubscriptions': [], 'NextToken': 'loop'}],
             'InvalidPaginationToken'),
            ([{'StandardsSubscriptions': [], 'NextToken': str(i)}
              for i in range(8)], 'PageLimit'),
        ]
        for pages, reason in cases:
            sdk = Mock()
            sdk.describe_hub.return_value = {'HubArn': HUB}
            sdk.get_enabled_standards.side_effect = pages
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk), \
                     patch('ScoutSuite.providers.aws.facade.securityhub.MAX_PAGES', 8):
                    output = await SecurityHubPublicFacade(object()).get_hub(REGION)
                assert output['standards_inventory_complete'] is False
                assert sdk.get_enabled_standards.call_count <= 8
                assert any(issue['reason_code'] == reason for issue in ctx.collection_issues)
            finally:
                await ctx.aclose()
        sdk = Mock()
        sdk.describe_hub.return_value = {'HubArn': HUB}
        sdk.get_enabled_standards.return_value = {
            'StandardsSubscriptions': [subscription(i) for i in range(6)]}
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk), \
                 patch('ScoutSuite.providers.aws.facade.securityhub.MAX_STANDARDS', 5):
                result = await SecurityHubPublicFacade(object()).get_hub(REGION)
            assert len(result['standards']) == 5
            assert not result['standards_inventory_complete']
            assert any(issue['reason_code'] == 'StandardsLimit' for issue in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_four_state_evidence_and_actual_rule_processing(tmp_path):
    for status, expected in [('READY', 'secure'), ('FAILED', 'insecure'),
                             ('INCOMPLETE', 'insecure'), ('PENDING', 'unknown'),
                             ('DELETING', 'unknown'), (None, 'unknown')]:
        assert classify_securityhub_standard({'status': status}) == expected
    assert classify_securityhub_standard(None) == 'unknown'
    parser = Hubs.__new__(Hubs)
    parser.region = REGION
    values = {
        s: {'id': s, 'status': s, 'unhealthy': s in ('FAILED', 'INCOMPLETE')}
        for s in ('READY', 'FAILED', 'INCOMPLETE', 'PENDING')
    }
    rules = {'about': 'Synthetic M10-C only', 'rules': {
        'securityhub-standard-status-unhealthy.json': [
            {'enabled': True, 'level': 'warning'}]}}
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules), encoding='utf-8')
    provider = SimpleNamespace(
        services={'securityhub': {'regions': {REGION: {
            'hubs': {'hub': {'standards': values}}}}}},
        service_list=['securityhub'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        row = provider.services['securityhub']['findings']['securityhub-standard-status-unhealthy']
        assert row['flagged_items'] == 2
        assert row['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 2, 'unknown': 1, 'not_applicable': 0}
        assert row['assessment_status'] == 'incomplete'
    finally:
        ctx.cleanup()


def test_default_metadata_template_and_aws_only_preservation():
    fake_config = lambda credentials: SimpleNamespace(
        credentials=credentials, iam={}, s3={}, securityhub={},
        accessanalyzer={}, guardduty={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake_config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value='000000000000'):
        default = AWSProvider(credentials=credentials)
        selected = AWSProvider(credentials=credentials, services=['securityhub'])
    assert 'securityhub' in default.service_list
    assert selected.service_list == ['securityhub']
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert metadata['security']['securityhub']['resources']['hubs']['path'] == (
        'services.securityhub.regions.id.hubs')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.securityhub.regions.id.hubs.html').read_text(encoding='utf-8')
    assert 'single_securityhub_hub_template' in template
    assert '{{hub_arn}}' in template and '{{status}}' in template
    assert '{{{' not in template and 'onclick=' not in template
    assert 'javascript:' not in template
