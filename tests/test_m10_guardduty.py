"""M10-B GuardDuty strict synthetic vertical slice and report security regressions."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_guardduty_detector
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.guardduty import GuardDutyPublicFacade, MAX_PAGES
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.guardduty.base import GuardDutyPublic
from ScoutSuite.providers.aws.resources.guardduty.detectors import Detectors


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'


def client():
    return boto3.client('guardduty', region_name=REGION, aws_access_key_id='test',
                        aws_secret_access_key='test')


def test_api_contract_and_pagination_shape():
    model = get_session().get_service_model('guardduty')
    listing = model.operation_model('ListDetectors')
    assert {'MaxResults', 'NextToken'} <= set(listing.input_shape.members)
    assert {'DetectorIds', 'NextToken'} <= set(listing.output_shape.members)
    detail = model.operation_model('GetDetector')
    assert 'DetectorId' in detail.input_shape.required_members
    assert {'Status', 'ServiceRole'} <= set(detail.output_shape.required_members)


def test_boto_stubber_two_pages_details_and_normalizer():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_detectors', {'DetectorIds': ['abc'], 'NextToken': 'next'},
                                  {'MaxResults': 50})
                stub.add_response('list_detectors', {'DetectorIds': ['def']},
                                  {'MaxResults': 50, 'NextToken': 'next'})
                stub.add_response('get_detector', {'ServiceRole': 'arn:aws:iam::000000000000:role/service',
                                                   'Status': 'ENABLED'}, {'DetectorId': 'abc'})
                stub.add_response('get_detector', {'ServiceRole': 'arn:aws:iam::000000000000:role/service',
                                                   'Status': 'DISABLED'}, {'DetectorId': 'def'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = GuardDutyPublicFacade(object())
                    rows = await facade.get_detectors(REGION)
                    get_client.assert_called_once_with('guardduty', facade.session, REGION)
                stub.assert_no_pending_responses()
            assert len(rows) == 2
            assert rows[1]['status'] == 'DISABLED'
            assert not any('findings' in row or 'Tags' in row for row in rows)
        finally:
            sdk.close()

        source = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            guardduty=SimpleNamespace(get_detectors=AsyncMock(return_value=rows)))
        resources = GuardDutyPublic(source)
        await resources.fetch_all(regions=[REGION])
        assert resources['regions_count'] == 1
        assert resources['detectors_count'] == 2
        by_status = {row['status']: row for row in resources['regions'][REGION]['detectors'].values()}
        assert by_status['DISABLED']['disabled'] is True
        assert by_status['ENABLED']['disabled'] is False
        assert all(row['id'].startswith('scoutid-') for row in by_status.values())
    asyncio.run(scenario())


def test_empty_inventory_not_confused_with_access_denied():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_detectors', {'DetectorIds': []}, {'MaxResults': 50})
                ctx = RunContext('aws').setup()
                try:
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                        assert await GuardDutyPublicFacade(object()).get_detectors(REGION) == []
                    assert not ctx.collection_issues
                finally:
                    await ctx.aclose()
                stub.assert_no_pending_responses()
            with Stubber(sdk) as stub:
                stub.add_client_error('list_detectors', service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={'MaxResults': 50})
                ctx = RunContext('aws').setup()
                try:
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                        assert await GuardDutyPublicFacade(object()).get_detectors(REGION) == []
                    assert ctx.collection_issues[0]['status'] == 'denied'
                    assert ctx.collection_issues[0]['scope'] == 'guardduty'
                finally:
                    await ctx.aclose()
                stub.assert_no_pending_responses()
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_partial_detail_access_denied_preserves_verified_detector_only():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_detectors', {'DetectorIds': ['abc', 'def']},
                                  {'MaxResults': 50})
                stub.add_response('get_detector', {'ServiceRole': 'arn:aws:iam::000000000000:role/service',
                                                   'Status': 'ENABLED'}, {'DetectorId': 'abc'})
                stub.add_client_error('get_detector', service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={'DetectorId': 'def'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    rows = await GuardDutyPublicFacade(object()).get_detectors(REGION)
                assert len(rows) == 1 and rows[0]['detector_id'] == 'abc'
                assert ctx.collection_issues[-1]['status'] == 'partial'
                assert ctx.collection_issues[-1]['reason_code'] == 'GetDetectorDenied'
                stub.assert_no_pending_responses()
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_bounded_pages_duplicate_and_malformed_responses():
    async def scenario():
        for pages, reason in [
            ([{}], 'MalformedDetectorList'),
            ([{'DetectorIds': [], 'NextToken': 'loop'},
              {'DetectorIds': [], 'NextToken': 'loop'}], 'InvalidPaginationToken'),
            ([{'DetectorIds': ['a', 'a']}], 'DuplicateDetector'),
            ([{'DetectorIds': [str(i) for i in range(101)]}], 'DetectorLimit'),
            ([{'DetectorIds': [], 'NextToken': str(i)} for i in range(MAX_PAGES)],
             'PageLimit'),
        ]:
            sdk = Mock()
            sdk.list_detectors.side_effect = pages
            sdk.get_detector.return_value = {'Status': 'ENABLED'}
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    rows = await GuardDutyPublicFacade(object()).get_detectors(REGION)
                assert len(rows) <= 100
                assert sdk.list_detectors.call_count <= MAX_PAGES
                assert any(issue['reason_code'] == reason for issue in ctx.collection_issues)
            finally:
                await ctx.aclose()
    asyncio.run(scenario())


def test_evidence_and_rule_evaluation_no_false_clean(tmp_path):
    parser = Detectors.__new__(Detectors)
    parser.region = REGION
    enabled_key, enabled = parser._parse_detector({'detector_id': 'a', 'status': 'ENABLED'})
    disabled_key, disabled = parser._parse_detector({'detector_id': 'b', 'status': 'DISABLED'})
    assert enabled_key != disabled_key
    assert classify_guardduty_detector(enabled) == 'secure'
    assert classify_guardduty_detector(disabled) == 'insecure'
    assert classify_guardduty_detector({'status': 'CREATING'}) == 'unknown'
    assert parser._parse_detector({'detector_id': 'bad', 'status': None}) is None
    selected = {'about': 'Synthetic M10-B rule', 'rules': {
        'guardduty-detector-disabled.json': [{'enabled': True, 'level': 'warning'}]}}
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(selected), encoding='utf-8')
    data = {REGION: {'detectors': {'good': enabled, 'bad': disabled,
                                  'unknown': {'status': 'UNKNOWN', 'disabled': False}}}}
    provider = SimpleNamespace(
        services={'guardduty': {'regions': data}}, service_list=['guardduty'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rules))).run(provider)
        row = provider.services['guardduty']['findings']['guardduty-detector-disabled']
        assert row['flagged_items'] == 1
        assert row['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
        assert row['assessment_status'] == 'incomplete'
        assert row['items'] == ['guardduty.regions.us-east-1.detectors.bad.Disabled']
    finally:
        context.cleanup()


def test_service_is_explicit_opt_in_and_html_safe():
    fake_config = lambda credentials: SimpleNamespace(
        credentials=credentials, iam={}, guardduty={}, accessanalyzer={}, s3={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake_config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value='000000000000'):
        default = AWSProvider(credentials=credentials)
        chosen = AWSProvider(credentials=credentials, services=['guardduty'])
    assert 'guardduty' not in default.service_list
    assert 'accessanalyzer' not in default.service_list
    assert chosen.service_list == ['guardduty']
    meta = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert meta['security']['guardduty']['resources']['detectors']['path'] == (
        'services.guardduty.regions.id.detectors')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.guardduty.regions.id.detectors.html').read_text(encoding='utf-8')
    assert 'single_guardduty_detector_template' in template
    assert '{{detector_id}}' in template and '{{status}}' in template
    assert '{{{' not in template and 'onclick=' not in template
    assert 'javascript:' not in template
