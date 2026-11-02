"""M10-D: strict offline Inspector2 contracts, no credential or AWS network calls."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
import pytest
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_inspector2_account, classify_inspector2_coverage,
)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.inspector2 import Inspector2Facade, MAX_PAGES, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.inspector2.base import Inspector2
from ScoutSuite.providers.aws.resources.inspector2.accounts import InspectorAccounts
from ScoutSuite.providers.aws.resources.inspector2.coverage import InspectorCoverage


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ACCOUNT = '000000000000'
FILTER = {'accountId': [{'comparison': 'EQUALS', 'value': ACCOUNT}]}


def client():
    return boto3.client('inspector2', region_name=REGION, aws_access_key_id='dummy',
                        aws_secret_access_key='dummy')


def account(status):
    return {'accountId': ACCOUNT, 'state': {'status': status},
            'resourceState': {'ec2': {'status': 'ENABLED'},
                              'ecr': {'status': 'DISABLED'}}}


def coverage(resource_id, code):
    return {'resourceType': 'AWS_EC2_INSTANCE', 'resourceId': resource_id,
            'accountId': ACCOUNT, 'scanType': 'PACKAGE',
            'scanStatus': {'statusCode': code,
                           'reason': 'SUCCESSFUL' if code == 'ACTIVE' else 'EC2_INSTANCE_STOPPED'}}


def test_inspector2_api_model_contract():
    service = get_session().get_service_model('inspector2')
    acc = service.operation_model('BatchGetAccountStatus')
    assert 'accountIds' in acc.input_shape.members
    assert {'accounts', 'failedAccounts'} <= set(acc.output_shape.members)
    listing = service.operation_model('ListCoverage')
    assert {'maxResults', 'nextToken', 'filterCriteria'} <= set(listing.input_shape.members)
    assert {'coveredResources', 'nextToken'} <= set(listing.output_shape.members)


def test_boto_stubber_account_and_two_coverage_pages_without_findings():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('batch_get_account_status',
                                  {'accounts': [account('ENABLED')], 'failedAccounts': []},
                                  {'accountIds': [ACCOUNT]})
                stub.add_response('list_coverage',
                                  {'coveredResources': [coverage('i-a', 'ACTIVE')], 'nextToken': 'next'},
                                  {'maxResults': PAGE_SIZE, 'filterCriteria': FILTER})
                stub.add_response('list_coverage',
                                  {'coveredResources': [coverage('i-b', 'INACTIVE')]},
                                  {'maxResults': PAGE_SIZE, 'filterCriteria': FILTER,
                                   'nextToken': 'next'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = Inspector2Facade(object(), ACCOUNT)
                    statuses = await facade.get_accounts(REGION)
                    resources = await facade.get_coverage(REGION)
                    assert get_client.call_count == 2
                stub.assert_no_pending_responses()
            assert statuses[0]['status'] == 'ENABLED'
            assert statuses[0]['resource_states']['ec2'] == 'ENABLED'
            assert {r['scan_status'] for r in resources} == {'ACTIVE', 'INACTIVE'}
            assert all('finding' not in r and 'resourceMetadata' not in r for r in resources)
            resource_facade = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                inspector2=SimpleNamespace(get_accounts=AsyncMock(return_value=statuses),
                                           get_coverage=AsyncMock(return_value=resources)))
            normalized = Inspector2(resource_facade)
            await normalized.fetch_all(regions=[REGION])
            assert normalized['regions_count'] == 1
            assert normalized['accounts_count'] == 1
            assert normalized['coverage_count'] == 2
            assert all(k.startswith('scoutid-') for k in normalized['regions'][REGION]['coverage'])
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_empty_coverage_distinct_from_denied_account_status():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_coverage', {'coveredResources': []},
                                  {'maxResults': PAGE_SIZE, 'filterCriteria': FILTER})
                ctx = RunContext('aws').setup()
                try:
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                        assert await Inspector2Facade(object(), ACCOUNT).get_coverage(REGION) == []
                    assert not ctx.collection_issues
                finally:
                    await ctx.aclose()
            with Stubber(sdk) as stub:
                stub.add_client_error('batch_get_account_status',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'accountIds': [ACCOUNT]})
                ctx = RunContext('aws').setup()
                try:
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                        assert await Inspector2Facade(object(), ACCOUNT).get_accounts(REGION) == []
                    assert ctx.collection_issues[0]['status'] == 'denied'
                    assert ctx.collection_issues[0]['scope'] == 'inspector2'
                finally:
                    await ctx.aclose()
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_partial_coverage_on_denied_second_page():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_coverage',
                                  {'coveredResources': [coverage('i-a', 'ACTIVE')], 'nextToken': 'next'},
                                  {'maxResults': PAGE_SIZE, 'filterCriteria': FILTER})
                stub.add_client_error('list_coverage',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'maxResults': PAGE_SIZE,
                                                       'filterCriteria': FILTER, 'nextToken': 'next'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await Inspector2Facade(object(), ACCOUNT).get_coverage(REGION)
                assert len(result) == 1
                assert ctx.collection_issues[-1]['status'] == 'partial'
                stub.assert_no_pending_responses()
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


@pytest.mark.parametrize('pages,reason', [
    ([{}], 'MalformedCoveragePage'),
    ([{'coveredResources': [], 'nextToken': 'loop'},
      {'coveredResources': [], 'nextToken': 'loop'}], 'InvalidPaginationToken'),
    ([{'coveredResources': [coverage('i-a', 'ACTIVE'), coverage('i-a', 'ACTIVE')]}],
     'DuplicateCoveredResource'),
    ([{'coveredResources': [coverage('i-a', 'ACTIVE')], 'nextToken': str(i)}
      for i in range(MAX_PAGES)], 'CoveragePageLimit'),
    ([{'coveredResources': [coverage(str(i), 'ACTIVE') for i in range(PAGE_SIZE + 1)]}],
     'CoverageLimit'),
    ([{'coveredResources': [dict(coverage('i-a', 'ACTIVE'), accountId='111111111111')]}],
     'UnexpectedAccount'),
])
def test_malformed_bounded_and_cross_account_collections(pages, reason):
    async def scenario():
        sdk = Mock()
        sdk.list_coverage.side_effect = pages
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                result = await Inspector2Facade(object(), ACCOUNT).get_coverage(REGION)
            assert len(result) <= 500
            assert sdk.list_coverage.call_count <= MAX_PAGES
            assert any(x['reason_code'] == reason for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_account_mismatch_and_transitional_unknown():
    async def scenario():
        sdk = Mock()
        sdk.batch_get_account_status.return_value = {
            'accounts': [{'accountId': '111111111111', 'state': {'status': 'ENABLED'}}],
            'failedAccounts': []}
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                assert await Inspector2Facade(object(), ACCOUNT).get_accounts(REGION) == []
            assert ctx.collection_issues
        finally:
            await ctx.aclose()
    asyncio.run(scenario())
    assert classify_inspector2_account({'status': 'ENABLING'}) == 'unknown'
    assert classify_inspector2_account({'status': 'ENABLED'}) == 'secure'
    assert classify_inspector2_account({'status': 'SUSPENDED'}) == 'insecure'
    assert classify_inspector2_coverage({'scan_status': 'INACTIVE'}) == 'insecure'
    assert classify_inspector2_coverage({'scan_status': 'ACTIVE'}) == 'secure'
    assert classify_inspector2_coverage({}) == 'unknown'


def test_rule_engine_flag_and_incomplete_evidence(tmp_path):
    selected = {'about': 'Synthetic M10-D Inspector2 rule test', 'rules': {
        'inspector2-account-disabled.json': [{'enabled': True, 'level': 'warning'}],
        'inspector2-coverage-inactive.json': [{'enabled': True, 'level': 'warning'}]}}
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(selected), encoding='utf-8')
    provider = SimpleNamespace(services={
        'inspector2': {'regions': {REGION: {
            'accounts': {'active': {'status': 'ENABLED', 'disabled': False},
                         'disabled': {'status': 'DISABLED', 'disabled': True},
                         'pending': {'status': 'ENABLING', 'disabled': False}},
            'coverage': {'good': {'scan_status': 'ACTIVE', 'inactive': False},
                         'bad': {'scan_status': 'INACTIVE', 'inactive': True},
                         'unknown': {'scan_status': 'UNKNOWN', 'inactive': False}}}}}},
        service_list=['inspector2'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        findings = provider.services['inspector2']['findings']
        for name in ('inspector2-account-disabled', 'inspector2-coverage-inactive'):
            result = findings[name]
            assert result['flagged_items'] == 1
            assert result['assessment_status'] == 'incomplete'
            assert result['evaluation_summary']['counts'] == {
                'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_opt_in_and_escaped_report_assets():
    credential = SimpleNamespace(session=object())
    def fake(credentials):
        return SimpleNamespace(credentials=credentials, inspector2={},
                               accessanalyzer={}, guardduty={}, iam={})
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        default = AWSProvider(credentials=credential)
        chosen = AWSProvider(credentials=credential, services=['inspector2'])
    assert 'inspector2' not in default.service_list
    assert chosen.service_list == ['inspector2']
    md = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert md['security']['inspector2']['resources']['coverage']['path'] == (
        'services.inspector2.regions.id.coverage')
    for name in ('accounts', 'coverage'):
        html = (ROOT / 'ScoutSuite/output/data/html/partials/aws' /
                ('services.inspector2.regions.id.' + name + '.html')).read_text(encoding='utf-8')
        assert '{{{' not in html and 'onclick=' not in html and 'javascript:' not in html
        assert '<script' in html and 'Handlebars.registerPartial' in html
