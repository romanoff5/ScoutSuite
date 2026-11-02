"""M10-Q S3 advanced SDK shape, pagination, denial and safe reporting regression."""
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.s3_advanced import S3AdvancedFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils

REGION = 'us-east-1'
ACCOUNT = '000000000000'


def sdk(service):
    return boto3.client(service, region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def test_readonly_sdk_contracts():
    control = get_session().get_service_model('s3control')
    s3 = get_session().get_service_model('s3')
    for name in ('ListAccessPoints', 'GetAccessPoint', 'GetAccessPointPolicy',
                 'GetAccessPointPolicyStatus', 'GetAccessPointScope',
                 'ListAccessPointsForDirectoryBuckets', 'ListMultiRegionAccessPoints',
                 'GetMultiRegionAccessPoint', 'GetMultiRegionAccessPointPolicyStatus',
                 'GetMultiRegionAccessPointPolicy', 'ListAccessGrantsInstances',
                 'ListAccessGrantsLocations', 'ListAccessGrants',
                 'GetAccessGrantsInstance', 'GetAccessGrantsInstanceResourcePolicy'):
        assert name in control.operation_names
    assert 'ListDirectoryBuckets' in s3.operation_names
    assert 'ContinuationToken' in s3.operation_model('ListDirectoryBuckets').input_shape.members
    assert 'NextToken' in control.operation_model('ListAccessGrants').input_shape.members


def test_access_point_public_evidence_and_directory_scope_with_stubber():
    async def scenario():
        client = sdk('s3control')
        facade = S3AdvancedFacade(object(), ACCOUNT)
        ap = {'Name': 'example-ap', 'Bucket': 'example'}
        try:
            with Stubber(client) as stub:
                params = {'AccountId': ACCOUNT, 'Name': 'example-ap'}
                stub.add_response('get_access_point', {
                    'Name': 'example-ap', 'Bucket': 'example', 'NetworkOrigin': 'Internet'}, params)
                stub.add_response('get_access_point_policy_status', {
                    'PolicyStatus': {'IsPublic': True}}, params)
                stub.add_response('get_access_point_policy', {
                    'Policy': json.dumps({'Statement': []})}, params)
                await facade._access_point(client, ap, REGION)
                stub.assert_no_pending_responses()
            assert ap['detail_complete'] is True
            assert ap['public_policy_review'] is True
            assert ap['policy_public'] is True
            assert isinstance(ap['policy_document'], dict)
        finally:
            client.close()
    asyncio.run(scenario())


def test_denied_list_never_passes_and_valid_empty_does():
    async def scenario():
        client = sdk('s3control')
        facade = S3AdvancedFacade(object(), ACCOUNT)
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_client_error('list_access_points', service_error_code='AccessDenied',
                                      http_status_code=403,
                                      expected_params={'AccountId': ACCOUNT, 'MaxResults': 100})
                stub.add_response('list_access_points', {'AccessPointList': []},
                                  {'AccountId': ACCOUNT, 'MaxResults': 100})
                failed, complete = await facade._pages(
                    client, 'ListAccessPoints', 'AccessPointList', REGION, AccountId=ACCOUNT)
                assert not complete and failed == []
                empty, complete = await facade._pages(
                    client, 'ListAccessPoints', 'AccessPointList', REGION, AccountId=ACCOUNT)
                assert complete and empty == []
                stub.assert_no_pending_responses()
            assert any(x['status'] == 'denied' and x['scope'] == 's3'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_pagination_repeated_token_preserves_rows_and_marks_incomplete():
    async def scenario():
        client = sdk('s3control')
        facade = S3AdvancedFacade(object(), ACCOUNT)
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_response('list_access_points', {
                    'AccessPointList': [{'Name': 'a'}], 'NextToken': 'loop'},
                    {'AccountId': ACCOUNT, 'MaxResults': 100})
                stub.add_response('list_access_points', {
                    'AccessPointList': [{'Name': 'b'}], 'NextToken': 'loop'},
                    {'AccountId': ACCOUNT, 'MaxResults': 100, 'NextToken': 'loop'})
                items, complete = await facade._pages(
                    client, 'ListAccessPoints', 'AccessPointList', REGION, AccountId=ACCOUNT)
                stub.assert_no_pending_responses()
            assert not complete
            assert [x['Name'] for x in items] == ['a', 'b']
            assert any('InvalidPaginationToken' in x['reason_code'] for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_verified_empty_region_and_unknown_detail_are_distinct():
    async def scenario():
        ctrl = sdk('s3control')
        s3 = sdk('s3')
        facade = S3AdvancedFacade(object(), ACCOUNT)
        try:
            with Stubber(ctrl) as sc, Stubber(s3) as ss:
                sc.add_response('list_access_points', {'AccessPointList': []},
                                {'AccountId': ACCOUNT, 'MaxResults': 100})
                sc.add_response('list_access_points_for_directory_buckets',
                                {'AccessPointList': []},
                                {'AccountId': ACCOUNT, 'MaxResults': 100})
                ss.add_response('list_directory_buckets', {'Buckets': []},
                                {'MaxDirectoryBuckets': 100})
                sc.add_response('list_access_grants_instances',
                                {'AccessGrantsInstancesList': []},
                                {'AccountId': ACCOUNT, 'MaxResults': 100})
                with patch.object(AWSFacadeUtils, 'get_client',
                                  side_effect=lambda service, session, region: (
                                      ctrl if service == 's3control' else s3)):
                    result = await facade._scan_region(REGION)
                sc.assert_no_pending_responses()
                ss.assert_no_pending_responses()
            assert result['coverage_status'] == 'complete'
            assert result['collection']['access_grants'] == 'not_configured'
            assert result['directory_buckets_count'] == 0
        finally:
            ctrl.close()
            s3.close()
    asyncio.run(scenario())


def test_metadata_templates_no_html_sinks_or_object_reads():
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / 'ScoutSuite/providers/aws/metadata.json').read_text())
    s3 = data['storage']['s3']['resources']
    assert {'access_points', 'directory_access_points', 'directory_buckets',
            'access_grants_instances', 'access_grants_locations',
            'access_grants', 'multi_region_access_points'} <= set(s3)
    files = ('services.s3.advanced.regions.id.access_points.html',
             'services.s3.advanced.regions.id.directory_access_points.html',
             'services.s3.advanced.regions.id.directory_buckets.html',
             'services.s3.advanced.regions.id.access_grants.html',
             'services.s3.advanced.multi_region_access_points.html')
    for name in files:
        html = (root / 'ScoutSuite/output/data/html/partials/aws' / name).read_text()
        assert 'Handlebars.registerPartial' in html
        assert '{{{' not in html and 'javascript:' not in html and 'onclick=' not in html
    source = (root / 'ScoutSuite/providers/aws/facade/s3_advanced.py').read_text()
    for forbidden in ('get_object(', 'list_objects(', 'get_access_grants_credentials(',
                      'get_caller_access_grants('):
        assert forbidden not in source
