"""M10-G EKS bounded read-only clusters and public API endpoint evidence."""
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
from ScoutSuite.core.rule_evidence import classify_eks_api_endpoint
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.eks_public import EKSPublicFacade, MAX_PAGES, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.eks_public.base import EKSPublic
from ScoutSuite.providers.aws.resources.eks_public.clusters import Clusters


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ACCOUNT = '000000000000'


def client():
    return boto3.client('eks', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def cluster(name='app', public=True, cidrs=None):
    if cidrs is None:
        cidrs = ['0.0.0.0/0']
    return {'name': name,
            'arn': 'arn:aws:eks:' + REGION + ':' + ACCOUNT + ':cluster/' + name,
            'version': '1.34', 'status': 'ACTIVE',
            'createdAt': datetime(2026, 10, 1, tzinfo=timezone.utc),
            'endpoint': 'https://synthetic.example.invalid',
            'roleArn': 'arn:aws:iam::' + ACCOUNT + ':role/eks-control-plane',
            'resourcesVpcConfig': {'endpointPublicAccess': public,
                                   'endpointPrivateAccess': True,
                                   'publicAccessCidrs': cidrs},
            'tags': {'owner': 'cloud-security'}}


def test_sdk_contract_and_explicit_name_description():
    model = get_session().get_service_model('eks')
    listing = model.operation_model('ListClusters')
    describe = model.operation_model('DescribeCluster')
    assert {'maxResults', 'nextToken'} <= set(listing.input_shape.members)
    assert 'clusters' in listing.output_shape.members
    assert 'name' in describe.input_shape.required_members
    assert 'cluster' in describe.output_shape.members
    assert {'resourcesVpcConfig', 'endpoint', 'roleArn'} <= set(
        describe.output_shape.members['cluster'].members)


def test_stubbed_two_pages_and_normalization_without_credentials():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_clusters', {'clusters': ['app'], 'nextToken': 'next'},
                                  {'maxResults': PAGE_SIZE})
                stub.add_response('list_clusters', {'clusters': ['internal']},
                                  {'maxResults': PAGE_SIZE, 'nextToken': 'next'})
                stub.add_response('describe_cluster',
                                  {'cluster': cluster('app')}, {'name': 'app'})
                stub.add_response('describe_cluster',
                                  {'cluster': cluster('internal', public=False, cidrs=[])},
                                  {'name': 'internal'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = EKSPublicFacade(object(), ACCOUNT)
                    rows = await facade.get_clusters(REGION)
                    get_client.assert_called_once_with('eks', facade.session, REGION)
                stub.assert_no_pending_responses()
            assert len(rows) == 2
            src = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                eks=SimpleNamespace(get_clusters=AsyncMock(return_value=rows)))
            resources = EKSPublic(src)
            await resources.fetch_all(regions=[REGION])
            assert resources['regions_count'] == 1
            assert resources['clusters_count'] == 2
            normalized = {item['name']: item
                          for item in resources['regions'][REGION]['clusters'].values()}
            assert normalized['app']['public_endpoint_unrestricted'] is True
            assert normalized['internal']['public_endpoint_unrestricted'] is False
            assert normalized['app']['cluster_arn'] == rows[0]['arn']
            assert normalized['app']['tags'] == {'owner': 'cloud-security'}
            assert normalized['app']['created_at'].startswith('2026-10-01')
            assert normalized['app']['cluster_role_arn'] == rows[0]['roleArn']
            assert all(key.startswith('scoutid-')
                       for key in resources['regions'][REGION]['clusters'])
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_denied_region_listing_and_invalid_account():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('list_clusters',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={'maxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await EKSPublicFacade(object(), ACCOUNT).get_clusters(REGION) == []
                stub.assert_no_pending_responses()
            assert any(x['status'] == 'denied' and x['scope'] == 'eks'
                       for x in ctx.collection_issues)
            with patch.object(AWSFacadeUtils, 'get_client') as get_client:
                assert await EKSPublicFacade(object(), 'invalid').get_clusters(REGION) == []
                get_client.assert_not_called()
            assert any(x['reason_code'] == 'InvalidAccountId'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_partial_describe_denied_retains_verified_cluster():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_clusters', {'clusters': ['app', 'internal']},
                                  {'maxResults': PAGE_SIZE})
                stub.add_response('describe_cluster',
                                  {'cluster': cluster('app')}, {'name': 'app'})
                stub.add_client_error('describe_cluster',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={'name': 'internal'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    rows = await EKSPublicFacade(object(), ACCOUNT).get_clusters(REGION)
                stub.assert_no_pending_responses()
            assert len(rows) == 1 and rows[0]['name'] == 'app'
            assert any(x['status'] == 'partial' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_malformed_duplicate_looped_and_cross_account_evidence():
    async def scenario():
        cases = [
            ([{}], 'MalformedClusterList'),
            ([{'clusters': [None]}], 'MalformedClusterName'),
            ([{'clusters': ['app', 'app']}], 'DuplicateClusterName'),
            ([{'clusters': [], 'nextToken': 'loop'},
              {'clusters': [], 'nextToken': 'loop'}], 'InvalidPaginationToken'),
            ([{'clusters': [], 'nextToken': str(i)} for i in range(MAX_PAGES)],
             'PageLimit'),
            ([{'clusters': ['c' + str(i) for i in range(PAGE_SIZE + 1)]}],
             'MalformedClusterList'),
        ]
        for pages, reason in cases:
            sdk = Mock()
            sdk.list_clusters.side_effect = pages
            sdk.describe_cluster.return_value = {'cluster': cluster('app')}
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    await EKSPublicFacade(object(), ACCOUNT).get_clusters(REGION)
                assert sdk.list_clusters.call_count <= MAX_PAGES
                assert any(x['reason_code'] == reason for x in ctx.collection_issues)
            finally:
                await ctx.aclose()
        sdk = Mock()
        sdk.list_clusters.return_value = {'clusters': ['app']}
        bad = cluster('app')
        bad['arn'] = bad['arn'].replace(ACCOUNT, '111111111111')
        sdk.describe_cluster.return_value = {'cluster': bad}
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                assert await EKSPublicFacade(object(), ACCOUNT).get_clusters(REGION) == []
            assert any(x['reason_code'] == 'UnexpectedClusterAccount'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_rule_engine_and_unknown_endpoint_state(tmp_path):
    examples = [
        ({'public_endpoint_access': False}, 'secure'),
        ({'public_endpoint_access': True, 'public_access_cidrs': ['10.0.0.0/8']}, 'secure'),
        ({'public_endpoint_access': True, 'public_access_cidrs': ['0.0.0.0/0']}, 'insecure'),
        ({'public_endpoint_access': True, 'public_access_cidrs': ['::/0']}, 'insecure'),
        ({'public_endpoint_access': True, 'public_access_cidrs': []}, 'unknown'),
        ({'public_endpoint_access': None}, 'unknown'),
    ]
    for row, expected in examples:
        assert classify_eks_api_endpoint(row) == expected
    assert classify_eks_api_endpoint(None) == 'unknown'
    parser = Clusters.__new__(Clusters)
    parser.region = REGION
    _, unprotected = parser._parse_cluster(cluster())
    _, protected = parser._parse_cluster(cluster('internal', False, []))
    _, unknown = parser._parse_cluster(dict(cluster('unknown'), resourcesVpcConfig={}))
    rules = {'about': 'Synthetic EKS M10-G', 'rules': {
        'eks-public-api-unrestricted.json': [{'enabled': True, 'level': 'warning'}]}}
    filename = tmp_path / 'eks-rules.json'
    filename.write_text(json.dumps(rules), encoding='utf-8')
    provider = SimpleNamespace(services={'eks': {'regions': {REGION: {'clusters': {
        'bad': unprotected, 'good': protected, 'unknown': unknown}}}}}, service_list=['eks'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(filename))).run(provider)
        row = provider.services['eks']['findings']['eks-public-api-unrestricted']
        assert row['flagged_items'] == 1
        assert row['assessment_status'] == 'incomplete'
        assert row['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_optin_and_escaped_template():
    config = lambda credentials: SimpleNamespace(credentials=credentials, eks={}, iam={}, s3={})
    creds = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        original = AWSProvider(credentials=creds)
        chosen = AWSProvider(credentials=creds, services=['eks'])
    assert 'eks' in original.service_list
    assert chosen.service_list == ['eks']
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert metadata['containers']['eks']['resources']['clusters']['path'] == (
        'services.eks.regions.id.clusters')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.eks.regions.id.clusters.html').read_text(encoding='utf-8')
    assert '{{cluster_arn}}' in template and '{{endpoint}}' in template
    assert '{{{' not in template and 'onclick=' not in template and 'javascript:' not in template
