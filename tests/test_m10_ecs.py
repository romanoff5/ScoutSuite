"""M10-F ECS bounded read-only inventory, status rule and report contract."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_ecs_container_insights
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.ecs_public import (
    ECSPublicFacade, INCLUDE, MAX_PAGES, PAGE_SIZE)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.ecs_public.base import ECSPublic


ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ACCOUNT = '000000000000'


def client():
    return boto3.client('ecs', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def arn(n):
    return 'arn:aws:ecs:' + REGION + ':' + ACCOUNT + ':cluster/cluster-' + str(n)


def cluster(n, insights='enabled'):
    return {'clusterArn': arn(n), 'clusterName': 'cluster-' + str(n),
            'status': 'ACTIVE',
            'runningTasksCount': n, 'registeredContainerInstancesCount': 0,
            'settings': [{'name': 'containerInsights', 'value': insights}],
            'configuration': {'executeCommandConfiguration': {
                'logging': 'OVERRIDE', 'kmsKeyId': 'arn:aws:kms:' + REGION + ':' + ACCOUNT + ':key/example'}},
            'tags': [{'key': 'owner', 'value': 'security-review'}]}


def test_sdk_api_contract_and_scoped_calls():
    model = get_session().get_service_model('ecs')
    listing = model.operation_model('ListClusters')
    describe = model.operation_model('DescribeClusters')
    assert {'maxResults', 'nextToken'} <= set(listing.input_shape.members)
    assert {'clusters', 'include'} <= set(describe.input_shape.members)
    assert {'clusters', 'failures'} <= set(describe.output_shape.members)
    assert set(INCLUDE) <= set(describe.input_shape.members['include'].member.enum)


def test_stubber_two_pages_describe_and_resource_normalization():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_clusters', {'clusterArns': [arn(1)], 'nextToken': 'next'},
                                  {'maxResults': PAGE_SIZE})
                stub.add_response('list_clusters', {'clusterArns': [arn(2)]},
                                  {'maxResults': PAGE_SIZE, 'nextToken': 'next'})
                stub.add_response('describe_clusters', {'clusters': [
                    cluster(1, 'enabled'), cluster(2, 'disabled')]},
                    {'clusters': [arn(1), arn(2)], 'include': INCLUDE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    facade = ECSPublicFacade(object(), ACCOUNT)
                    result = await facade.get_clusters(REGION)
                    get_client.assert_called_once_with('ecs', facade.session, REGION)
                stub.assert_no_pending_responses()
            assert len(result) == 2
            assert result[0]['clusterArn'] == arn(1)
            src = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                ecs=SimpleNamespace(get_clusters=AsyncMock(return_value=result),
                get_task_definitions=AsyncMock(return_value=[])))
            resources = ECSPublic(src)
            await resources.fetch_all(regions=[REGION])
            assert resources['regions_count'] == 1
            assert resources['clusters_count'] == 2
            values = {row['cluster_name']: row
                      for row in resources['regions'][REGION]['clusters'].values()}
            assert values['cluster-2']['container_insights_disabled'] is True
            assert values['cluster-1']['container_insights'] == 'enabled'
            assert values['cluster-1']['cluster_arn'] == arn(1)
            assert values['cluster-1']['tags'] == [{'key': 'owner', 'value': 'security-review'}]
            assert values['cluster-1']['configuration']['executeCommandConfiguration']['kmsKeyId']
            assert all(k.startswith('scoutid-') for k in resources['regions'][REGION]['clusters'])
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_denied_and_invalid_owner_are_not_clean():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('list_clusters', service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={'maxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await ECSPublicFacade(object(), ACCOUNT).get_clusters(REGION) == []
                stub.assert_no_pending_responses()
            assert any(x['status'] == 'denied' and x['scope'] == 'ecs'
                       for x in ctx.collection_issues)
            with patch.object(AWSFacadeUtils, 'get_client') as get_client:
                assert await ECSPublicFacade(object(), 'invalid').get_clusters(REGION) == []
                get_client.assert_not_called()
            assert any(x['reason_code'] == 'InvalidAccountId' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_partial_missing_details_and_failed_describe():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_clusters', {'clusterArns': [arn(1), arn(2)]},
                                  {'maxResults': PAGE_SIZE})
                stub.add_response('describe_clusters', {
                    'clusters': [cluster(1)],
                    'failures': [{'arn': arn(2), 'reason': 'MISSING'}]},
                    {'clusters': [arn(1), arn(2)], 'include': INCLUDE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await ECSPublicFacade(object(), ACCOUNT).get_clusters(REGION)
                stub.assert_no_pending_responses()
            assert len(result) == 1
            assert {'ClusterDescriptionFailures', 'MissingClusterDetails'} <= {
                x['reason_code'] for x in ctx.collection_issues}
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_malformed_duplicates_cross_account_and_pagination():
    async def scenario():
        foreign = 'arn:aws:ecs:' + REGION + ':111111111111:cluster/foreign'
        cases = [
            ([{}], 'MalformedClusterList'),
            ([{'clusterArns': [None]}], 'MalformedClusterArn'),
            ([{'clusterArns': [foreign]}], 'UnexpectedClusterAccount'),
            ([{'clusterArns': [arn(1), arn(1)]}], 'DuplicateCluster'),
            ([{'clusterArns': [], 'nextToken': 'loop'},
              {'clusterArns': [], 'nextToken': 'loop'}], 'InvalidPaginationToken'),
            ([{'clusterArns': [], 'nextToken': str(i)}
              for i in range(MAX_PAGES)], 'PageLimit'),
            ([{'clusterArns': [arn(i) for i in range(PAGE_SIZE + 1)]}],
             'MalformedClusterList'),
        ]
        for pages, reason in cases:
            sdk = Mock()
            sdk.list_clusters.side_effect = pages
            sdk.describe_clusters.return_value = {'clusters': [], 'failures': []}
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    await ECSPublicFacade(object(), ACCOUNT).get_clusters(REGION)
                assert sdk.list_clusters.call_count <= MAX_PAGES
                assert any(x['reason_code'] == reason for x in ctx.collection_issues)
            finally:
                await ctx.aclose()
    asyncio.run(scenario())


def test_evidence_rule_and_ambiguous_missing_setting(tmp_path):
    for value, expected in [('enabled', 'secure'), ('enhanced', 'secure'),
                            ('disabled', 'insecure'), ('unexpected', 'unknown'),
                            (None, 'unknown')]:
        assert classify_ecs_container_insights({'container_insights': value}) == expected
    assert classify_ecs_container_insights(None) == 'unknown'
    rules = {'about': 'M10-F ECS synthetic', 'rules': {
        'ecs-container-insights-disabled.json': [{'enabled': True, 'level': 'warning'}]}}
    filename = tmp_path / 'ecs-rules.json'
    filename.write_text(json.dumps(rules), encoding='utf-8')
    src = SimpleNamespace(
        services={'ecs': {'regions': {REGION: {'clusters': {
            'good': {'container_insights': 'enabled', 'container_insights_disabled': False},
            'bad': {'container_insights': 'disabled', 'container_insights_disabled': True},
            'unknown': {'container_insights': None, 'container_insights_disabled': False}}}}}},
        service_list=['ecs'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(filename))).run(src)
        row = src.services['ecs']['findings']['ecs-container-insights-disabled']
        assert row['flagged_items'] == 1
        assert row['assessment_status'] == 'incomplete'
        assert row['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_optin_and_escaped_html():
    config = lambda credentials: SimpleNamespace(credentials=credentials, ecs={}, iam={}, s3={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        baseline = AWSProvider(credentials=credentials)
        chosen = AWSProvider(credentials=credentials, services=['ecs'])
    assert 'ecs' in baseline.service_list
    assert chosen.service_list == ['ecs']
    meta = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert meta['containers']['ecs']['resources']['clusters']['path'] == (
        'services.ecs.regions.id.clusters')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.ecs.regions.id.clusters.html').read_text(encoding='utf-8')
    assert '{{cluster_arn}}' in template and '{{container_insights}}' in template
    assert '{{{' not in template and 'onclick=' not in template and 'javascript:' not in template
