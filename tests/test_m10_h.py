"""M10-H integration: default AWS selection and deeper ECR/ECS/EKS evidence."""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_ecr_registry_scanning, classify_ecs_task_privilege,
    classify_eks_control_plane_audit)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.ecr_public import ECRPublicFacade
from ScoutSuite.providers.aws.facade.ecs_public import ECSPublicFacade, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.ecs_public.task_definitions import TaskDefinitions
from ScoutSuite.providers.aws.resources.eks_public.clusters import Clusters


ACCOUNT = '000000000000'
REGION = 'us-east-1'
ROOT = Path(__file__).resolve().parents[1]
TASK_ARN = 'arn:aws:ecs:us-east-1:' + ACCOUNT + ':task-definition/team:13'


def client(service):
    return boto3.client(service, region_name=REGION,
                        aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def task_definition(privileged=True):
    return {'taskDefinitionArn': TASK_ARN, 'family': 'team', 'revision': 13,
            'status': 'ACTIVE', 'taskRoleArn': 'arn:aws:iam::' + ACCOUNT + ':role/task',
            'executionRoleArn': 'arn:aws:iam::' + ACCOUNT + ':role/exec',
            'registeredAt': datetime(2026, 10, 30, tzinfo=timezone.utc),
            'containerDefinitions': [{
                'name': 'web', 'image': 'example.invalid/team:13',
                'privileged': privileged, 'readonlyRootFilesystem': False,
                'environment': [{'name': 'API_PASSWORD', 'value': 'DO_NOT_LEAK_VALUE_123'}],
                'secrets': [{'name': 'DATABASE_PASSWORD',
                             'valueFrom': 'arn:aws:secretsmanager:us-east-1:' +
                                          ACCOUNT + ':secret:db'}],
                'logConfiguration': {'logDriver': 'splunk',
                                     'options': {'splunk-token': 'DO_NOT_LEAK_TOKEN_456'}},
            }]}


def test_ecr_registry_scanning_stubber_and_explicit_scope():
    async def run():
        sdk = client('ecr')
        try:
            with Stubber(sdk) as stub:
                stub.add_response('get_registry_scanning_configuration', {
                    'registryId': ACCOUNT,
                    'scanningConfiguration': {
                        'scanType': 'ENHANCED',
                        'rules': [{'scanFrequency': 'CONTINUOUS_SCAN',
                                   'repositoryFilters': [{'filterType': 'WILDCARD',
                                                          'filter': 'team/*'}]}]}}, {})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await ECRPublicFacade(object(), ACCOUNT).get_registry_scanning(REGION)
                stub.assert_no_pending_responses()
            assert result['scan_type'] == 'ENHANCED'
            assert result['rules'][0]['repositoryFilters'][0]['filter'] == 'team/*'
            assert result['registry_id'] == ACCOUNT
        finally:
            sdk.close()
    asyncio.run(run())


def test_ecr_denied_scanning_is_partial_not_clean():
    async def run():
        sdk = client('ecr')
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('get_registry_scanning_configuration',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await ECRPublicFacade(object(), ACCOUNT).get_registry_scanning(REGION) is None
                stub.assert_no_pending_responses()
            assert any(r['scope'] == 'ecr' and r['status'] == 'partial'
                       for r in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(run())


def test_ecs_task_definition_stubber_and_no_environment_secrets_in_output():
    async def run():
        sdk = client('ecs')
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_task_definitions', {
                    'taskDefinitionArns': [TASK_ARN]},
                    {'status': 'ACTIVE', 'sort': 'DESC', 'maxResults': PAGE_SIZE})
                stub.add_response('describe_task_definition', {
                    'taskDefinition': task_definition()},
                    {'taskDefinition': TASK_ARN})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    rows = await ECSPublicFacade(object(), ACCOUNT).get_task_definitions(REGION)
                stub.assert_no_pending_responses()
            assert len(rows) == 1
            collection = TaskDefinitions(SimpleNamespace(), REGION)
            # Normalized output is intentionally not a copy of the AWS response.
            collection.facade = SimpleNamespace(
                ecs=SimpleNamespace(get_task_definitions=AsyncMock(return_value=rows)))
            await collection.fetch_all()
            resource = next(iter(collection.values()))
            data = json.dumps(resource)
            assert resource['task_definition_arn'] == TASK_ARN
            assert resource['has_privileged_container'] is True
            assert resource['containers'][0]['environment_variable_names'] == ['API_PASSWORD']
            assert resource['containers'][0]['log_option_names'] == ['splunk-token']
            assert 'DO_NOT_LEAK_VALUE_123' not in data
            assert 'DO_NOT_LEAK_TOKEN_456' not in data
            assert resource['execution_role_arn'].endswith(':role/exec')
        finally:
            sdk.close()
    asyncio.run(run())



def test_ecs_task_definition_denied_and_partial_list():
    async def run():
        sdk = client('ecs')
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_task_definitions', {
                    'taskDefinitionArns': [TASK_ARN], 'nextToken': 'later'},
                    {'status': 'ACTIVE', 'sort': 'DESC', 'maxResults': PAGE_SIZE})
                stub.add_client_error('list_task_definitions',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'status': 'ACTIVE', 'sort': 'DESC',
                                                       'maxResults': PAGE_SIZE,
                                                       'nextToken': 'later'})
                stub.add_response('describe_task_definition', {
                    'taskDefinition': task_definition(False)}, {'taskDefinition': TASK_ARN})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    rows = await ECSPublicFacade(object(), ACCOUNT).get_task_definitions(REGION)
                stub.assert_no_pending_responses()
            assert len(rows) == 1
            assert any(x['scope'] == 'ecs' and x['status'] == 'partial'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(run())


def test_eks_audit_configuration_and_unknown_states():
    parser = Clusters.__new__(Clusters)
    parser.region = REGION
    row = {'arn': 'arn:aws:eks:us-east-1:' + ACCOUNT + ':cluster/sample',
           'name': 'sample',
           'logging': {'clusterLogging': [
               {'types': ['audit', 'api'], 'enabled': False},
               {'types': ['scheduler'], 'enabled': True}]}}
    _, bad = parser._parse_cluster(row)
    assert bad['audit_logging_enabled'] is False
    assert bad['audit_logging_disabled'] is True
    assert classify_eks_control_plane_audit(bad) == 'insecure'
    row['logging']['clusterLogging'][0]['enabled'] = True
    _, good = parser._parse_cluster(row)
    assert classify_eks_control_plane_audit(good) == 'secure'
    row['logging'] = {'clusterLogging': []}
    _, unknown = parser._parse_cluster(row)
    assert unknown['audit_logging_enabled'] is None
    assert classify_eks_control_plane_audit(unknown) == 'unknown'


def test_three_evidence_classifiers_in_rule_engine(tmp_path):
    for value, expected in [('BASIC', 'insecure'), ('ENHANCED', 'secure'),
                            (None, 'unknown')]:
        assert classify_ecr_registry_scanning({'scan_type': value}) == expected
    assert classify_ecs_task_privilege({
        'privilege_observation_complete': False,
        'has_privileged_container': False}) == 'unknown'
    assert classify_ecs_task_privilege({
        'privilege_observation_complete': True,
        'has_privileged_container': False}) == 'secure'
    assert classify_ecs_task_privilege({
        'privilege_observation_complete': True,
        'has_privileged_container': True}) == 'insecure'
    rules = {'about': 'M10-H', 'rules': {
        'ecs-task-definition-privileged.json': [{'enabled': True, 'level': 'warning'}]}}
    path = tmp_path / 'ecs-rules.json'
    path.write_text(json.dumps(rules), encoding='utf-8')
    resources = {'bad': {'has_privileged_container': True, 'privilege_observation_complete': True},
                 'good': {'has_privileged_container': False, 'privilege_observation_complete': True},
                 'unknown': {'has_privileged_container': False, 'privilege_observation_complete': False}}
    provider = SimpleNamespace(
        services={'ecs': {'regions': {REGION: {'task_definitions': resources}}}},
        service_list=['ecs'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        finding = provider.services['ecs']['findings']['ecs-task-definition-privileged']
        assert finding['flagged_items'] == 1
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_default_aws_selection_and_safe_report_templates():
    config = lambda credentials: SimpleNamespace(
        credentials=credentials, iam={}, ecr={}, ecs={}, eks={}, s3={},
        inspector2={}, organizations={}, accessanalyzer={},
        securityhub={}, guardduty={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        default = AWSProvider(credentials=credentials)
        narrow = AWSProvider(credentials=credentials, services=['eks'])
    for service in ('ecr', 'ecs', 'eks'):
        assert service in default.service_list
    for service in ('inspector2', 'organizations', 'accessanalyzer',
                    'securityhub', 'guardduty'):
        assert service in default.service_list
    assert narrow.service_list == ['eks']
    for filename in ('services.ecr.regions.id.registry_scanning.html',
                     'services.ecs.regions.id.task_definitions.html'):
        template = (ROOT / 'ScoutSuite/output/data/html/partials/aws' / filename).read_text()
        assert '{{{' not in template and 'onclick=' not in template and 'javascript:' not in template
    ecs_template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                    'services.ecs.regions.id.task_definitions.html').read_text()
    assert '{{task_definition_arn}}' in ecs_template
    assert 'environment_variable_names' in ecs_template
