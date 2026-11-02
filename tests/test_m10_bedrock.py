"""M10-R: SDK-backed Amazon Bedrock security inventory (no invocation/data plane)."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.bedrock import BedrockFacade, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.bedrock.base import BedrockPublic

REGION = 'us-east-1'


def client(service):
    return boto3.client(service, region_name=REGION,
                        aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def test_sdk_contracts_and_read_only_allowlist():
    models = {name: get_session().get_service_model(name)
              for name in ('bedrock', 'bedrock-agent')}
    assert {'GetModelInvocationLoggingConfiguration', 'ListGuardrails',
            'GetGuardrail', 'ListEnforcedGuardrailsConfiguration',
            'ListInferenceProfiles', 'ListProvisionedModelThroughputs',
            'ListModelCustomizationJobs'} <= set(models['bedrock'].operation_names)
    assert {'ListAgents', 'GetAgent', 'ListAgentAliases', 'ListAgentActionGroups',
            'ListKnowledgeBases', 'GetKnowledgeBase', 'ListDataSources',
            'GetDataSource', 'ListFlows', 'ListPrompts'} <= set(
                models['bedrock-agent'].operation_names)
    text = (Path(__file__).resolve().parents[1] /
            'ScoutSuite/providers/aws/facade/bedrock.py').read_text()
    for forbidden in ('invoke_model(', 'invoke_agent(', 'retrieve(', 'get_prompt(',
                      'get_knowledge_base_documents(', 'get_model_invocation_job('):
        assert forbidden not in text.lower()


def test_bedrock_stubber_minimal_contract_and_complete_empty_inventory():
    async def scenario():
        control, agent = client('bedrock'), client('bedrock-agent')
        try:
            with Stubber(control) as s, Stubber(agent) as a:
                s.add_response('get_model_invocation_logging_configuration', {}, {})
                for operation, key in (
                    ('list_guardrails', 'guardrails'),
                    ('list_enforced_guardrails_configuration', 'guardrailsConfig'),
                    ('list_inference_profiles', 'inferenceProfileSummaries'),
                    ('list_provisioned_model_throughputs', 'provisionedModelSummaries'),
                    ('list_model_customization_jobs', 'modelCustomizationJobSummaries')):
                    s.add_response(operation, {key: []},
                                   {} if operation == 'list_enforced_guardrails_configuration'
                                   else {'maxResults': PAGE_SIZE})
                for operation, key in (
                    ('list_agents', 'agentSummaries'),
                    ('list_knowledge_bases', 'knowledgeBaseSummaries'),
                    ('list_flows', 'flowSummaries'),
                    ('list_prompts', 'promptSummaries')):
                    a.add_response(operation, {key: []}, {'maxResults': PAGE_SIZE})
                def sdk(service, session, region):
                    assert region == REGION
                    return control if service == 'bedrock' else agent
                with patch.object(AWSFacadeUtils, 'get_client', side_effect=sdk):
                    result = await BedrockFacade(object()).inventory(REGION)
                s.assert_no_pending_responses()
                a.assert_no_pending_responses()
        finally:
            control.close()
            agent.close()
        assert result['logging_verified']
        assert all(result['collection'].values())
        assert not result['agents'] and not result['guardrails']
    asyncio.run(scenario())


def test_pagination_repeated_token_and_denied_are_incomplete():
    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            fake = Mock()
            fake.list_agents.side_effect = [
                {'agentSummaries': [], 'nextToken': 'repeated'},
                {'agentSummaries': [], 'nextToken': 'repeated'}]
            rows, complete = await BedrockFacade(object()).pages(
                fake, 'list_agents', 'agentSummaries')
            assert rows == [] and not complete and fake.list_agents.call_count == 2
            assert any(i['scope'] == 'bedrock' and
                       i['reason_code'] == 'list_agents_InvalidToken'
                       for i in ctx.collection_issues)
            sdk = client('bedrock-agent')
            try:
                with Stubber(sdk) as stub:
                    stub.add_client_error('list_agents', service_error_code='AccessDeniedException',
                                          http_status_code=403,
                                          expected_params={'maxResults': PAGE_SIZE})
                    rows, complete = await BedrockFacade(object()).pages(
                        sdk, 'list_agents', 'agentSummaries')
                    assert not rows and not complete
                assert any(i['scope'] == 'bedrock' and i['status'] == 'denied'
                           for i in ctx.collection_issues)
            finally:
                sdk.close()
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_resources_preserve_names_and_fail_closed():
    async def check(raw):
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            bedrock=SimpleNamespace(inventory=AsyncMock(return_value=raw)))
        result = BedrockPublic(facade)
        await result.fetch_all(regions=[REGION])
        return result['regions'][REGION]
    raw = {
        'logging_verified': True, 'logging_config': {},
        'collection': {'agents': True, 'enforced_guardrails': True,
                       'guardrails': True, 'knowledge_bases': True,
                       'flows': True, 'prompts': True,
                       'inference_profiles': True, 'provisioned_models': True,
                       'model_jobs': True},
        'agents': [{'agentId': 'A1B2C3D4E5', 'agentName': 'Customer Support',
                    'agentStatus': 'PREPARED', 'agent_role_arn':
                    'arn:aws:iam::000000000000:role/bedrock',
                    'detail_verified': True,
                    'aliases': [{'agentAliasId': 'alias1', 'agentAliasName': 'live'}],
                    'action_groups': []}],
        'knowledge_bases': [{'knowledgeBaseId': 'KB1', 'name': 'Sales KB',
                            'data_sources': [{'dataSourceId': 'DS1',
                                              'name': 'docs',
                                              's3_bucket_arn': 'arn:aws:s3:::kb-synthetic',
                                              'detail_verified': True}]}],
        'guardrails': [], 'enforced_guardrails': [], 'flows': [], 'prompts': [],
        'inference_profiles': [], 'provisioned_models': [], 'model_jobs': [],
    }
    region = asyncio.run(check(raw))
    assert region['coverage_status'] == 'complete'
    assert region['invocation_logging_review'] is True
    agent = next(iter(region['agents'].values()))
    assert agent['name'] == 'Customer Support'
    assert agent['no_explicit_guardrail_review'] is True
    kb = next(iter(region['knowledge_bases'].values()))
    assert next(iter(kb['data_sources'].values()))['s3_bucket_arn'].endswith('kb-synthetic')
    assert 'arn:aws:iam::000000000000:role/bedrock' in json.dumps(region)
    denied = asyncio.run(check({**raw, 'logging_verified': False,
                                'collection': {**raw['collection'],
                                               'enforced_guardrails': False}}))
    assert denied['invocation_logging_review'] is False
    assert denied['coverage_status'] == 'incomplete'
    assert next(iter(denied['agents'].values()))['no_explicit_guardrail_review'] is False


def test_report_catalog_and_safe_templates():
    root = Path(__file__).resolve().parents[1]
    metadata = json.loads((root / 'ScoutSuite/providers/aws/metadata.json').read_text())
    assert 'bedrock' in metadata['security']
    resources = metadata['security']['bedrock']['resources']
    for kind in ('regions', 'guardrails', 'enforced_guardrails', 'agents',
                 'knowledge_bases', 'data_sources', 'flows', 'prompts',
                 'inference_profiles', 'provisioned_models', 'model_jobs'):
        assert kind in resources
    for item in resources.values():
        name = item['path'].replace('services.', 'services.')
        template = root / 'ScoutSuite/output/data/html/partials/aws' / (name + '.html')
        content = template.read_text()
        assert '{{{' not in content and 'onclick=' not in content
        assert 'Handlebars.registerPartial' in content
