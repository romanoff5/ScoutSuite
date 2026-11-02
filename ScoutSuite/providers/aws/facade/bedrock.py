"""M10-R: read-only, bounded Amazon Bedrock control-plane inventory.

This collector deliberately never calls Invoke*, Retrieve*, GetPrompt,
GetKnowledgeBaseDocuments, GetAgentActionGroup (schema/payload), or
GetModelInvocationJob (request/response content).
"""
from datetime import datetime

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

PAGE_SIZE = 100
MAX_PAGES = 250
MAX_ITEMS = 25000
MAX_DETAILS = 25000
DENIED = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
          'UnrecognizedClientException'}
UNSUPPORTED = {'UnknownOperationException', 'UnsupportedOperationException',
               'UnsupportedRegionException', 'UnknownEndpoint'}


def safe_time(value):
    return value.isoformat() if isinstance(value, datetime) else value


def select(row, mapping):
    """Explicit allowlist: never persist prompts, messages or KB document text."""
    if not isinstance(row, dict):
        return {}
    return {target: safe_time(row[source]) for source, target in mapping.items()
            if source in row and isinstance(row[source], (str, int, float, bool, datetime))}


def status_of_resource(response, key):
    return isinstance(response, dict) and isinstance(response.get(key), dict)


class BedrockFacade(AWSBaseFacade):
    def issue(self, status, reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue(status, 'bedrock', reason)

    def failure(self, operation, error):
        code = (error.response.get('Error', {}).get('Code')
                if isinstance(error, ClientError) else '')
        status = ('denied' if code in DENIED else
                  'unsupported' if code in UNSUPPORTED else 'failed')
        self.issue(status, operation + ':' + (code or type(error).__name__))

    async def one(self, client, operation, **kwargs):
        try:
            response = await run_concurrently(
                lambda: getattr(client, operation)(**kwargs))
            if not isinstance(response, dict):
                self.issue('partial', operation + ':MalformedResponse')
                return None, False
            return response, True
        except Exception as error:
            self.failure(operation, error)
            return None, False

    async def pages(self, client, operation, key, **filters):
        """Preserve collected pages but never mark a truncated inventory complete."""
        rows, token, seen = [], None, set()
        for _ in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE, **filters}
            if operation == 'list_enforced_guardrails_configuration':
                params.pop('maxResults')
            if token is not None:
                params['nextToken'] = token
            page, valid = await self.one(client, operation, **params)
            if not valid:
                return rows, False
            items = page.get(key)
            if (not isinstance(items, list) or len(items) > MAX_ITEMS or
                    any(not isinstance(x, dict) for x in items)):
                self.issue('partial', operation + ':MalformedPage')
                return rows, False
            if len(rows) + len(items) > MAX_ITEMS:
                rows.extend(items[:MAX_ITEMS-len(rows)])
                self.issue('partial', operation + ':ItemLimit')
                return rows, False
            rows.extend(items)
            upcoming = page.get('nextToken')
            if upcoming in (None, ''):
                return rows, True
            if (not isinstance(upcoming, str) or len(upcoming) > 4096
                    or upcoming in seen):
                self.issue('partial', operation + ':InvalidToken')
                return rows, False
            seen.add(upcoming)
            token = upcoming
        self.issue('partial', operation + ':PageLimit')
        return rows, False

    async def inventory(self, region):
        raw = {
            'collection': {}, 'logging_verified': False, 'logging_config': {},
            'guardrails': [], 'enforced_guardrails': [], 'agents': [],
            'knowledge_bases': [], 'flows': [], 'prompts': [],
            'inference_profiles': [], 'provisioned_models': [],
            'model_jobs': [],
        }
        control = AWSFacadeUtils.get_client('bedrock', self.session, region)
        agent = AWSFacadeUtils.get_client('bedrock-agent', self.session, region)
        if control is None:
            self.issue('failed', 'BedrockClientConstruction')
        if agent is None:
            self.issue('failed', 'BedrockAgentClientConstruction')

        if control is not None:
            result, ok = await self.one(control, 'get_model_invocation_logging_configuration')
            raw['logging_verified'] = ok
            if ok:
                config = result.get('loggingConfig') or {}
                if not isinstance(config, dict):
                    raw['logging_verified'] = False
                    self.issue('partial', 'GetModelInvocationLoggingConfiguration:Malformed')
                else:
                    cloudwatch = config.get('cloudWatchConfig') or {}
                    s3 = config.get('s3Config') or {}
                    raw['logging_config'] = {
                        'text_enabled': config.get('textDataDeliveryEnabled') is True,
                        'image_enabled': config.get('imageDataDeliveryEnabled') is True,
                        'embedding_enabled': config.get('embeddingDataDeliveryEnabled') is True,
                        'audio_enabled': config.get('audioDataDeliveryEnabled') is True,
                        'video_enabled': config.get('videoDataDeliveryEnabled') is True,
                        'cloudwatch_log_group': cloudwatch.get('logGroupName'),
                        'cloudwatch_role_arn': cloudwatch.get('roleArn'),
                        'cloudwatch_large_data_bucket':
                            (cloudwatch.get('largeDataDeliveryS3Config') or {}).get('bucketName'),
                        's3_bucket': s3.get('bucketName'), 's3_key_prefix': s3.get('keyPrefix'),
                    }
            calls = [
                ('guardrails', 'list_guardrails', 'guardrails'),
                ('enforced_guardrails', 'list_enforced_guardrails_configuration',
                 'guardrailsConfig'),
                ('inference_profiles', 'list_inference_profiles', 'inferenceProfileSummaries'),
                ('provisioned_models', 'list_provisioned_model_throughputs',
                 'provisionedModelSummaries'),
                ('model_jobs', 'list_model_customization_jobs',
                 'modelCustomizationJobSummaries'),
            ]
            for key, method, output in calls:
                rows, complete = await self.pages(control, method, output)
                raw['collection'][key] = complete
                raw[key] = rows
            details_complete = raw['collection']['guardrails']
            for row in raw['guardrails'][:MAX_DETAILS]:
                identity = row.get('id')
                row['detail_verified'] = False
                if not identity:
                    details_complete = False
                    self.issue('partial', 'GuardrailMissingIdentifier')
                    continue
                detail, ok = await self.one(control, 'get_guardrail',
                                            guardrailIdentifier=identity)
                if ok and detail.get('guardrailId') == identity:
                    row['detail_verified'] = True
                    row['kms_key_arn'] = detail.get('kmsKeyArn')
                    row['topic_policy_configured'] = bool(detail.get('topicPolicy'))
                    row['content_policy_configured'] = bool(detail.get('contentPolicy'))
                    row['word_policy_configured'] = bool(detail.get('wordPolicy'))
                    row['pii_policy_configured'] = bool(detail.get('sensitiveInformationPolicy'))
                    row['grounding_policy_configured'] = bool(detail.get('contextualGroundingPolicy'))
                    row['automated_reasoning_configured'] = bool(detail.get('automatedReasoningPolicy'))
                else:
                    details_complete = False
            raw['collection']['guardrail_details'] = (
                details_complete and len(raw['guardrails']) <= MAX_DETAILS)

        if agent is not None:
            calls = [
                ('agents', 'list_agents', 'agentSummaries'),
                ('knowledge_bases', 'list_knowledge_bases', 'knowledgeBaseSummaries'),
                ('flows', 'list_flows', 'flowSummaries'),
                ('prompts', 'list_prompts', 'promptSummaries'),
            ]
            for key, method, output in calls:
                rows, complete = await self.pages(agent, method, output)
                raw['collection'][key] = complete
                raw[key] = rows

            agent_detail_complete = raw['collection']['agents']
            for row in raw['agents'][:MAX_DETAILS]:
                ident = row.get('agentId')
                row['detail_verified'] = False
                row['aliases'] = []
                row['action_groups'] = []
                row['aliases_complete'] = False
                row['action_groups_complete'] = False
                if not ident:
                    agent_detail_complete = False
                    self.issue('partial', 'AgentMissingIdentifier')
                    continue
                detail, ok = await self.one(agent, 'get_agent', agentId=ident)
                if ok and status_of_resource(detail, 'agent'):
                    data = detail['agent']
                    row.update({
                        'detail_verified': True,
                        'agent_role_arn': data.get('agentResourceRoleArn'),
                        'kms_key_arn': data.get('customerEncryptionKeyArn'),
                        'guardrail_identifier':
                            (data.get('guardrailConfiguration') or {}).get('guardrailIdentifier'),
                        'guardrail_version':
                            (data.get('guardrailConfiguration') or {}).get('guardrailVersion'),
                        'idle_session_ttl': data.get('idleSessionTTLInSeconds'),
                    })
                else:
                    agent_detail_complete = False
                aliases, alias_ok = await self.pages(
                    agent, 'list_agent_aliases', 'agentAliasSummaries', agentId=ident)
                row['aliases'] = aliases
                row['aliases_complete'] = alias_ok
                if not alias_ok:
                    agent_detail_complete = False
                # Action groups on DRAFT are metadata-only; they may differ from deployed aliases.
                groups, group_ok = await self.pages(
                    agent, 'list_agent_action_groups', 'actionGroupSummaries',
                    agentId=ident, agentVersion='DRAFT')
                row['action_groups'] = groups
                row['action_groups_complete'] = group_ok
                if not group_ok:
                    agent_detail_complete = False
            raw['collection']['agent_details'] = (
                agent_detail_complete and len(raw['agents']) <= MAX_DETAILS)

            kb_detail_complete = raw['collection']['knowledge_bases']
            for row in raw['knowledge_bases'][:MAX_DETAILS]:
                ident = row.get('knowledgeBaseId')
                row['detail_verified'] = False
                row['data_sources'] = []
                row['data_sources_complete'] = False
                if not ident:
                    self.issue('partial', 'KnowledgeBaseMissingIdentifier')
                    kb_detail_complete = False
                    continue
                detail, ok = await self.one(agent, 'get_knowledge_base',
                                            knowledgeBaseId=ident)
                if ok and status_of_resource(detail, 'knowledgeBase'):
                    item = detail['knowledgeBase']
                    row.update({
                        'detail_verified': True, 'role_arn': item.get('roleArn'),
                        'knowledge_base_arn': item.get('knowledgeBaseArn'),
                        'storage_type': (item.get('storageConfiguration') or {}).get('type'),
                        'knowledge_base_type': (item.get('knowledgeBaseConfiguration') or {}).get('type'),
                    })
                else:
                    kb_detail_complete = False
                sources, src_ok = await self.pages(
                    agent, 'list_data_sources', 'dataSourceSummaries',
                    knowledgeBaseId=ident)
                row['data_sources_complete'] = src_ok
                if not src_ok:
                    kb_detail_complete = False
                for source in sources[:MAX_DETAILS]:
                    sid = source.get('dataSourceId')
                    source['detail_verified'] = False
                    if not sid:
                        kb_detail_complete = False
                        continue
                    details, ok = await self.one(
                        agent, 'get_data_source', knowledgeBaseId=ident, dataSourceId=sid)
                    if ok and status_of_resource(details, 'dataSource'):
                        data = details['dataSource']
                        s3 = ((data.get('dataSourceConfiguration') or {}).get('s3Configuration') or {})
                        source.update({
                            'detail_verified': True,
                            'data_deletion_policy': data.get('dataDeletionPolicy'),
                            'source_type': (data.get('dataSourceConfiguration') or {}).get('type'),
                            's3_bucket_arn': s3.get('bucketArn'),
                            's3_inclusion_prefixes': s3.get('inclusionPrefixes', []),
                        })
                    else:
                        kb_detail_complete = False
                row['data_sources'] = sources
                if len(sources) > MAX_DETAILS:
                    kb_detail_complete = False
                    self.issue('partial', 'DataSourceDetailLimit')
            raw['collection']['knowledge_base_details'] = (
                kb_detail_complete and len(raw['knowledge_bases']) <= MAX_DETAILS)
        if control is None:
            for k in ('guardrails', 'enforced_guardrails', 'inference_profiles',
                      'provisioned_models', 'model_jobs', 'guardrail_details'):
                raw['collection'][k] = False
        if agent is None:
            for k in ('agents', 'knowledge_bases', 'flows', 'prompts',
                      'agent_details', 'knowledge_base_details'):
                raw['collection'][k] = False
        return raw
