"""M10-R Bedrock metadata-only inventory for standard AWS scans."""
import asyncio

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.utils import get_non_provider_id
from ScoutSuite.providers.aws.facade.bedrock import select, safe_issue_code


FIELDS = {
    'guardrails': {'id': 'guardrail_id', 'arn': 'arn', 'name': 'name',
                   'status': 'status', 'version': 'version',
                   'createdAt': 'created_at', 'updatedAt': 'updated_at'},
    'enforced_guardrails': {'configId': 'config_id', 'guardrailArn': 'arn',
                            'guardrailId': 'guardrail_id',
                            'guardrailVersion': 'version',
                            'createdAt': 'created_at', 'updatedAt': 'updated_at'},
    'agents': {'agentId': 'agent_id', 'agentName': 'name',
               'agentStatus': 'status', 'latestAgentVersion': 'latest_version',
               'updatedAt': 'updated_at'},
    'knowledge_bases': {'knowledgeBaseId': 'knowledge_base_id', 'name': 'name',
                        'status': 'status', 'updatedAt': 'updated_at'},
    'flows': {'id': 'flow_id', 'arn': 'arn', 'name': 'name',
              'status': 'status', 'version': 'version',
              'createdAt': 'created_at', 'updatedAt': 'updated_at'},
    'prompts': {'id': 'prompt_id', 'arn': 'arn', 'name': 'name',
                'version': 'version', 'createdAt': 'created_at',
                'updatedAt': 'updated_at'},
    'inference_profiles': {'inferenceProfileId': 'profile_id',
                           'inferenceProfileArn': 'arn', 'inferenceProfileName': 'name',
                           'status': 'status', 'type': 'type'},
    'provisioned_models': {'provisionedModelArn': 'arn',
                           'provisionedModelName': 'name',
                           'status': 'status', 'modelArn': 'model_arn'},
    'model_jobs': {'jobArn': 'arn', 'jobName': 'name',
                   'status': 'status', 'baseModelArn': 'base_model_arn',
                   'customModelArn': 'custom_model_arn',
                   'creationTime': 'created_at', 'lastModifiedTime': 'updated_at'},
}
IDENTITY = {
    'guardrails': 'id', 'enforced_guardrails': 'configId',
    'agents': 'agentId', 'knowledge_bases': 'knowledgeBaseId',
    'flows': 'id', 'prompts': 'id',
    'inference_profiles': 'inferenceProfileArn',
    'provisioned_models': 'provisionedModelArn', 'model_jobs': 'jobArn',
}


class BedrockPublic(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('bedrock', facade)

    @staticmethod
    def issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'bedrock', safe_issue_code(reason))

    async def fetch_all(self, regions=None, excluded_regions=None,
                        partition_name='aws', **kwargs):
        chosen = await self.facade.build_region_list(
            'bedrock', regions, excluded_regions, partition_name)
        self['regions'] = {}
        semaphore = asyncio.Semaphore(4)

        async def fetch(region):
            async with semaphore:
                try:
                    return await self.facade.bedrock.inventory(region)
                except Exception:
                    self.issue('RegionInventoryFailed')
                    return {'collection': {}}

        outcomes = await asyncio.gather(*(fetch(region) for region in chosen))
        for region, raw in zip(chosen, outcomes):
            data = {'id': region, 'name': region, 'region': region,
                    'collection': dict(raw.get('collection') or {}),
                    'logging_verified': raw.get('logging_verified') is True,
                    'logging_config': raw.get('logging_config') or {}}
            for kind, mapping in FIELDS.items():
                bucket = {}
                complete = data['collection'].get(kind) is True
                for entry in raw.get(kind, []):
                    if not isinstance(entry, dict):
                        self.issue(kind + ':MalformedResource')
                        complete = False
                        continue
                    identity = entry.get(IDENTITY[kind])
                    if not isinstance(identity, str) or not identity:
                        self.issue(kind + ':MissingIdentity')
                        complete = False
                        continue
                    key = get_non_provider_id(identity)
                    if key in bucket:
                        self.issue(kind + ':DuplicateIdentity')
                        complete = False
                        continue
                    item = {'id': key, 'region': region,
                            **select(entry, mapping)}
                    if kind == 'guardrails':
                        for field in ('kms_key_arn', 'detail_verified',
                                      'topic_policy_configured', 'content_policy_configured',
                                      'word_policy_configured', 'pii_policy_configured',
                                      'grounding_policy_configured',
                                      'automated_reasoning_configured'):
                            item[field] = entry.get(field)
                    if kind == 'agents':
                        item.update({
                            'agent_role_arn': entry.get('agent_role_arn'),
                            'kms_key_arn': entry.get('kms_key_arn'),
                            'guardrail_identifier': entry.get('guardrail_identifier'),
                            'guardrail_version': entry.get('guardrail_version'),
                            'idle_session_ttl': entry.get('idle_session_ttl'),
                            'detail_verified': entry.get('detail_verified') is True,
                            'aliases_complete': entry.get('aliases_complete') is True,
                            'action_groups_complete': entry.get('action_groups_complete') is True,
                            'aliases': [
                                select(x, {'agentAliasId': 'alias_id',
                                           'agentAliasName': 'name',
                                           'agentAliasStatus': 'status',
                                           'aliasInvocationState': 'invocation_state',
                                           'updatedAt': 'updated_at'})
                                for x in entry.get('aliases', []) if isinstance(x, dict)],
                            'action_groups': [
                                select(x, {'actionGroupId': 'action_group_id',
                                           'actionGroupName': 'name',
                                           'actionGroupState': 'state'})
                                for x in entry.get('action_groups', []) if isinstance(x, dict)],
                        })
                        item['no_explicit_guardrail_review'] = (
                            item['detail_verified'] and
                            not item['guardrail_identifier'] and
                            data['collection'].get('enforced_guardrails') is True and
                            not raw.get('enforced_guardrails') and
                            item.get('status') not in ('DELETING', 'FAILED'))
                    if kind == 'knowledge_bases':
                        sources = {}
                        for source in entry.get('data_sources', []):
                            sid = source.get('dataSourceId') if isinstance(source, dict) else None
                            if not isinstance(sid, str) or not sid:
                                complete = False
                                self.issue('DataSourceMissingIdentity')
                                continue
                            skey = get_non_provider_id(sid)
                            if skey in sources:
                                complete = False
                                self.issue('DuplicateDataSource')
                                continue
                            sources[skey] = {
                                'id': skey, 'region': region,
                                **select(source, {
                                    'dataSourceId': 'data_source_id', 'name': 'name',
                                    'status': 'status', 'updatedAt': 'updated_at'}),
                                'detail_verified': source.get('detail_verified') is True,
                                'source_type': source.get('source_type'),
                                's3_bucket_arn': source.get('s3_bucket_arn'),
                                's3_inclusion_prefixes': source.get('s3_inclusion_prefixes', []),
                                'data_deletion_policy': source.get('data_deletion_policy'),
                            }
                        item.update({
                            'detail_verified': entry.get('detail_verified') is True,
                            'role_arn': entry.get('role_arn'),
                            'knowledge_base_arn': entry.get('knowledge_base_arn'),
                            'storage_type': entry.get('storage_type'),
                            'knowledge_base_type': entry.get('knowledge_base_type'),
                            'data_sources_complete': entry.get('data_sources_complete') is True,
                            'data_sources': sources, 'data_sources_count': len(sources),
                        })
                    bucket[key] = item
                data[kind] = bucket
                data[kind + '_count'] = len(bucket)
                if not complete:
                    data['collection'][kind] = False
            active = any(data[k + '_count'] for k in (
                'agents', 'knowledge_bases', 'flows', 'prompts',
                'provisioned_models', 'model_jobs'))
            config = data['logging_config']
            enabled = any(config.get(k) is True for k in (
                'text_enabled', 'image_enabled', 'embedding_enabled',
                'audio_enabled', 'video_enabled'))
            data['invocation_logging_review'] = (
                active and data['logging_verified'] and not enabled)
            data['coverage_status'] = (
                'complete' if (data['logging_verified'] and
                               all(data['collection'].values())) else 'incomplete')
            self['regions'][region] = data
        self['regions_count'] = len(self['regions'])
        for kind in FIELDS:
            self[kind + '_count'] = sum(x[kind + '_count']
                                      for x in self['regions'].values())
