"""M10: sparse AWS account discovery must not create fake IAM gaps or PASSes."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from ScoutSuite.providers.aws.facade.backup import BoundedResults
from ScoutSuite.providers.aws.facade.ssm_public import SSMPublicFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.backup.base import BackupPublic

REGION = 'eu-central-1'


def test_ssm_empty_managed_nodes_skips_aws_default_baseline_details_but_flags_ec2():
    async def scenario():
        ssm, ec2 = Mock(), Mock()
        ssm.describe_instance_information.return_value = {'InstanceInformationList': []}
        ssm.describe_patch_baselines.return_value = {
            'BaselineIdentities': [
                {'BaselineId': f'pb-{number:017x}', 'BaselineName': f'AWS-Default-{number}'}
                for number in range(18)]}
        ssm.describe_patch_groups.return_value = {'Mappings': []}
        ec2.describe_instances.return_value = {'Reservations': [{
            'Instances': [{'InstanceId': f'i-{n:017x}', 'State': {'Name': 'running'}}
                          for n in range(9)]}]}
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda name, *_: ssm if name == 'ssm' else ec2):
            result = await SSMPublicFacade(object()).inventory(REGION)
        ssm.get_patch_baseline.assert_not_called()
        ssm.describe_instance_patch_states.assert_not_called()
        assert result['collection']['managed_nodes'] is True
        assert result['collection']['patch_baselines'] is True
        assert result['collection']['patch_baseline_details'] == (
            'not_required_no_managed_nodes')
        assert len(result['patch_baselines']) == 18
        assert all(p['detail'] is None and p['detail_complete'] is False
                   for p in result['patch_baselines'])
        assert result['ec2_comparison_complete'] is True
        assert len(result['managed_nodes']) == 9
        assert all(node['ssm_managed'] is False for node in result['managed_nodes'])
        assert all(node['patch_compliant_evidence'] is False
                   for node in result['managed_nodes'])
    asyncio.run(scenario())


def test_ssm_custom_patch_group_prevents_baseline_detail_deferral():
    async def scenario():
        ssm, ec2 = Mock(), Mock()
        baseline = 'pb-0123456789abcdef0'
        ssm.describe_instance_information.return_value = {'InstanceInformationList': []}
        ssm.describe_patch_baselines.return_value = {
            'BaselineIdentities': [{'BaselineId': baseline, 'BaselineName': 'Custom'}]}
        ssm.describe_patch_groups.return_value = {
            'Mappings': [{'PatchGroup': 'prod', 'BaselineIdentity': {'BaselineId': baseline}}]}
        ssm.get_patch_baseline.return_value = {'BaselineId': baseline}
        ec2.describe_instances.return_value = {'Reservations': []}
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda name, *_: ssm if name == 'ssm' else ec2):
            result = await SSMPublicFacade(object()).inventory(REGION)
        ssm.get_patch_baseline.assert_called_once_with(BaselineId=baseline)
        assert result['collection']['patch_baseline_details'] == 'complete'
    asyncio.run(scenario())


def test_backup_verified_empty_current_census_defers_restricted_history_not_absence():
    async def scenario():
        backup = SimpleNamespace(
            discovery_complete={REGION: {'plans': True, 'vaults': True}},
            get_vaults=AsyncMock(return_value=[]),
            get_plans=AsyncMock(return_value=[]),
            get_protected_resources=AsyncMock(return_value=BoundedResults()),
            get_backup_jobs=AsyncMock(side_effect=AssertionError('not required')),
            get_restore_jobs=AsyncMock(side_effect=AssertionError('not required')),
            get_restore_testing_plans=AsyncMock(
                side_effect=AssertionError('not required')))
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]), backup=backup)
        service = BackupPublic(facade)
        await service.fetch_all(regions=[REGION])
        data = service['regions'][REGION]
        assert data['backup_service_activity'] == 'no_current_resources_observed'
        assert data['backup_inventory_status']['protected_resources'] == 'complete'
        assert all(data['backup_inventory_status'][key] ==
                   'deferred_no_current_backup_inventory'
                   for key in ('backup_jobs', 'restore_jobs', 'restore_testing_plans'))
        backup.get_backup_jobs.assert_not_awaited()
        backup.get_restore_jobs.assert_not_awaited()
        backup.get_restore_testing_plans.assert_not_awaited()
        assert data['restore_testing_plans_count'] == 0
    asyncio.run(scenario())


def test_backup_verified_empty_census_keeps_s3_backup_evidence_gap_finding():
    from ScoutSuite.core.rule_evidence import classify_m10q_s3_backup
    from ScoutSuite.providers.aws.resources.coverage_reconciliation import (
        reconcile_m10q_coverage)

    async def scenario():
        backup = SimpleNamespace(
            discovery_complete={REGION: {'plans': True, 'vaults': True}},
            get_vaults=AsyncMock(return_value=[]),
            get_plans=AsyncMock(return_value=[]),
            get_protected_resources=AsyncMock(return_value=BoundedResults()),
            get_backup_jobs=AsyncMock(side_effect=AssertionError('not required')),
            get_restore_jobs=AsyncMock(side_effect=AssertionError('not required')),
            get_restore_testing_plans=AsyncMock(
                side_effect=AssertionError('not required')))
        service = BackupPublic(SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]), backup=backup))
        await service.fetch_all(regions=[REGION])
        return service

    service = asyncio.run(scenario())
    services = {
        's3': {'buckets': {'bucket-1': {
            'id': 'bucket-1', 'name': 'synthetic-bucket',
            'arn': 'arn:aws:s3:::*/synthetic-bucket', 'region': REGION}}},
        'backup': {'regions': {REGION: service['regions'][REGION]}},
    }
    reconcile_m10q_coverage(services, ['s3', 'backup'], '000000000000')
    bucket = services['s3']['buckets']['bucket-1']
    evidence = bucket['m10q_backup']
    # A region with no vault, plan or protected resource cannot hold an AWS
    # Backup recovery point for the bucket: the gap is verified, not UNKNOWN.
    assert evidence['state'] == 'not_reported'
    assert evidence['canonical_bucket_arn'] == 'arn:aws:s3:::synthetic-bucket'
    assert evidence['job_history_status'] == 'not_assessed'
    assert evidence['reasons'] == ['no_current_backup_inventory_job_history_not_assessed']
    assert evidence['completed_job_ids'] == []
    assert bucket['m10q_backup_evidence_gap'] is True
    assert classify_m10q_s3_backup(bucket) == 'insecure'


def test_backup_incomplete_or_nonempty_census_still_queries_deep_history():
    async def scenario(protected_complete, plan_present):
        empty = BoundedResults()
        empty.complete = protected_complete
        plan = {'arn': 'arn:aws:backup:eu-central-1:000000000000:backup-plan:a',
                'name': 'test', 'plan_id': 'a', 'rules': [],
                'selections': [], 'selection_collection_complete': True}
        backup = SimpleNamespace(
            discovery_complete={REGION: {'plans': True, 'vaults': True}},
            get_vaults=AsyncMock(return_value=[]),
            get_plans=AsyncMock(return_value=[plan] if plan_present else []),
            get_protected_resources=AsyncMock(return_value=empty),
            get_backup_jobs=AsyncMock(return_value=BoundedResults()),
            get_restore_jobs=AsyncMock(return_value=BoundedResults()),
            get_restore_testing_plans=AsyncMock(return_value=BoundedResults()))
        service = BackupPublic(SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]), backup=backup))
        await service.fetch_all(regions=[REGION])
        backup.get_backup_jobs.assert_awaited_once()
        backup.get_restore_jobs.assert_awaited_once()
        backup.get_restore_testing_plans.assert_awaited_once()
        assert service['regions'][REGION]['backup_service_activity'] == 'not_determined'
    asyncio.run(scenario(False, False))
    asyncio.run(scenario(True, True))


def test_s3_directory_access_points_resume_when_directory_bucket_exists():
    from ScoutSuite.providers.aws.facade.s3_advanced import S3AdvancedFacade

    async def scenario():
        facade = S3AdvancedFacade(object(), '000000000000')
        calls = []
        async def pages(client, operation, field, region, **kwargs):
            calls.append(operation)
            if operation == 'ListDirectoryBuckets':
                return [{'Name': 'test--euc1-az1--x-s3'}], True
            return [], True

        with patch.object(AWSFacadeUtils, 'get_client', return_value=Mock()), (
                patch.object(facade, '_pages', side_effect=pages)), (
                patch.object(facade, '_directory_bucket', new_callable=AsyncMock)):
            result = await facade._scan_region(REGION)
        assert 'ListAccessPointsForDirectoryBuckets' in calls
        assert result['collection']['directory_access_points'] == 'complete'

    asyncio.run(scenario())


def test_bedrock_enforced_guardrails_resume_when_customer_workload_observed():
    from ScoutSuite.providers.aws.facade.bedrock import BedrockFacade

    async def scenario():
        control, agent = Mock(), Mock()
        control.get_model_invocation_logging_configuration.return_value = {}
        control.list_guardrails.return_value = {'guardrails': []}
        control.list_inference_profiles.return_value = {'inferenceProfileSummaries': []}
        control.list_provisioned_model_throughputs.return_value = {
            'provisionedModelSummaries': [{
                'provisionedModelArn': 'arn:aws:bedrock:eu-central-1:000000000000:provisioned-model/test',
                'provisionedModelName': 'synthetic-model'}]}
        control.list_model_customization_jobs.return_value = {
            'modelCustomizationJobSummaries': []}
        control.list_enforced_guardrails_configuration.return_value = {
            'guardrailsConfig': []}
        agent.list_agents.return_value = {'agentSummaries': []}
        agent.list_knowledge_bases.return_value = {'knowledgeBaseSummaries': []}
        agent.list_flows.return_value = {'flowSummaries': []}
        agent.list_prompts.return_value = {'promptSummaries': []}
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda name, *_: (
                              control if name == 'bedrock' else agent)):
            result = await BedrockFacade(object()).inventory(REGION)
        control.list_enforced_guardrails_configuration.assert_called_once_with()
        assert result['collection']['enforced_guardrails'] is True
        assert result['enforced_guardrails_evidence_status'] == 'verified'

    asyncio.run(scenario())
