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
