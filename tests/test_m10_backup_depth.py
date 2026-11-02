"""M10-N: AWS Backup real botocore contracts and conservative evidence correlation."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.backup import (
    BackupPublicFacade, BoundedResults, PAGE_SIZE)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.backup.base import BackupPublic

REGION = 'us-east-1'
ACCOUNT = '000000000000'
ARN = 'arn:aws:backup:us-east-1:000000000000:backup-plan:plan-1'
VAULT = 'arn:aws:backup:us-east-1:000000000000:backup-vault:primary'
RESOURCE = 'arn:aws:ec2:us-east-1:000000000000:volume/vol-123'
TEST_ARN = 'arn:aws:backup:us-east-1:000000000000:restore-testing-plan:test-1'


def sdk():
    return boto3.client(
        'backup', region_name=REGION,
        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def test_sdk_operations_and_pagination_shapes_are_read_only():
    model = get_session().get_service_model('backup')
    paginated = {
        'ListBackupSelections', 'ListProtectedResources', 'ListBackupJobs',
        'ListRestoreJobs', 'ListRestoreTestingPlans', 'ListRestoreTestingSelections'}
    assert paginated <= set(model.operation_names)
    for op in paginated:
        assert {'MaxResults', 'NextToken'} <= set(
            model.operation_model(op).input_shape.members)
    for op, param in [('GetBackupSelection', 'SelectionId'),
                      ('GetBackupVaultAccessPolicy', 'BackupVaultName')]:
        assert param in model.operation_model(op).input_shape.required_members


def test_stubber_selection_details_and_vault_policy():
    async def run():
        cli = sdk()
        try:
            with Stubber(cli) as stub:
                stub.add_response('list_backup_plans', {
                    'BackupPlansList': [{'BackupPlanId': 'plan-1', 'BackupPlanArn': ARN,
                                         'BackupPlanName': 'daily'}]},
                    {'MaxResults': PAGE_SIZE})
                stub.add_response('get_backup_plan', {
                    'BackupPlan': {'BackupPlanName': 'daily', 'Rules': []},
                    'BackupPlanId': 'plan-1', 'BackupPlanArn': ARN, 'VersionId': 'v1'},
                    {'BackupPlanId': 'plan-1'})
                stub.add_response('list_backup_selections', {
                    'BackupSelectionsList': [
                        {'SelectionId': 'sel-1', 'BackupPlanId': 'plan-1'}],
                    'NextToken': 'page2'},
                    {'BackupPlanId': 'plan-1', 'MaxResults': PAGE_SIZE})
                stub.add_response('list_backup_selections', {
                    'BackupSelectionsList': []},
                    {'BackupPlanId': 'plan-1', 'MaxResults': PAGE_SIZE, 'NextToken': 'page2'})
                stub.add_response('get_backup_selection', {
                    'BackupPlanId': 'plan-1', 'SelectionId': 'sel-1',
                    'BackupSelection': {'SelectionName': 'explicit', 'IamRoleArn':
                        'arn:aws:iam::000000000000:role/backup',
                        'Resources': [RESOURCE], 'NotResources': [],
                        'ListOfTags': []}},
                    {'BackupPlanId': 'plan-1', 'SelectionId': 'sel-1'})
                stub.add_response('list_backup_vaults', {
                    'BackupVaultList': [{'BackupVaultName': 'primary',
                                         'BackupVaultArn': VAULT}]},
                    {'MaxResults': PAGE_SIZE})
                stub.add_response('describe_backup_vault', {
                    'BackupVaultName': 'primary', 'BackupVaultArn': VAULT,
                    'Locked': True},
                    {'BackupVaultName': 'primary'})
                stub.add_response('get_backup_vault_access_policy', {
                    'BackupVaultName': 'primary', 'BackupVaultArn': VAULT,
                    'Policy': '{"Version":"2012-10-17","Statement":[]}'},
                    {'BackupVaultName': 'primary'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
                    facade = BackupPublicFacade(object(), ACCOUNT)
                    plans = await facade.get_plans(REGION)
                    vaults = await facade.get_vaults(REGION)
                stub.assert_no_pending_responses()
        finally:
            cli.close()
        assert plans[0]['selection_collection_complete'] is True
        assert plans[0]['selections'][0]['BackupSelection']['Resources'] == [RESOURCE]
        assert vaults[0]['access_policy_status'] == 'present'
        assert json.loads(vaults[0]['access_policy'])['Version'] == '2012-10-17'
    asyncio.run(run())


def test_stubber_paginated_protected_resources_and_denied_jobs():
    async def run():
        cli = sdk()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(cli) as stub:
                stub.add_response('list_protected_resources', {
                    'Results': [{'ResourceArn': RESOURCE, 'ResourceType': 'EBS'}],
                    'NextToken': 'more'}, {'MaxResults': PAGE_SIZE})
                stub.add_response('list_protected_resources', {'Results': []},
                                  {'MaxResults': PAGE_SIZE, 'NextToken': 'more'})
                stub.add_client_error('list_backup_jobs',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'MaxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
                    facade = BackupPublicFacade(object(), ACCOUNT)
                    protected = await facade.get_protected_resources(REGION)
                    jobs = await facade.get_backup_jobs(REGION)
                stub.assert_no_pending_responses()
            assert protected.complete and protected[0]['ResourceArn'] == RESOURCE
            assert jobs == [] and not jobs.complete
            assert any(x['scope'] == 'backup' and x['status'] == 'denied'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            cli.close()
    asyncio.run(run())


def test_restore_testing_plans_with_actual_stubber_methods():
    async def run():
        cli = sdk()
        try:
            with Stubber(cli) as stub:
                stub.add_response('list_restore_testing_plans', {
                    'RestoreTestingPlans': [{
                        'RestoreTestingPlanName': 'test-1',
                        'RestoreTestingPlanArn': TEST_ARN,
                        'ScheduleExpression': 'cron(0 1 ? * SUN *)',
                        'CreationTime': 1.0}]},
                    {'MaxResults': PAGE_SIZE})
                stub.add_response('list_restore_testing_selections', {
                    'RestoreTestingSelections': [{
                        'RestoreTestingPlanName': 'test-1',
                        'RestoreTestingSelectionName': 'EBS',
                        'ProtectedResourceType': 'EBS',
                        'IamRoleArn': 'arn:aws:iam::000000000000:role/backup',
                        'CreationTime': 1.0}]},
                    {'RestoreTestingPlanName': 'test-1', 'MaxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
                    result = await BackupPublicFacade(object(), ACCOUNT).get_restore_testing_plans(REGION)
                stub.assert_no_pending_responses()
            assert result.complete
            assert result[0]['selections'][0]['ProtectedResourceType'] == 'EBS'
        finally:
            cli.close()
    asyncio.run(run())


def test_plan_reconciliation_distinguishes_assignments_recovery_points_and_jobs():
    async def run():
        plan = {
            'arn': ARN, 'name': 'daily', 'plan_id': 'plan-1', 'rules': [],
            'selection_collection_complete': True,
            'selections': [{
                'BackupPlanId': 'plan-1', 'SelectionId': 'sel-1',
                'BackupSelection': {'Resources': [RESOURCE],
                                    'NotResources': [], 'ListOfTags': []}}]}
        protected = BoundedResults([{
            'ResourceArn': RESOURCE, 'ResourceName': 'real-ebs',
            'ResourceType': 'EBS', 'LastRecoveryPointArn': 'arn:aws:backup:...'}])
        jobs = BoundedResults([{
            'BackupJobId': 'job-1', 'ResourceArn': RESOURCE,
            'CreatedBy': {'BackupPlanId': 'plan-1'}, 'State': 'COMPLETED'},
            {'BackupJobId': 'job-2', 'ResourceArn': RESOURCE,
             'CreatedBy': {'BackupPlanId': 'another'}, 'State': 'FAILED'}])
        restores = BoundedResults([{
            'RestoreJobId': 'restore-1', 'Status': 'COMPLETED',
            'ValidationStatus': 'FAILED', 'SourceResourceArn': RESOURCE,
            'CreatedBy': {'RestoreTestingPlanArn': TEST_ARN}}])
        tests = BoundedResults([{
            'RestoreTestingPlanName': 'test-1', 'RestoreTestingPlanArn': TEST_ARN,
            'selections': [{'ProtectedResourceType': 'EBS'}],
            'selection_collection_complete': True}])
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            backup=SimpleNamespace(
                get_vaults=AsyncMock(return_value=[]),
                get_plans=AsyncMock(return_value=[plan]),
                get_protected_resources=AsyncMock(return_value=protected),
                get_backup_jobs=AsyncMock(return_value=jobs),
                get_restore_jobs=AsyncMock(return_value=restores),
                get_restore_testing_plans=AsyncMock(return_value=tests)))
        service = BackupPublic(facade)
        await service.fetch_all(regions=[REGION])
        region = service['regions'][REGION]
        assert service['protected_resources_count'] == 1
        assert next(iter(region['protected_resources'])).startswith('scoutid-')
        result = next(iter(region['plans'].values()))
        assert result['matching_protected_resource_arns'] == [RESOURCE]
        assert result['observed_completed_backup_resource_arns'] == [RESOURCE]
        assert result['completed_job_resource_arns_with_recovery_point'] == [RESOURCE]
        assert result['correlation_status'] == 'complete'
        test = next(iter(region['restore_testing_plans'].values()))
        assert test['observed_restore_jobs'][0]['ValidationStatus'] == 'FAILED'
        assert test['observed_restore_jobs'][0]['Status'] == 'COMPLETED'
        assert not test['results_status'] == 'partial'
    asyncio.run(run())


def test_missing_or_partial_inventory_cannot_assert_absence():
    async def run():
        plan = {'arn': ARN, 'name': 'daily', 'plan_id': 'plan-1', 'rules': [],
                'selections': [{'BackupSelection': {
                    'Resources': [RESOURCE], 'NotResources': []}}],
                'selection_collection_complete': True}
        partial = BoundedResults()
        partial.complete = False
        backup = SimpleNamespace(
            get_vaults=AsyncMock(return_value=[]),
            get_plans=AsyncMock(return_value=[plan]),
            get_protected_resources=AsyncMock(return_value=partial),
            get_backup_jobs=AsyncMock(return_value=partial),
            get_restore_jobs=AsyncMock(return_value=partial),
            get_restore_testing_plans=AsyncMock(return_value=partial))
        service = BackupPublic(SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]), backup=backup))
        await service.fetch_all(regions=[REGION])
        record = next(iter(service['regions'][REGION]['plans'].values()))
        assert record['correlation_status'] == 'partial'
        assert record['explicit_resource_arns_without_reported_recovery_point'] == []
    asyncio.run(run())


def test_escaped_report_templates_registered_and_no_raw_html():
    root = Path(__file__).resolve().parents[1]
    metadata = json.loads((root / 'ScoutSuite/providers/aws/metadata.json').read_text())
    names = ['backup_jobs', 'restore_jobs', 'protected_resources', 'restore_testing_plans']
    for name in names:
        assert name in metadata['storage']['backup']['resources']
        file = root / 'ScoutSuite/output/data/html/partials/aws' / (
            'services.backup.regions.id.' + name + '.html')
        source = file.read_text()
        assert '{{{' not in source
        assert 'javascript:' not in source
        assert 'onclick=' not in source
        assert 'Handlebars.registerPartial' in source
