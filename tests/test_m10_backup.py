"""M10-K: Backup read-only SDK contracts, completeness and actionable evidence."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_backup_vault_lock
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.backup import BackupPublicFacade, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.backup.base import BackupPublic

ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
ACCOUNT = '000000000000'
VAULT_ARN = 'arn:aws:backup:us-east-1:000000000000:backup-vault:primary'
PLAN_ARN = 'arn:aws:backup:us-east-1:000000000000:backup-plan:plan-id'


def client():
    return boto3.client('backup', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def test_api_model_and_read_only_surface():
    model = get_session().get_service_model('backup')
    operations = {
        'ListBackupVaults', 'DescribeBackupVault', 'ListBackupPlans', 'GetBackupPlan'}
    assert operations <= set(model.operation_names)
    for name in ('ListBackupVaults', 'ListBackupPlans'):
        op = model.operation_model(name)
        assert {'NextToken', 'MaxResults'} <= set(op.input_shape.members)
    assert 'BackupVaultName' in model.operation_model('DescribeBackupVault').input_shape.required_members
    assert 'BackupPlanId' in model.operation_model('GetBackupPlan').input_shape.required_members


def test_stubber_vaults_plans_and_normalized_resource_evidence():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_backup_vaults', {
                    'BackupVaultList': [{'BackupVaultName': 'primary',
                                         'BackupVaultArn': VAULT_ARN}],
                    'NextToken': 'page-two'}, {'MaxResults': PAGE_SIZE})
                stub.add_response('list_backup_vaults', {'BackupVaultList': []},
                                  {'MaxResults': PAGE_SIZE, 'NextToken': 'page-two'})
                stub.add_response('describe_backup_vault', {
                    'BackupVaultName': 'primary', 'BackupVaultArn': VAULT_ARN,
                    'Locked': False,
                    'MinRetentionDays': 7, 'MaxRetentionDays': 365,
                    'EncryptionKeyArn': 'arn:aws:kms:us-east-1:000000000000:key/synthetic',
                    'NumberOfRecoveryPoints': 2}, {'BackupVaultName': 'primary'})
                stub.add_response('list_backup_plans', {
                    'BackupPlansList': [{'BackupPlanName': 'daily',
                                         'BackupPlanId': 'plan-id',
                                         'BackupPlanArn': PLAN_ARN}]},
                    {'MaxResults': PAGE_SIZE})
                stub.add_response('get_backup_plan', {
                    'BackupPlan': {'BackupPlanName': 'daily',
                                   'Rules': [{'RuleName': 'daily-rule',
                                              'TargetBackupVaultName': 'primary',
                                              'ScheduleExpression': 'cron(0 4 * * ? *)',
                                              'Lifecycle': {'DeleteAfterDays': 35},
                                              'CopyActions': [{
                                                  'DestinationBackupVaultArn': VAULT_ARN}]}]},
                    'BackupPlanId': 'plan-id', 'BackupPlanArn': PLAN_ARN,
                    'VersionId': 'v1'}, {'BackupPlanId': 'plan-id'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as getter:
                    facade = BackupPublicFacade(object(), ACCOUNT)
                    vaults = await facade.get_vaults(REGION)
                    plans = await facade.get_plans(REGION)
                    assert getter.call_count == 2
                stub.assert_no_pending_responses()
        finally:
            sdk.close()
        assert len(vaults) == len(plans) == 1
        assert vaults[0]['arn'] == VAULT_ARN
        assert vaults[0]['locked'] is False
        assert vaults[0]['min_retention_days'] == 7
        assert plans[0]['arn'] == PLAN_ARN
        assert plans[0]['rules'][0]['Lifecycle']['DeleteAfterDays'] == 35
        assert plans[0]['rules'][0]['CopyActions'][0]['DestinationBackupVaultArn'] == VAULT_ARN
        source = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            backup=SimpleNamespace(get_vaults=AsyncMock(return_value=vaults),
                                   get_plans=AsyncMock(return_value=plans)))
        service = BackupPublic(source)
        await service.fetch_all(regions=[REGION])
        assert service['regions_count'] == 1
        assert service['vaults_count'] == 1
        assert service['plans_count'] == 1
        vault = next(iter(service['regions'][REGION]['vaults'].values()))
        plan = next(iter(service['regions'][REGION]['plans'].values()))
        assert vault['backup_vault_arn'] == VAULT_ARN
        assert vault['unlocked'] is True
        assert vault['encryption_key_arn'].endswith('/synthetic')
        assert plan['backup_plan_arn'] == PLAN_ARN
        assert plan['rules'][0]['ScheduleExpression'] == 'cron(0 4 * * ? *)'
        assert vault['id'].startswith('scoutid-')
        assert plan['id'].startswith('scoutid-')
        assert 'synthetic' in json.dumps(service)
    asyncio.run(scenario())


def test_access_denial_not_treated_as_empty_verified_inventory():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('list_backup_vaults',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'MaxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await BackupPublicFacade(object(), ACCOUNT).get_vaults(REGION) == []
                stub.assert_no_pending_responses()
            assert any(x['scope'] == 'backup' and x['status'] == 'denied'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_token_cycle_malformed_and_partial_detail_failures():
    async def scenario():
        sdk = Mock()
        sdk.list_backup_vaults.side_effect = [
            {'BackupVaultList': [{'BackupVaultName': 'primary',
                                  'BackupVaultArn': VAULT_ARN}], 'NextToken': 'repeat'},
            {'BackupVaultList': [], 'NextToken': 'repeat'}]
        sdk.describe_backup_vault.side_effect = RuntimeError('synthetic error')
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                result = await BackupPublicFacade(object(), ACCOUNT).get_vaults(REGION)
            assert result == []
            assert sdk.list_backup_vaults.call_count == 2
            reasons = {item['reason_code'] for item in ctx.collection_issues}
            assert 'ListBackupVaultsInvalidPaginationToken' in reasons
            assert 'DescribeBackupVaultFailed' in reasons
            with patch.object(AWSFacadeUtils, 'get_client', return_value=Mock(
                    list_backup_plans=Mock(return_value={'BackupPlansList': 'bad'}))):
                assert await BackupPublicFacade(object(), ACCOUNT).get_plans(REGION) == []
            assert any(item['reason_code'] == 'ListBackupPlansMalformedPage'
                       for item in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_lock_rule_only_flags_explicit_unlocked_and_preserves_unknown(tmp_path):
    assert classify_backup_vault_lock({'locked': False}) == 'insecure'
    assert classify_backup_vault_lock({'locked': True}) == 'secure'
    assert classify_backup_vault_lock({'locked': None}) == 'unknown'
    assert classify_backup_vault_lock({}) == 'unknown'
    assert classify_backup_vault_lock(None) == 'unknown'
    selected = {'about': 'synthetic M10-K', 'rules': {
        'backup-vault-lock-disabled.json': [{'enabled': True, 'level': 'warning'}]}}
    file = tmp_path / 'rules.json'
    file.write_text(json.dumps(selected))
    objects = {
        'bad': {'locked': False, 'unlocked': True, 'backup_vault_arn': VAULT_ARN},
        'good': {'locked': True, 'unlocked': False, 'backup_vault_arn': VAULT_ARN},
        'unknown': {'locked': None, 'unlocked': False, 'backup_vault_arn': VAULT_ARN}}
    provider = SimpleNamespace(services={'backup': {'regions': {REGION: {
        'vaults': objects}}}}, service_list=['backup'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(file))).run(provider)
        result = provider.services['backup']['findings']['backup-vault-lock-disabled']
        assert result['flagged_items'] == 1
        assert result['assessment_status'] == 'incomplete'
        assert result['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_dashboard_metadata_and_escaped_templates():
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text())
    assert metadata['storage']['backup']['resources']['vaults']['path'] == (
        'services.backup.regions.id.vaults')
    for kind, expected in [('vaults', '{{backup_vault_arn}}'),
                           ('plans', '{{backup_plan_arn}}')]:
        template = (ROOT / 'ScoutSuite/output/data/html/partials/aws' /
                    ('services.backup.regions.id.' + kind + '.html')).read_text()
        assert expected in template and '{{name}}' in template
        assert '{{{' not in template and 'onclick=' not in template
        assert 'javascript:' not in template and 'http://' not in template
