"""M10-K/M10-N: bounded, read-only regional AWS Backup evidence."""
from copy import deepcopy
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

PAGE_SIZE = 100
MAX_PAGES = 1000
MAX_ITEMS = 100000
DENIED = frozenset(('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation'))
UNSUPPORTED = frozenset(('UnknownOperationException', 'UnsupportedOperationException'))


def timestamp(value):
    return value.isoformat() if hasattr(value, 'isoformat') else value


def json_safe(value):
    """Preserve AWS diagnostic fields while converting timestamps for JSON/SQLite."""
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [json_safe(v) for v in value]
    return timestamp(value)


class BoundedResults(list):
    """List with an explicit inventory-completeness indicator."""
    def __init__(self, iterable=()):
        super().__init__(iterable)
        self.complete = True


class BackupPublicFacade(AWSBaseFacade):
    """Collect configuration metadata only; never read recovery-point contents."""

    def __init__(self, session, account_id):
        super().__init__(session)
        self.account_id = account_id

    @staticmethod
    def issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'backup', reason)

    @classmethod
    def failure(cls, operation, error, partial=False):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code')
            state = 'denied' if code in DENIED else (
                'unsupported' if code in UNSUPPORTED else 'failed')
        else:
            state = 'failed'
        cls.issue('partial' if partial else state, operation + state.capitalize())

    async def _paginate(self, call, key, operation, **fixed):
        records, seen_tokens = BoundedResults(), set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'MaxResults': PAGE_SIZE, **fixed}
            if token is not None:
                params['NextToken'] = token
            try:
                response = await run_concurrently(lambda params=params: call(**params))
            except Exception as error:
                self.failure(operation, error, partial=bool(records))
                records.complete = False
                break
            batch = response.get(key) if isinstance(response, dict) else None
            if (not isinstance(batch, list) or len(batch) > PAGE_SIZE
                    or any(not isinstance(item, dict) for item in batch)):
                self.issue('partial', operation + 'MalformedPage')
                records.complete = False
                break
            remaining = MAX_ITEMS - len(records)
            if len(batch) > remaining:
                records.extend(batch[:remaining])
                self.issue('partial', operation + 'ItemLimit')
                records.complete = False
                break
            records.extend(batch)
            next_token = response.get('NextToken')
            if next_token in (None, ''):
                break
            if (not isinstance(next_token, str) or len(next_token) > 4096
                    or next_token in seen_tokens):
                self.issue('partial', operation + 'InvalidPaginationToken')
                records.complete = False
                break
            seen_tokens.add(next_token)
            token = next_token
        else:
            self.issue('partial', operation + 'PageLimit')
            records.complete = False
        return records

    def _valid_arn(self, arn, region, resource_type):
        if not isinstance(arn, str) or not isinstance(self.account_id, str):
            return False
        parts = arn.split(':', 5)
        return (len(parts) == 6 and parts[0] == 'arn' and
                parts[2] == 'backup' and parts[3] == region and
                parts[4] == self.account_id and
                parts[5].startswith(resource_type + ':') and
                len(parts[5]) > len(resource_type) + 1)

    async def get_vaults(self, region):
        client = AWSFacadeUtils.get_client('backup', self.session, region)
        if client is None:
            self.issue('failed', 'VaultClientConstruction')
            return []
        summary = await self._paginate(client.list_backup_vaults, 'BackupVaultList', 'ListBackupVaults')
        result, seen = [], set()
        for vault in summary:
            name, arn = vault.get('BackupVaultName'), vault.get('BackupVaultArn')
            if (not isinstance(name, str) or not name
                    or not self._valid_arn(arn, region, 'backup-vault')):
                self.issue('partial', 'InvalidBackupVaultIdentity')
                continue
            if arn in seen:
                self.issue('partial', 'DuplicateBackupVault')
                continue
            seen.add(arn)
            try:
                response = await run_concurrently(
                    lambda name=name: client.describe_backup_vault(BackupVaultName=name))
            except Exception as error:
                self.failure('DescribeBackupVault', error, partial=True)
                continue
            if (not isinstance(response, dict) or response.get('BackupVaultName') != name
                    or response.get('BackupVaultArn') != arn):
                self.issue('partial', 'MismatchedBackupVaultDetail')
                continue
            policy, policy_status = None, 'unknown'
            try:
                access = await run_concurrently(
                    lambda name=name: client.get_backup_vault_access_policy(
                        BackupVaultName=name))
                if (not isinstance(access, dict)
                        or access.get('BackupVaultArn') not in (None, arn)
                        or access.get('BackupVaultName') not in (None, name)
                        or not isinstance(access.get('Policy'), str)):
                    self.issue('partial', 'MismatchedBackupVaultPolicy')
                else:
                    policy, policy_status = access['Policy'], 'present'
            except ClientError as error:
                if error.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                    policy_status = 'absent'
                else:
                    self.failure('GetBackupVaultAccessPolicy', error, partial=True)
            except Exception as error:
                self.failure('GetBackupVaultAccessPolicy', error, partial=True)
            result.append({
                'access_policy': policy, 'access_policy_status': policy_status,
                'name': name, 'arn': arn, 'region': region,
                'vault_type': response.get('VaultType', summary and vault.get('VaultType')),
                'vault_state': response.get('VaultState', vault.get('VaultState')),
                'encryption_key_arn': response.get('EncryptionKeyArn'),
                'encryption_key_type': response.get('EncryptionKeyType'),
                'number_of_recovery_points': response.get('NumberOfRecoveryPoints'),
                'locked': response.get('Locked'),
                'min_retention_days': response.get('MinRetentionDays'),
                'max_retention_days': response.get('MaxRetentionDays'),
                'lock_date': timestamp(response.get('LockDate')),
                'creation_date': timestamp(response.get('CreationDate')),
                'creator_request_id': response.get('CreatorRequestId'),
                'source_backup_vault_arn': response.get('SourceBackupVaultArn'),
            })
        return result

    async def get_plans(self, region):
        client = AWSFacadeUtils.get_client('backup', self.session, region)
        if client is None:
            self.issue('failed', 'PlanClientConstruction')
            return []
        summary = await self._paginate(client.list_backup_plans, 'BackupPlansList', 'ListBackupPlans')
        result, seen = [], set()
        for plan in summary:
            identifier, arn = plan.get('BackupPlanId'), plan.get('BackupPlanArn')
            if (not isinstance(identifier, str) or not identifier
                    or not self._valid_arn(arn, region, 'backup-plan')):
                self.issue('partial', 'InvalidBackupPlanIdentity')
                continue
            if arn in seen:
                self.issue('partial', 'DuplicateBackupPlan')
                continue
            seen.add(arn)
            try:
                response = await run_concurrently(
                    lambda identifier=identifier: client.get_backup_plan(BackupPlanId=identifier))
            except Exception as error:
                self.failure('GetBackupPlan', error, partial=True)
                continue
            config = response.get('BackupPlan') if isinstance(response, dict) else None
            if (not isinstance(config, dict) or response.get('BackupPlanId') != identifier
                    or response.get('BackupPlanArn') != arn
                    or not isinstance(config.get('BackupPlanName'), str)
                    or not isinstance(config.get('Rules'), list)):
                self.issue('partial', 'MismatchedBackupPlanDetail')
                continue
            selections = await self._paginate(
                client.list_backup_selections, 'BackupSelectionsList',
                'ListBackupSelections', BackupPlanId=identifier)
            details, selection_complete, selection_ids = [], selections.complete, set()
            for selection in selections:
                selection_id = selection.get('SelectionId')
                if (not isinstance(selection_id, str) or not selection_id
                        or selection_id in selection_ids
                        or selection.get('BackupPlanId') not in (None, identifier)):
                    self.issue('partial', 'InvalidBackupSelectionIdentity')
                    selection_complete = False
                    continue
                selection_ids.add(selection_id)
                try:
                    item = await run_concurrently(
                        lambda selection_id=selection_id: client.get_backup_selection(
                            BackupPlanId=identifier, SelectionId=selection_id))
                except Exception as error:
                    self.failure('GetBackupSelection', error, partial=True)
                    selection_complete = False
                    continue
                if (not isinstance(item, dict) or item.get('BackupPlanId') != identifier
                        or item.get('SelectionId') != selection_id
                        or not isinstance(item.get('BackupSelection'), dict)):
                    self.issue('partial', 'MismatchedBackupSelectionDetail')
                    selection_complete = False
                    continue
                details.append(json_safe(item))
            result.append({
                'selections': details, 'selection_collection_complete': selection_complete,
                'name': config['BackupPlanName'], 'plan_id': identifier,
                'arn': arn, 'region': region, 'version_id': response.get('VersionId'),
                'creation_date': timestamp(response.get('CreationDate')),
                'last_execution_date': timestamp(response.get('LastExecutionDate')),
                'creator_request_id': response.get('CreatorRequestId'),
                'rules': config['Rules'],
                'advanced_backup_settings': config.get('AdvancedBackupSettings', []),
            })
        return result

    async def _list_evidence(self, region, method, response_key, operation):
        client = AWSFacadeUtils.get_client('backup', self.session, region)
        if client is None:
            self.issue('failed', operation + 'ClientConstruction')
            result = BoundedResults()
            result.complete = False
            return result
        response = await self._paginate(getattr(client, method), response_key, operation)
        result = BoundedResults(json_safe(item) for item in response)
        result.complete = response.complete
        return result

    async def get_protected_resources(self, region):
        return await self._list_evidence(
            region, 'list_protected_resources', 'Results', 'ListProtectedResources')

    async def get_backup_jobs(self, region):
        # AWS Backup ListBackupJobs is limited to the service's available history
        # (normally the last 30 days), not a lifetime backup success assertion.
        return await self._list_evidence(
            region, 'list_backup_jobs', 'BackupJobs', 'ListBackupJobs')

    async def get_restore_jobs(self, region):
        return await self._list_evidence(
            region, 'list_restore_jobs', 'RestoreJobs', 'ListRestoreJobs')

    async def get_restore_testing_plans(self, region):
        client = AWSFacadeUtils.get_client('backup', self.session, region)
        if client is None:
            self.issue('failed', 'RestoreTestingClientConstruction')
            result = BoundedResults()
            result.complete = False
            return result
        plans = await self._paginate(
            client.list_restore_testing_plans, 'RestoreTestingPlans',
            'ListRestoreTestingPlans')
        result, seen = BoundedResults(), set()
        result.complete = plans.complete
        for plan in plans:
            name = plan.get('RestoreTestingPlanName')
            arn = plan.get('RestoreTestingPlanArn')
            if (not isinstance(name, str) or not name or name in seen
                    or not self._valid_arn(arn, region, 'restore-testing-plan')):
                self.issue('partial', 'InvalidRestoreTestingPlanIdentity')
                result.complete = False
                continue
            seen.add(name)
            selections = await self._paginate(
                client.list_restore_testing_selections, 'RestoreTestingSelections',
                'ListRestoreTestingSelections', RestoreTestingPlanName=name)
            record = json_safe(plan)
            record['selections'] = json_safe(list(selections))
            record['selection_collection_complete'] = selections.complete
            if not selections.complete:
                result.complete = False
            result.append(record)
        return result
