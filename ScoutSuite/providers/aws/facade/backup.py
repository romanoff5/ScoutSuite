"""M10-K: read-only regional AWS Backup vault and plan inventory."""
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

    async def _paginate(self, call, key, operation):
        records, seen_tokens = [], set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'MaxResults': PAGE_SIZE}
            if token is not None:
                params['NextToken'] = token
            try:
                response = await run_concurrently(lambda params=params: call(**params))
            except Exception as error:
                self.failure(operation, error, partial=bool(records))
                break
            batch = response.get(key) if isinstance(response, dict) else None
            if (not isinstance(batch, list) or len(batch) > PAGE_SIZE
                    or any(not isinstance(item, dict) for item in batch)):
                self.issue('partial', operation + 'MalformedPage')
                break
            remaining = MAX_ITEMS - len(records)
            if len(batch) > remaining:
                records.extend(batch[:remaining])
                self.issue('partial', operation + 'ItemLimit')
                break
            records.extend(batch)
            next_token = response.get('NextToken')
            if next_token in (None, ''):
                break
            if (not isinstance(next_token, str) or len(next_token) > 4096
                    or next_token in seen_tokens):
                self.issue('partial', operation + 'InvalidPaginationToken')
                break
            seen_tokens.add(next_token)
            token = next_token
        else:
            self.issue('partial', operation + 'PageLimit')
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
            result.append({
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
            result.append({
                'name': config['BackupPlanName'], 'plan_id': identifier,
                'arn': arn, 'region': region, 'version_id': response.get('VersionId'),
                'creation_date': timestamp(response.get('CreationDate')),
                'last_execution_date': timestamp(response.get('LastExecutionDate')),
                'creator_request_id': response.get('CreatorRequestId'),
                'rules': config['Rules'],
                'advanced_backup_settings': config.get('AdvancedBackupSettings', []),
            })
        return result
