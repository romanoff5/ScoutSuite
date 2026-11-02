"""Actionable backup vault metadata; missing Vault Lock status remains unknown."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Vaults(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw in await self.facade.backup.get_vaults(self.region):
            arn = raw.get('arn') if isinstance(raw, dict) else None
            if not isinstance(arn, str) or not arn.startswith('arn:'):
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'backup', 'InvalidVaultRecord')
                continue
            key = get_non_provider_id(arn)
            if key in self:
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'backup', 'DuplicateVaultRecord')
                continue
            locked = raw.get('locked')
            self[key] = {
                'id': key, 'name': raw.get('name'), 'backup_vault_arn': arn,
                'region': self.region, 'vault_type': raw.get('vault_type'),
                'vault_state': raw.get('vault_state'),
                'access_policy': raw.get('access_policy'),
                'access_policy_status': raw.get('access_policy_status', 'unknown'),
                'encryption_key_arn': raw.get('encryption_key_arn'),
                'encryption_key_type': raw.get('encryption_key_type'),
                'number_of_recovery_points': raw.get('number_of_recovery_points'),
                'locked': locked if type(locked) is bool else None,
                'unlocked': locked is False,
                'min_retention_days': raw.get('min_retention_days'),
                'max_retention_days': raw.get('max_retention_days'),
                'lock_date': raw.get('lock_date'),
                'creation_date': raw.get('creation_date'),
                'creator_request_id': raw.get('creator_request_id'),
                'source_backup_vault_arn': raw.get('source_backup_vault_arn'),
            }
