from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSCompositeResources
from ScoutSuite.providers.utils import get_non_provider_id
from .grants import Grants


class Keys(AWSCompositeResources):
    _children = [
        (Grants, 'grants'),
    ]

    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_keys = await self.facade.kms.get_keys(self.region)
        for raw_key in raw_keys:
            key_id, key = await self._parse_key(raw_key)
            self[key_id] = key

        await self._fetch_children_of_all_resources(
            resources=self,
            scopes={key_id: {'region': self.region, 'key_id': key['id']}
                    for (key_id, key) in self.items()}
        )

    async def _parse_key(self, raw_key):
        key = {
            'id': raw_key.get('KeyId'),
            'name': raw_key.get('KeyId'),
            'arn': raw_key.get('KeyArn'),
            'policy': raw_key.get('policy'),
            'rotation_enabled': None,
            'rotation_status': 'unknown',
            'rotation_period_days': None,
            'next_rotation_date': None,
        }

        metadata = (raw_key.get('metadata') or {}).get('KeyMetadata') or {}
        key['creation_date'] = metadata.get('CreationDate')
        state = metadata.get('KeyState')
        key['key_enabled'] = (state == 'Enabled') if state is not None else None
        key['key_state'] = state
        for source, target in (
            ('Description', 'description'), ('Origin', 'origin'),
            ('KeyManager', 'key_manager')
        ):
            value = metadata.get(source)
            key[target] = value.strip() or None if isinstance(value, str) else value

        key['key_usage'] = metadata.get('KeyUsage')
        key['key_spec'] = metadata.get('KeySpec', metadata.get('CustomerMasterKeySpec'))
        key['multi_region'] = metadata.get('MultiRegion')
        key['multi_region_key_type'] = (
            (metadata.get('MultiRegionConfiguration') or {}).get('MultiRegionKeyType')
        )

        # Only symmetric encryption with AWS_KMS origin supports AWS-managed
        # automatic rotation. Do not mistake ineligible keys for rotated keys.
        eligible = (
            key['key_spec'] == 'SYMMETRIC_DEFAULT'
            and key['key_usage'] == 'ENCRYPT_DECRYPT'
            and key['origin'] == 'AWS_KMS'
        )
        if metadata:
            if key['key_manager'] == 'AWS' and eligible:
                key['rotation_enabled'] = True
                key['rotation_status'] = 'aws_managed'
            elif key['key_manager'] == 'CUSTOMER' and eligible:
                result = await self.facade.kms.get_key_rotation_status(
                    self.region, key['id']
                )
                if isinstance(result, dict) and isinstance(
                    result.get('KeyRotationEnabled'), bool
                ):
                    key['rotation_enabled'] = result['KeyRotationEnabled']
                    key['rotation_status'] = 'enabled' if result[
                        'KeyRotationEnabled'] else 'disabled'
                    key['rotation_period_days'] = result.get('RotationPeriodInDays')
                    key['next_rotation_date'] = result.get('NextRotationDate')
                else:
                    key['rotation_status'] = 'unavailable'
            elif key['key_manager'] == 'CUSTOMER' and not eligible:
                key['rotation_status'] = 'not_supported'
            elif key['key_manager'] == 'AWS':
                key['rotation_status'] = 'not_supported'

        key['aliases'] = [
            self._parse_alias(alias) for alias in (raw_key.get('aliases') or [])
            if isinstance(alias, dict) and alias.get('AliasArn')
            and alias.get('AliasName')
        ]
        return key['id'], key

    def _parse_alias(self, raw_alias):
        alias_dict = {
            # all KMS Aliases are prefixed with alias/, so we'll strip that off
            'id': get_non_provider_id(raw_alias.get('AliasArn')),
            'name': raw_alias.get('AliasName').split('alias/', 1)[-1],
            'arn': raw_alias.get('AliasArn'),
            'key_id': raw_alias.get('TargetKeyId')}
        return alias_dict
