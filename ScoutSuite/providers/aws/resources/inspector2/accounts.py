"""Normalized Inspector account status."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.inspector2 import SCAN_TYPES, VALID_SCAN_STATES
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class InspectorAccounts(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for item in await self.facade.inspector2.get_accounts(self.region):
            parsed = self._parse_account(item)
            if parsed is None:
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'inspector2', 'InvalidInspectorAccount')
                continue
            key, account = parsed
            self[key] = account

    def _parse_account(self, item):
        if not isinstance(item, dict):
            return None
        account_id, status = item.get('account_id'), item.get('status')
        if not isinstance(account_id, str) or len(account_id) != 12 or not account_id.isascii() or not account_id.isdigit():
            return None
        if status not in ('ENABLED', 'DISABLED', 'SUSPENDED', 'ENABLING', 'DISABLING', 'SUSPENDING'):
            return None
        states = item.get('resource_states')
        if not isinstance(states, dict):
            states = {}
        normalized_states = {}
        scan_types = {}
        for name in SCAN_TYPES:
            value = states.get(name)
            if value is not None and (not isinstance(value, str) or value not in VALID_SCAN_STATES):
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'inspector2', 'InvalidScanTypeStatus')
                value = None
            normalized_states[name] = value
            scan_types[name] = {
                'id': name, 'name': name, 'region': self.region,
                'status': value if value is not None else 'UNKNOWN',
                'inactive': value in ('DISABLED', 'SUSPENDED'),
            }
        key = get_non_provider_id(account_id)
        return key, {'id': key, 'name': account_id, 'account_id': account_id,
                     'region': self.region, 'status': status,
                     'disabled': status in ('DISABLED', 'SUSPENDED'),
                     'resource_states': normalized_states,
                     'scan_types': scan_types,
                     'scan_types_count': len(scan_types)}
