"""Normalize Inspector2 account scan activation; never retrieve findings."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


SCAN_TYPES = ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository')
INACTIVE = ('DISABLED', 'SUSPENDED')


class Accounts(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        result = await self.facade.inspector2.get_account_status(self.region)
        if result is None:
            return
        account_id = result.get('account_id')
        if not isinstance(account_id, str) or len(account_id) != 12 or not account_id.isdigit():
            self._issue('InvalidAccountResource')
            return
        status = result.get('status')
        if not isinstance(status, str):
            self._issue('InvalidAccountResource')
            return
        raw_types = result.get('scan_types')
        if not isinstance(raw_types, dict):
            self._issue('InvalidScanTypeCollection')
            return
        scan_types = {}
        for name in SCAN_TYPES:
            value = raw_types.get(name)
            if value is not None and not isinstance(value, str):
                self._issue('InvalidScanTypeStatus')
                value = None
            scan_types[name] = {
                'id': name, 'name': name, 'region': self.region,
                'status': value, 'inactive': value in INACTIVE,
            }
        key = get_non_provider_id(self.region + ':' + account_id)
        self[key] = {
            'id': key, 'name': 'Inspector account ' + account_id,
            'account_id': account_id, 'region': self.region,
            'status': status, 'inactive': status in INACTIVE,
            'scan_types': scan_types, 'scan_types_count': len(scan_types),
        }

    @staticmethod
    def _issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'inspector2', reason)
