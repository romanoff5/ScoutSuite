"""Normalized Inspector2 scan coverage; no raw vulnerability findings."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class InspectorCoverage(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for item in await self.facade.inspector2.get_coverage(self.region):
            parsed = self._parse_coverage(item)
            if parsed is None:
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'inspector2', 'InvalidInspectorCoverage')
                continue
            key, coverage = parsed
            self[key] = coverage

    def _parse_coverage(self, item):
        if not isinstance(item, dict) or any(
                not isinstance(item.get(n), str) or not item[n]
                for n in ('resource_type', 'resource_id', 'scan_type', 'account_id')):
            return None
        status = item.get('scan_status')
        if status not in ('ACTIVE', 'INACTIVE'):
            status = None
        key = get_non_provider_id('|'.join(item[n] for n in (
            'resource_type', 'resource_id', 'scan_type', 'account_id')))
        return key, {'id': key, 'name': item['resource_id'], 'region': self.region,
                     'resource_type': item['resource_type'], 'resource_id': item['resource_id'],
                     'account_id': item['account_id'], 'scan_type': item['scan_type'],
                     'scan_status': status or 'UNKNOWN', 'inactive': status == 'INACTIVE',
                     'scan_reason': item.get('scan_reason') if isinstance(
                         item.get('scan_reason'), str) else None}
