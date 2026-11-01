"""Normalize visible Access Analyzer configurations; never collect findings."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Analyzers(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for row in await self.facade.accessanalyzer.get_analyzers(self.region):
            entry = self._parse_analyzer(row)
            if entry is None:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'accessanalyzer', 'InvalidAnalyzer')
                continue
            key, analyzer = entry
            self[key] = analyzer

    def _parse_analyzer(self, raw):
        arn = raw.get('arn')
        status = raw.get('status')
        if not isinstance(arn, str) or not arn.startswith('arn:') or not isinstance(status, str):
            return None
        status = status.upper()
        if status not in ('ACTIVE', 'CREATING', 'DISABLED', 'FAILED'):
            return None
        reason = raw.get('statusReason') or {}
        key = get_non_provider_id(arn)
        return key, {
            'id': key, 'arn': arn, 'name': raw.get('name') or arn.rsplit('/', 1)[-1],
            'region': self.region, 'type': raw.get('type'), 'status': status,
            'status_reason': reason.get('code') if isinstance(reason, dict) else None,
            'inactive': status in ('DISABLED', 'FAILED'),
            'evaluation_status': 'partial' if status == 'CREATING' else 'complete',
        }
