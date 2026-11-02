"""Normalized GuardDuty detector state, without findings or sensitive payloads."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Detectors(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for item in await self.facade.guardduty.get_detectors(self.region):
            parsed = self._parse_detector(item)
            if parsed is None:
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'guardduty', 'UnrecognizedDetector')
                continue
            key, value = parsed
            self[key] = value

    def _parse_detector(self, item):
        detector_id = item.get('detector_id')
        state = item.get('status')
        if not isinstance(detector_id, str) or not detector_id:
            return None
        if state not in ('ENABLED', 'DISABLED'):
            return None
        key = get_non_provider_id(detector_id)
        return key, {
            'id': key, 'detector_id': detector_id, 'region': self.region,
            'name': detector_id, 'status': state, 'disabled': state == 'DISABLED',
            'finding_publishing_frequency': item.get('finding_publishing_frequency'),
        }
