"""Region-scoped GuardDuty detector inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .detectors import Detectors


class GuardDutyPublic(Regions):
    _children = [(Detectors, 'detectors')]

    def __init__(self, facade):
        super().__init__('guardduty', facade)

    async def fetch_all(self, **kwargs):
        await super().fetch_all(**kwargs)
        census = getattr(self.facade.guardduty, 'detector_census', {})
        for region, data in self.get('regions', {}).items():
            detectors = data.get('detectors') or {}
            record = census.get(region) if isinstance(census, dict) else None
            # Complete only if the facade enumerated the region AND every
            # detector it described also passed normalisation.
            complete = (isinstance(record, dict) and record.get('complete') is True
                        and record.get('count') == len(detectors))
            data['detector_census_status'] = 'complete' if complete else 'incomplete'
            data['enabled_detectors_count'] = sum(
                1 for detector in detectors.values() if detector.get('status') == 'ENABLED')
            data['guardduty_status'] = (
                'unknown' if not complete else
                'not_enabled' if not detectors else
                'enabled' if data['enabled_detectors_count'] else 'detector_disabled')
            # Region-level gap only; a DISABLED detector has its own rule.
            data['guardduty_not_enabled'] = data['guardduty_status'] == 'not_enabled'
