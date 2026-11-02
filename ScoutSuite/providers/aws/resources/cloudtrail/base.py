from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.regions import Regions

from .trails import Trails


class CloudTrail(Regions):
    _children = [
        (Trails, 'trails')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('cloudtrail', facade)

    async def finalize(self):
        # M10-S: preserve API collection completeness independent of an empty
        # trail list. A denied DescribeTrails must never resemble no trails.
        statuses = getattr(getattr(self.facade, 'cloudtrail', None),
                           'trail_inventory_status', {})
        for name, record in self.get('regions', {}).items():
            record['trails_inventory_status'] = statuses.get(name, 'unknown')
        global_events_logging = []

        for region in self['regions']:
            for trail_id, trail in self['regions'][region]['trails'].items():
                if 'HomeRegion' in trail and trail['HomeRegion'] != region:
                    # Part of a multi-region trail, skip until we find the whole object
                    continue
                if trail['IncludeGlobalServiceEvents'] and trail['IsLogging']:
                    global_events_logging.append((region, trail_id,))

        self['IncludeGlobalServiceEvents'] = len(global_events_logging) > 0
        self['DuplicatedGlobalServiceEvents'] = len(global_events_logging) > 1
