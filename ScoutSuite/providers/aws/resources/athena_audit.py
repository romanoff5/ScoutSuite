"""P2 regional Athena workgroup policy evidence, bounded collector."""
import asyncio

from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.utils import get_non_provider_id


class AthenaAudit(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('athena', facade)

    async def fetch_all(self, regions=None, excluded_regions=None,
                        partition_name='aws', **kwargs):
        self['regions'] = {}
        selected = await self.facade.build_region_list(
            self.service, regions, excluded_regions, partition_name)
        limit = asyncio.Semaphore(4)

        async def collect(region):
            async with limit:
                return region, await self.facade.athena.inventory_workgroups(region)

        for region, inventory in await asyncio.gather(*(collect(r) for r in selected)):
            groups = {}
            for item in inventory.get('work_groups', []):
                name = item.get('name')
                if not isinstance(name, str) or not name:
                    continue
                key = get_non_provider_id(name)
                groups[key] = {'id': key, 'region': region, **item}
            self['regions'][region] = {
                'id': region, 'region': region, 'name': region,
                'work_groups': groups, 'work_groups_count': len(groups),
                'workgroup_inventory_status': inventory.get('status', 'unknown')}
        self['regions_count'] = len(self['regions'])
        self['work_groups_count'] = sum(item['work_groups_count']
                                       for item in self['regions'].values())
